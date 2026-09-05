import bns from 'bns';
import { BufferReader } from 'bufio';
import pRetry from 'p-retry';
import Ethereum from './ethereum.ts';
import { HIP5_ZONES, HIP5_ZONE_DOT, HIP5_ABSTRACT_DOT, hip5Target, isHip5NS, pruneHip5Authority } from './hip5.ts';
import OffchainResolver from './offchain.ts';

const { wire, util } = bns;

const TYPE_MAP_EMPTY = Buffer.from('0006000000000003', 'hex');

// Helios may reject state-proofs for minutes after it starts ("distance to
// target block exceeds maximum proof window"), so keep retrying activation
// in the background instead of letting the node crash-loop.
const ACTIVATION_RETRY_DELAY = 60 * 1000;
const TYPE_MAP_ALL = [
  wire.types.A, wire.types.HINFO, wire.types.MX,
  wire.types.TXT, wire.types.AAAA, wire.types.LOC, wire.types.SRV,
  wire.types.NAPTR, wire.types.CERT, wire.types.SSHFP, wire.types.RRSIG,
  wire.types.NSEC, wire.types.DNSKEY, wire.types.TLSA, wire.types.SMIMEA,
  wire.types.HIP, wire.types.CDS, wire.types.CDNSKEY, wire.types.OPENPGPKEY,
  wire.types.SPF, wire.types.URI, wire.types.CAA
];

interface HsdNode {
  ns: any;
  logger: any;
  config: any;
  chain: any;
}

interface HsdQuestion {
  name: string;
  type: number;
}

// Split a referral's NS records into HIP-5 markers (delegations into
// .eth / ._eth) and real, resolvable nameserver delegations. Dual-mode
// TLDs (onchain + offchain names) ship both in the same root-zone
// NS RRset.
function classifyReferralNS(res: any): { markers: any[]; realNS: any[] } {
  const markers: any[] = [];
  const realNS: any[] = [];

  for (const rr of res.authority) {
    if (isHip5NS(rr)) {
      markers.push(rr);
    } else if (rr.type === wire.types.NS) {
      realNS.push(rr);
    }
  }

  return { markers, realNS };
}

class Plugin {
  ready = false;
  node: HsdNode;
  ns: any;
  logger: any;
  ethereum: Ethereum;
  // Self-contained DNSSEC-validating off-chain resolver; see OffchainResolver
  // for the re-entry rationale. Null only if its own construction failed.
  offchain: OffchainResolver | null;
  activationAbort: AbortController | null = null;

  constructor(node: HsdNode) {
    this.node = node;
    this.ns = node.ns;
    this.logger = node.logger.context('handover');

    this.ethereum = new Ethereum({
      rpcUrl: node.config.str('handover-rpc-url')
    });

    try {
      const resolver = new OffchainResolver({
        resolve: async (name, type) => {
          // Plain HNS root lookup feeding the off-chain mirror (bypasses
          // ns.middle; see OffchainResolver).
          const last = util.split(name);
          const tld = util.label(name, last, -1);
          const req = { question: [new wire.Question(name, type)] };
          return this.resolveHNS(req, name, type, `${tld}.`);
        },
        sign: (rrset, type) => this.ns.signRRSet(rrset, type)
      }, this.logger);

      this.offchain = resolver;
    } catch (e) {
      this.offchain = null;
    }

    // The plugin cannot operate if the root server isn't enabled
    if (!this.ns) {
      return;
    }

    // Middleware intercepting queries to the root before cache,
    // blocklist, or HNS lookup
    this.ns.middle = async (tld: string, req: any) => {
      // Answer only once ready, to avoid poisoning recursive caches
      if (!this.ready) {
        const res = new wire.Message();
        res.code = wire.codes.REFUSED;
        return res;
      }

      // hsd does not lowercase the TLD for us
      tld = tld.toLowerCase();

      const [qs]: HsdQuestion[] = req.question;
      const name = qs.name.toLowerCase();
      const type = qs.type;
      const labels = util.split(name);

      // The plugin can resolve direct queries for ENS (.eth) names,
      // but we must get the complete query string from the recursive resolver.
      // That way we don't need to run a separate authoritative nameserver.
      // If the recursive is "minimizing query names" and only requesting a
      // referral for the TLD, we claim authority so it sends us the full name.
      let data;
      switch (tld) {
        case HIP5_ZONE_DOT:
          if (labels.length < 2) {
            return this.sendSOA(name, tld, type);
          }

          try {
            data = await this.ethereum.resolveDnsFromEns(name, type);
            if (data && data.length > 0) {
              return this.sendData(data, type);
            }
          } catch (e) {
            this.logResolutionFailure(e, name);
          }

          return this.sendSOA(name, tld, type);
        case HIP5_ABSTRACT_DOT:
          return this.sendSOA(name, tld, type);
      }

      // Next, try actually resolving the name with the HNS root zone.
      // We are going to examine the result before sending it back.
      const originalRes = await this.resolveHNS(req, name, type, tld);

      // "<tld> DS" needs special processing: handover won't find any
      // referral in the answer, it won't recognize it as a HIP-5 name
      // which results in a bad proof "NS RRSIG NSEC". Manually request
      // "<hip-5 tld> NS" below for handover to process it.
      const tldDS = type === wire.types.DS && labels.length === 1;

      const res = tldDS
        ? await this.resolveHNS({
            question: [
              new wire.Question(name, wire.types.NS)
            ]
          }, name, wire.types.NS, tld)
        : originalRes;

      // No NS records: we're done, the plugin is bypassed. For the
      // synthetic DS->NS rewrite, send the original DS response instead of
      // an NS-typed message to a DS question (HIP-5: no bare NS referrals).
      if (!res.authority.length) {
        return tldDS ? originalRes : res;
      }

      const { markers, realNS } = classifyReferralNS(res);

      // Special DS processing if the request is "<hip-5 tld> DS":
      // there is no on-chain DS, answer with the upstream NODATA NSEC
      // proof whether or not the TLD carries a HIP-5 marker.
      if (tldDS) {
        return markers.length > 0
          ? this.sendSOA(name, tld, type)
          : originalRes;
      }

      // Bare TLD queries (e.g. "hns. NS"): this is where requesters look
      // up the HIP-5 marker to detect cross-chain support, so keep the
      // referral intact when the TLD is dual-mode. Pure HIP-5 TLDs (no
      // resolvable NS) keep the upstream referral-hiding behavior.
      if (labels.length < 2 && markers.length > 0) {
        return realNS.length > 0 ? res : this.sendSOA(name, tld, type);
      }

      // Dual-mode TLD (real NS alongside the HIP-5 marker): resolve
      // off-chain first. A plain DNS lookup is far cheaper than an
      // Ethereum round trip, and it gives the off-chain zone final say:
      // only an NXDOMAIN from it makes the name an on-chain candidate,
      // and an off-chain answer always wins over eth.
      let offchainNXDOMAIN: any = null;

      if (realNS.length > 0) {
        const offchain = await this.resolveOffchain(name, type);

        if (offchain) {
          // Relay only genuine off-chain answers. SERVFAIL means the
          // path broke (dead NS, validation failure) — falling through
          // to the on-chain lookups beats relaying a broken rcode,
          // otherwise on-chain names would vanish whenever the
          // off-chain zone misbehaves. Only NXDOMAIN proves the name
          // wasn't published off-chain.
          if (offchain.code === wire.codes.SERVFAIL) {
            // Treat as if the off-chain attempt never happened; the
            // final fallback below returns the marker-free referral.
          } else if (offchain.code !== wire.codes.NXDOMAIN) {
            return offchain;
          } else {
            offchainNXDOMAIN = offchain;
          }
        }
      }

      // Resolve on-chain (cross-chain) names via the HIP-5 extension.
      const hip5Data = await this.resolveDnsViaMarkers(name, type, markers);

      // If we did get an answer, mark the response
      // as authoritative and send the new answer. A and CNAME records
      // (incl. CNAME chains) are routed into the answer section by
      // sendData, per DNS spec.
      if (hip5Data && hip5Data.length > 0) {
        this.logger.debug('Returning answers from alternate naming system');
        return this.sendData(hip5Data, type);
      }

      if (markers.length === 0) {
        // return the HNS root server response unmodified.
        return originalRes;
      }

      if (realNS.length === 0) {
        // Pure HIP-5 TLD with nothing on-chain: never send HIP-5 type
        // referrals to recursive resolvers since they aren't real
        // delegations and it could end up poisoning their cache.
        return this.sendSOA(name, tld, type);
      }

      if (type === wire.types.NS) {
        // Dual-mode TLD, NS question, no on-chain NS records: tell
        // on-chain names from off-chain ones by probing A/CNAME (the
        // types every live EIP-1185 name publishes). On-chain names keep
        // the HIP-5 marker visible in their delegation; off-chain names
        // never see it.
        if (await this.isMintedOnChain(name, markers)) {
          const delegation = new wire.Message();
          delegation.aa = false;
          delegation.authority = markers.slice();
          this.ns.signRRSet(delegation.authority, wire.types.DS);
          return delegation;
        }
      }

      if (offchainNXDOMAIN) {
        // Name doesn't exist off-chain and has nothing on-chain either:
        // relay the off-chain zone's NXDOMAIN (honest, validated
        // negative proof).
        return offchainNXDOMAIN;
      }

      // Off-chain name under a dual-mode TLD (recursive resolver not
      // available): strip the HIP-5 marker from the referral so the
      // recursive resolves it off-chain through the real nameservers,
      // and a requester cannot mistake this for an on-chain delegation.
      return this.stripHip5(res);
    };
  }

  // Full off-chain (real NS) resolution via the plugin's own validating
  // resolver. Its stub zone mirrors the HNS root (markers pruned,
  // self-signed), so the recursor reaches the real nameservers without
  // ever passing through this middleware again. Returns null when
  // recursion is unavailable or failed; the caller then falls back to the
  // on-chain upstream behavior, so a dead off-chain path can never mask
  // an on-chain name.
  async resolveOffchain(name: string, type: number) {
    const offchain = this.offchain;

    if (!offchain) {
      return null;
    }

    try {
      return await offchain.lookup(name, type);
    } catch (e) {
      this.logResolutionFailure(e, name);
      return null;
    }
  }

  // Resolve the requested type through the given HIP-5 markers, returning
  // the first DNS record set the Ethereum side yields (A and CNAME chains
  // included). Ethereum resolution historically returns null for misses;
  // every miss or failure falls through to the next marker.
  async resolveDnsViaMarkers(
    name: string,
    type: number,
    markers: any[]
  ): Promise<Buffer | undefined | null> {
    for (const rr of markers) {
      const ending = hip5Target(rr.data.ns);
      if (ending === null) {
        continue;
      }

      this.logger.debug(
        'Intercepted referral to .%s: %s %s -> %s NS: %s',
        ending,
        name,
        wire.typesByVal[type],
        rr.name,
        rr.data.ns
      );

      try {
        if (ending === HIP5_ZONES.ETH) {
          const data = await this.ethereum.resolveDnsFromEns(
            name,
            type,
            rr.data.ns
          );

          if (data && data.length > 0) {
            return data;
          }
        } else {
          // Look up an alternate (forked) ENS contract by the Ethereum
          // address specified in the NS record
          const data = await this.ethereum.resolveDnsFromAbstractEns(
            name,
            type,
            rr.data.ns
          );

          if (data && data.length > 0) {
            return data;
          }
        }
      } catch (e) {
        this.logResolutionFailure(e, name);
      }
    }

    return undefined;
  }

  // Detect whether a name is minted on-chain when the DNS lookup for the
  // requested type (NS) yields nothing. EIP-1185 datasets don't reliably
  // publish NS records, so probe A and CNAME instead. Not airtight (a
  // name with only MX/TXT records reads as off-chain) but covers how
  // these domains are used in practice.
  async isMintedOnChain(name: string, markers: any[]): Promise<boolean> {
    for (const probeType of [wire.types.A, wire.types.CNAME]) {
      const data = await this.resolveDnsViaMarkers(
        name,
        probeType,
        markers
      );

      if (data && data.length > 0) {
        return true;
      }
    }

    return false;
  }

  // Copy of res — the input comes from hsd's resolver cache and must not
  // be mutated — with the HIP-5 marker NS records stripped and the pruned
  // delegation re-signed.
  // Shared with the off-chain mirror; why the stale NS RRSIG must go (the
  // referral would be bogus to a validating resolver) is documented beside
  // pruneHip5Authority in hip5.ts.
  stripHip5(res: any) {
    const out = new wire.Message();
    out.code = res.code;
    out.aa = res.aa;
    out.answer = res.answer.slice();
    out.authority = pruneHip5Authority(
      res.authority,
      (nsSet, type) => this.ns.signRRSet(nsSet, type)
    );
    out.additional = res.additional;
    return out;
  }

  async open() {
    this.logger.info('handover external network resolver plugin installed.');

    // Bring the off-chain resolver's sockets up (best effort): if the
    // machine cannot bind a loopback port, off-chain lookups fail open to
    // the on-chain path instead of breaking the node.
    try {
      await this.offchain?.open();
    } catch (e) {
      this.logResolutionFailure(e, 'off-chain resolver');
    }

    // The plugin wants to contact the local Ethereum client (Helios) right
    // when it's opened, but if this hsd instance resolves DNS for the system
    // it runs on, the client may not be reachable yet this early in the hsd
    // life cycle. Wait for the node to fully sync before activating.
    if (this.node.chain.isFull()) {
      await this.activate();
    }

    this.node.chain.on('full', () => {
      return this.activate();
    });
  }

  // Initialize the Ethereum client and start answering queries. Safe to call
  // multiple times (a repeat call once the previous retry runner has finished
  // re-fetches the resolver). Never throws an RPC error back at hsd: a throw
  // from here would fail FullNode.openPlugins and crash-loop the node
  // (helios rejects state proofs until it is caught up with the chain tip).
  // Instead, stay not-ready and retry in the background at a fixed interval
  // until the Ethereum client responds — one retry runner at a time.
  async activate() {
    if (this.activationAbort) {
      return;
    }

    const controller = new AbortController();
    this.activationAbort = controller;

    void pRetry(
      async () => {
        await this.ethereum.init();
        this.activationAbort = null;
        this.ready = true;
        this.logger.info(
          'handover external network resolver plugin is active!'
        );
      },
      {
        retries: Infinity,
        minTimeout: ACTIVATION_RETRY_DELAY,
        maxTimeout: ACTIVATION_RETRY_DELAY,
        factor: 1,
        unref: true,
        signal: controller.signal,
        onFailedAttempt: ({ error, attemptNumber }) => {
          this.ready = false;
          this.logger.warning(
            'handover activation attempt %d failed, retrying in %d seconds: %s',
            attemptNumber,
            ACTIVATION_RETRY_DELAY / 1000,
            error.message
          );
          this.logger.debug(error.stack);
        }
      }
    ).catch(() => {
      // Unreachable while retries is Infinity; only close() (via the abort
      // signal) or process shutdown can get us here. Nothing to do.
    });
  }

  // Cancel any background retry runner, e.g. when the plugin is closed.
  stopRetry() {
    this.activationAbort?.abort(new Error('handover plugin closed'));
    this.activationAbort = null;
  }

  // Both middleware lookup paths log failures the same way.
  logResolutionFailure(e: unknown, name: string) {
    this.logger.warning('Resolution failed for name: %s', name);
    this.logger.debug((e as Error).stack);
  }

  async close() {
    this.ready = false;
    this.stopRetry();
    await this.offchain?.close();
  }

  // Mirrors hsd's server.resolve(): look up a name on HNS normally.
  async resolveHNS(req: any, name: string, type: number, tld: string) {
    let res = null;

    // Check the root resolver cache first
    const cache = this.ns.cache.get(name, type);

    if (cache) {
      res = cache;
    } else {
      res = await this.ns.response(req);
      // Cache responses
      if (!util.equal(tld, '_synth.')) {
        this.ns.cache.set(name, type, res);
      }
    }

    return res;
  }

  // SOA-only reply when we have no answer or don't want to give one.
  async sendSOA(name: string, tld: string, type: number) {
    const res = new wire.Message();
    res.aa = true;
    const nsec = this.toNSEC(name);

    if (name === tld) {
      // Prove ENT with NSEC RRSIG
      nsec.data.typeBitmap = TYPE_MAP_EMPTY;
    } else {
      // claim all types exist except for qtype
      const typeMap = TYPE_MAP_ALL.filter((v) => {
        return v !== type;
      });

      nsec.data.setTypes(typeMap);
    }

    res.authority.push(nsec);
    this.ns.signRRSet(res.authority, wire.types.NSEC);
    res.authority.push(this.ns.toSOA());
    this.ns.signRRSet(res.authority, wire.types.SOA);

    return res;
  }

  toNSEC(name: string) {
    const rr = new wire.Record();
    const rd = new wire.NSECRecord();
    rr.name = util.fqdn(name);
    rr.type = wire.types.NSEC;
    rr.ttl = 36 * 10 * 60;

    rd.nextDomain = util.fqdn('\\000.' + name);
    rr.data = rd;

    return rr;
  }

  // Convert a wire-format DNS record to a message and send.
  sendData(data: Buffer, type: number) {
    const res = new wire.Message();
    res.aa = true;
    const br = new BufferReader(data);

    while (br.left() > 0) {
      const rr = wire.Record.read(br);

      if (rr.type === wire.types.NS) {
        res.authority.push(rr);
      } else if (rr.type === type || rr.type === wire.types.CNAME) {
        res.answer.push(rr);
      } else {
        res.authority.push(rr);
      }
    }

    // Referral answer
    if (res.answer.length === 0 && res.authority.length > 0) {
      res.aa = false;
      this.ns.signRRSet(res.authority, wire.types.DS);
    }

    // Answers resolved from alternate name systems appear to come directly
    // from the HNS root zone.
    this.ns.signRRSet(res.answer, type);

    if (type !== wire.types.CNAME) {
      this.ns.signRRSet(res.answer, wire.types.CNAME);
    }

    return res;
  }
}

export const id = 'handover';

export function init(node: HsdNode): Plugin {
  return new Plugin(node);
}
