import bns from 'bns';
import { BufferReader } from 'bufio';
import pRetry from 'p-retry';
import Ethereum from './ethereum.ts';

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

class Plugin {
  ready = false;
  node: HsdNode;
  ns: any;
  logger: any;
  ethereum: Ethereum;
  activationAbort: AbortController | null = null;

  constructor(node: HsdNode) {
    this.node = node;
    this.ns = node.ns;
    this.logger = node.logger.context('handover');

    this.ethereum = new Ethereum({
      rpcUrl: node.config.str('handover-rpc-url')
    });

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
        case 'eth.':
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
        case '_eth.':
          return this.sendSOA(name, tld, type);
      }

      // Next, try actually resolving the name with the HNS root zone.
      // We are going to examine the result before sending it back.
      const originalRes = await this.resolveHNS(req, name, type, tld);

      // Special DS processing if the request is "<hip-5 tld> DS"
      // handover won't find any referral in the answer
      // it won't recognize it as a HIP5 name which results
      // in a bad proof "NS RRSIG NSEC". Need to manually
      // request "<hip-5 tld> NS" for handover to process it.
      const res = type === wire.types.DS && labels.length === 1
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
        return type === wire.types.DS && labels.length === 1 ? originalRes : res;
      }

      let hip5Referral = false;

      // Check NS records for HIP-5 referrals
      for (const rr of res.authority) {
        if (rr.type !== wire.types.NS) {
          continue;
        }

        const ending = util.label(rr.data.ns, util.split(rr.data.ns), -1);

        // Look for any supported HIP-5 extension in the NS record
        // and query it for the user's original request.
        if (ending === '_eth' || ending === 'eth') {
          hip5Referral = true;

          // If the recursive is being minimal, don't look up the name.
          // Send the SOA back and get the full query from the recursive.
          if (labels.length < 2) {
            return this.sendSOA(name, tld, type);
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
            switch (ending) {
              case 'eth':
                data = await this.ethereum.resolveDnsFromEns(
                  name,
                  type,
                  rr.data.ns
                );
                break;
              case '_eth':
                // Look up an alternate (forked) ENS contract by the Ethereum
                // address specified in the NS record
                data = await this.ethereum.resolveDnsFromAbstractEns(
                  name,
                  type,
                  rr.data.ns
                );
                break;
            }
          } catch (e) {
            this.logResolutionFailure(e, name);
          }
        }
      }

      if (!data || data.length === 0) {
        // Never send HIP-5 type referrals to recursive resolvers
        // since they aren't real delegations and it could end up
        // poisoning their cache.
        if (hip5Referral) {
          return this.sendSOA(name, tld, type);
        }

        // return the HNS root server response unmodified.
        return originalRes;
      }

      // If we did get an answer, mark the response
      // as authoritative and send the new answer.
      this.logger.debug('Returning answers from alternate naming system');
      return this.sendData(data, type);
    };
  }

  async open() {
    this.logger.info('handover external network resolver plugin installed.');

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

  close() {
    this.ready = false;
    this.stopRetry();
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
