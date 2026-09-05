import bns from 'bns';

const { wire, util, dnssec } = bns;

const { types, codes } = wire;

// Upper bound for a single off-chain resolution: UnboundResolver retries
// internally (maxAttempts × maxTimeout); this guard keeps a wedged stub or
// an unreachable nameserver from hanging the middleware past that.
const RESOLUTION_TIMEOUT = 10 * 1000;

// Zones an NS delegation target can point into to mark a HIP-5 referral.
// Mirrors hip5Target() in handover.ts; kept local so this module stays off
// the handover import graph.
const HIP5_ZONES = new Set(['eth', '_eth']);

function isHip5NS(rr: any): boolean {
  if (rr.type !== types.NS) {
    return false;
  }

  // Last label, trailing dot or not.
  const name = String(rr.data.ns).toLowerCase();
  const label = util.label(name, util.split(name), -1);

  return HIP5_ZONES.has(label);
}

export interface OffchainHooks {
  // Root-zone lookup that bypasses ns.middle (the plugin's resolveHNS).
  // Returns an HNS root response for (name, type) exactly as hsd's
  // RootServer would answer it.
  resolve: (name: string, type: number) => Promise<any>;

  // hsd's own RRset signer (node.ns.signRRSet), used to re-sign the only
  // RRset the mirror is allowed to modify: the marker-pruned NS referral.
  // Must be hsd's own signer because relayed records are instances of
  // hsd's bns copy — third-party signatures stay intact, so every other
  // RRset is relayed untouched.
  sign: (rrset: any[], type: number) => void;
}

/**
 * Off-chain recursion with DNSSEC validation, bypassing hsd's root server
 * entirely.
 *
 * hsd's own RecursiveServer resolves by sending every query to the root
 * nameserver socket (127.0.0.1:5300), on which Handover is installed as an
 * `ns.middle` hook — so it re-enters this middleware with the same qname it
 * is still resolving, and the middleware recurses into itself. This
 * resolver is self-contained instead: it runs a mirror of the root zone on
 * 127.0.0.1:<ephemeral> and points a bns UnboundResolver (the same
 * validating recursive resolver hsd uses) at it.
 *
 * The mirror relays the HNS root's responses untouched — signatures and
 * all, so they validate against the root's own KSK, which is relayed via
 * the '. DNSKEY' answer and pinned as the recursor's trust anchor. The one
 * permitted edit: HIP-5 marker NS records are pruned from referrals (bogus
 * `_eth` targets would otherwise be chased or randomly picked by the
 * recursor), and the pruned NS RRset is re-signed with hsd's own signer.
 */
export default class OffchainResolver {
  #hooks: OffchainHooks;
  #logger: any;
  #stub: any;
  #resolver: any;
  #opened = false;
  #opening: Promise<void> | null = null;

  constructor(hooks: OffchainHooks, logger?: any) {
    this.#hooks = hooks;
    this.#logger = logger ?? null;

    this.#stub = new bns.DNSServer({ inet6: false, tcp: true });
    this.#stub.ra = false;
    this.#stub.edns = true;
    this.#stub.dnssec = true;
    // bns reads answers from this.resolve(req, rinfo) on the DNSServer
    // itself; without this hook its default handler throws (and the base
    // class swallows the error) and every stub query dies in silence.
    this.#stub.resolve = (req: any, rinfo: any) => this.resolve(req, rinfo);

    this.#resolver = new bns.UnboundResolver({
      inet6: false,
      tcp: true,
      edns: true,
      dnssec: true,
      minimize: true
    });
  }

  get stubAddress(): string | null {
    if (!this.#opened) {
      return null;
    }

    const { address, port } = this.#stub.address();
    return `${address}:${port}`;
  }

  // bns DNSServer.answer() dispatches to resolve(req, rinfo). Always
  // resolves to a Message so the server layer never leaves the recursor
  // hanging.
  async resolve(req: any, _rinfo: any): Promise<any> {
    const [qs] = req.question;

    try {
      return await this.#mirror(await this.#hooks.resolve(qs.name, qs.type));
    } catch (e) {
      this.#log(
        'mirror failure for %s: %s',
        qs.name,
        (e as Error).stack || (e as Error).message
      );

      const res = new wire.Message();
      res.code = codes.SERVFAIL;
      return res;
    }
  }

  async open(): Promise<void> {
    if (this.#opened) {
      return;
    }

    if (!this.#opening) {
      const opening = (async () => {
        // Pin the trust anchor from the root's own DNSKEY answer: the KSK
        // whose signatures cover the '. DNSKEY' RRset we relay.
        const parent = await this.#hooks.resolve('.', types.DNSKEY);
        const ksk = parent.answer.find((rr: any) => {
          return rr.type === types.DNSKEY && (rr.data.flags & wire.keyFlags.KSK);
        });

        if (ksk == null) {
          throw new Error('Root zone has no KSK to anchor off-chain recursion.');
        }

        // Same bytes through this module's own Record class: dnssec.createDS
        // asserts `instanceof`, and relayed records may come from hsd's bns
        // copy, which is a distinct module instance.
        const anchorKey = wire.Record.fromJSON(ksk.toJSON());
        const anchor = dnssec.createDS(anchorKey, dnssec.hashes.SHA256);

        await this.#stub.open(0, '127.0.0.1');
        const { port } = this.#stub.address();
        this.#resolver.setStub('127.0.0.1', port, anchor);
        await this.#resolver.open();
        this.#opened = true;
      })();

      // A failed bring-up (no KSK yet, bind refused) must not stay
      // memoized: the next lookup would replay a rejected promise
      // forever and off-chain resolution would never retry.
      this.#opening = opening;
      opening.catch(() => {
        if (this.#opening === opening) {
          this.#opening = null;
        }
      });
    }

    return this.#opening;
  }

  async close(): Promise<void> {
    try {
      await this.#opening;
      this.#opening = null;

      if (this.#opened) {
        this.#opened = false;
        await this.#resolver.close();
        await this.#stub.close();
      }
    } catch (e) {
      this.#opening = null;
      this.#opened = false;
    }
  }

  async lookup(name: string, type: number): Promise<any> {
    await this.open();

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`off-chain lookup timed out: ${name} ${type}`));
      }, RESOLUTION_TIMEOUT);

      timer.unref();

      this.#resolver.lookup(name, type).then(
        (msg: any) => {
          clearTimeout(timer);
          resolve(msg);
        },
        (err: any) => {
          clearTimeout(timer);
          reject(err);
        }
      );
    });
  }

  // Relay an HNS root response; prune HIP-5 marker NS records and re-sign
  // the pruned delegation. Everything else keeps the root's signatures.
  // The signer appends its RRSIG to the array it is given; only the fresh
  // signature records flow back into the relayed message.
  #mirror(msg: any): any {
    const res = new wire.Message();

    res.code = msg.code;
    res.aa = msg.aa;
    res.ad = msg.ad;
    res.answer = msg.answer;
    res.additional = msg.additional;

    const markers = msg.authority.filter((rr: any) => isHip5NS(rr));

    if (markers.length === 0) {
      res.authority = msg.authority;
      return res;
    }

    const nsOwner = markers[0].name;

    // Marker-free NS records of the delegation, re-signed as a group.
    const nsSet: any[] = [];

    for (const rr of msg.authority) {
      if (rr.type === types.NS
          && !isHip5NS(rr)
          && util.equal(rr.name, nsOwner)) {
        nsSet.push(rr);
      }
    }

    if (nsSet.length > 0) {
      this.#hooks.sign(nsSet, types.NS);
    }

    const out: any[] = [];

    for (const rr of msg.authority) {
      // Markers themselves are never relayed.
      if (isHip5NS(rr)) {
        continue;
      }

      // The old NS signature no longer covers the pruned subset.
      if (rr.type === types.RRSIG
          && rr.data.typeCovered === types.NS
          && util.equal(rr.name, nsOwner)) {
        continue;
      }

      out.push(rr);
    }

    // The signer's fresh RRSIGs arrived on the nsSet array.
    for (const rr of nsSet) {
      if (rr.type === types.RRSIG) {
        out.push(rr);
      }
    }

    res.authority = out;

    return res;
  }

  #log(...args: any[]): void {
    if (this.#logger) {
      this.#logger.debug(...args);
    }
  }
}
