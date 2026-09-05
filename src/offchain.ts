import bns from 'bns';
import { pruneHip5Authority } from './hip5.ts';

const { wire, dnssec } = bns;

const { types, codes } = wire;

// Upper bound for a single off-chain resolution: UnboundResolver retries
// internally (maxAttempts × maxTimeout); this guard keeps a wedged stub or
// an unreachable nameserver from hanging the middleware past that.
const RESOLUTION_TIMEOUT = 10 * 1000;

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
  #stubOpened = false;
  #opening: Promise<void> | null = null;
  #timeout: number;

  constructor(hooks: OffchainHooks, logger?: any, timeout: number = RESOLUTION_TIMEOUT) {
    this.#hooks = hooks;
    this.#logger = logger ?? null;
    this.#timeout = timeout;

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
    try {
      // Destructure inside the try: a malformed request (no/empty question)
      // throws here and is normalized to SERVFAIL below instead of leaving
      // the recursor hanging.
      const [qs] = req.question;
      return await this.#mirror(await this.#hooks.resolve(qs.name, qs.type));
    } catch (e) {
      this.#log(
        'mirror failure: %s',
        (e as Error).stack || (e as Error).message
      );

      const res = new wire.Message();
      res.code = codes.SERVFAIL;
      return res;
    }
  }

  // Bring the stub + recursor pair up, bounded so a wedged bring-up cannot
  // leave the shared, memoized `open()` pending forever. Lookups inside the
  // middleware all await the same `open()` promise; if it never settled, a
  // single stalled request would hang every off-chain query behind it (and
  // DoH endpoints that expect a prompt answer would time out / EOF). On
  // timeout the memo resets so the next lookup retries from scratch, and
  // callers fail fast into the on-chain path instead of stalling.
  #bringUp(): Promise<void> {
    // If the deadline fires while the bring-up is mid-flight (after the stub
    // bound its loopback socket but before `#resolver.open()` completes),
    // the socket must not be left behind: `#stubOpened` is tracked so a
    // retried bring-up or `close()` always releases it.
    let aborted = false;

    const bring = (async () => {
      if (aborted) {
        throw new Error('off-chain resolver bring-up aborted');
      }

      // Pin the trust anchor from the root's own DNSKEY answer: the KSK
      // whose signatures cover the '. DNSKEY' RRset we relay.
      const parent = await this.#hooks.resolve('.', types.DNSKEY);
      const ksk = parent.answer.find((rr: any) => {
        return rr.type === types.DNSKEY && (rr.data.flags & wire.keyFlags.KSK);
      });

      if (aborted) {
        throw new Error('off-chain resolver bring-up aborted');
      }

      if (ksk == null) {
        throw new Error('Root zone has no KSK to anchor off-chain recursion.');
      }

      // Same bytes through this module's own Record class: dnssec.createDS
      // asserts `instanceof`, and relayed records may come from hsd's bns
      // copy, which is a distinct module instance.
      const anchorKey = wire.Record.fromJSON(ksk.toJSON());
      const anchor = dnssec.createDS(anchorKey, dnssec.hashes.SHA256);

      this.#log('off-chain resolver pinned root trust anchor');

      await this.#stub.open(0, '127.0.0.1');
      this.#stubOpened = true;

      const { port } = this.#stub.address();
      this.#log('off-chain resolver mirror listening on 127.0.0.1:%d', port);
      this.#resolver.setStub('127.0.0.1', port, anchor);
      await this.#resolver.open();

      if (aborted) {
        throw new Error('off-chain resolver bring-up aborted');
      }

      this.#opened = true;
      this.#log('off-chain resolver ready (stub %s)', this.stubAddress);
    })();

    const { done } = this.#setTimeout();
    const deadline = done.then(() => {
      aborted = true;
      throw new Error('off-chain resolver failed to open within timeout');
    });

    return Promise.race([bring, deadline]).finally(() => {
      // Only a half-open bring-up (bound the stub but never fully opened:
      // deadline fired, or a step after stub.open threw) must release it
      // here. A fully-opened resolver stays up for the lookups it serves.
      if (this.#stubOpened && !this.#opened) {
        void this.#teardownOpened();
      }
    });
  }

  // Tear down whatever bring-up left open, zeroing the open flags first so
  // a concurrent close() (or vice versa) can't double-close. Both the
  // deadline finalizer and close() route through here; the single place
  // also fixes the close ordering (resolver before stub).
  async #teardownOpened(): Promise<void> {
    const resolverOpen = this.#opened;
    const stubOpen = this.#stubOpened;
    this.#opened = false;
    this.#stubOpened = false;

    if (resolverOpen) {
      await this.#resolver.close().catch(() => {});
    }
    if (stubOpen) {
      await this.#stub.close().catch(() => {});
    }
  }

  // Unref'd one-shot timer resolving after the resolution timeout. The
  // bring-up deadline, close(), and lookup() each apply their own settle
  // semantics on top; a cancelled loser never settles late (and never
  // rejects unhandled).
  #setTimeout(): { done: Promise<void>; cancel: () => void } {
    let cancel = () => {};
    const done = new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, this.#timeout);
      timer.unref();
      cancel = () => clearTimeout(timer);
    });
    return { done, cancel };
  }

  async open(): Promise<void> {
    if (this.#opened) {
      return;
    }

    if (!this.#opening) {
      const opening = this.#bringUp();

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
    const opening = this.#opening;
    this.#opening = null;

    // Don't let a never-settling bring-up block shutdown: wait at most the
    // resolution timeout for it, then tear down whatever is actually open.
    if (opening) {
      const { done } = this.#setTimeout();
      await Promise.race([opening.catch(() => {}), done]);
    }

    await this.#teardownOpened();
  }

  async lookup(name: string, type: number): Promise<any> {
    await this.open();

    this.#log('off-chain lookup: %s %s', name, type);

    // The timeout below cannot abort the underlying query — bns 0.16 has
    // no per-query cancellation primitive, and tearing down the shared
    // resolver would kill concurrent lookups. The abandoned query still
    // self-bounds through the recursor's maxAttempts × maxTimeout, so
    // this only caps how long a *caller* waits.
    const { done, cancel } = this.#setTimeout();
    try {
      return await Promise.race([
        this.#resolver.lookup(name, type).then(
          (msg: any) => {
            this.#log(
              'off-chain answer: %s %s -> code=%s (%d answers)',
              name,
              type,
              msg.code,
              msg.answer ? msg.answer.length : 0
            );
            return msg;
          },
          (err: any) => {
            this.#log(
              'off-chain lookup failed: %s %s (%s)',
              name,
              type,
              (err as Error).message
            );
            throw err;
          }
        ),
        done.then(() => {
          this.#log('off-chain lookup timed out: %s %s', name, type);
          throw new Error(`off-chain lookup timed out: ${name} ${type}`);
        })
      ]);
    } finally {
      cancel();
    }
  }

  // Relay an HNS root response; prune HIP-5 marker NS records and re-sign
  // the pruned delegation. Everything else keeps the root's signatures.
  // Signer contract is documented beside pruneHip5Authority (hip5.ts):
  // only the fresh signature records flow back into the relayed message.
  #mirror(msg: any): any {
    const res = new wire.Message();

    res.code = msg.code;
    res.aa = msg.aa;
    res.ad = msg.ad;
    res.answer = msg.answer;
    res.additional = msg.additional;
    res.authority = pruneHip5Authority(
      msg.authority,
      (nsSet, type) => this.#hooks.sign(nsSet, type)
    );

    return res;
  }

  #log(...args: any[]): void {
    if (this.#logger) {
      this.#logger.debug(...args);
    }
  }
}
