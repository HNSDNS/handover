import { describe, it, expect, vi } from 'vitest';
import bns from 'bns';
import { init } from '../src/handover.ts';
import { EthereumUnhealthyError, DEFAULT_RPC_URL } from '../src/ethereum.ts';
import {
  aRecord,
  aRecordBytes,
  dualReferral,
  fakeSign,
  GLUE_ADDR,
  LABEL_NS,
  MARKER_NS,
  nxdomainMessage,
  question,
  signedDualReferral,
  soaRecord,
  STALE_ROOT_SIG,
  tlsaRecord,
  tlsaRecordBytes
} from './helpers.ts';

const { wire } = bns;

interface FakeNode {
  ns: {
    middle?: (tld: string, req: any) => Promise<any>;
    signRRSet: (rrset: any[], type: number) => void;
    toSOA: () => any;
  };
  config: { str: () => string };
  logger: { context: () => { debug: (...a: any[]) => void; warning: (...a: any[]) => void } };
  chain: object;
}

// When `debugLog` is given, every logger.debug call is recorded there as
// its argument list so tests can assert the exact log lines emitted.
function makeNode(debugLog?: any[][]): FakeNode {
  return {
    ns: {
      signRRSet() {},
      toSOA: () => new wire.Record({ name: '.', type: wire.types.SOA, data: new wire.SOARecord() })
    },
    config: { str: () => DEFAULT_RPC_URL },
    logger: {
      context: () => ({
        debug: (...a: any[]) => { debugLog?.push(a); },
        warning() {},
        info() {}
      })
    },
    chain: {}
  };
}

function markerRecords(msg: typeof wire.Message.prototype): any[] {
  return msg.authority.filter((rr: any) => {
    return rr.type === wire.types.NS && rr.data.ns === MARKER_NS;
  });
}

// Construct the plugin, mark it ready, and apply dependency overrides.
// Single bootstrap path so readiness/wiring changes are updated in one place.
function makeReadyPlugin(node: FakeNode, overrides?: Record<string, any>): any {
  const plugin = init(node as any);
  plugin.ready = true;

  if (overrides) {
    for (const [key, value] of Object.entries(overrides)) {
      (plugin as any)[key] = value;
    }
  }

  return plugin;
}

// Same surface as OffchainResolver, without sockets or recursion. Records
// every lookup so tests can assert what the middleware actually asks for.
function makeOffchainStub(answer: any): any {
  const lookups: { name: string; type: number }[] = [];
  return {
    lookups,
    open: async () => {},
    lookup: async (name: string, type: number) => {
      lookups.push({ name, type });
      return answer;
    }
  };
}

// Root referral for a plain delegation: real nameservers only, zero HIP-5
// markers — the shape ICANN mirror TLDs (com., it.) and every ordinary HNS
// TLD present to the middleware.
function plainReferral(): any {
  const msg = new wire.Message();
  msg.code = wire.codes.NOERROR;
  msg.authority.push(
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl: 0, type: 'NS', data: { ns: LABEL_NS } })
  );
  return msg;
}

function setupDualPlugin(node: FakeNode, opts: {
  offchain?: any | null;
  eth?: (name: string, type: number) => Buffer | null;
  // Referral factory; defaults to the plain unsigned dual referral. Held
  // by a stable reference so the middleware's base response is an object
  // the test can still see: if the middleware mutated it (the
  // cached-referral hazard), the post-resolution marker assertions catch it.
  referral?: () => any;
}): any {
  const dual = opts.referral ? opts.referral() : dualReferral({ ttl: 0 });

  const plugin = makeReadyPlugin(node, {
    resolveHNS: async () => dual,
    offchain: opts.offchain === null ? null : makeOffchainStub(opts.offchain)
  });

  (plugin as any).ethereum.resolveDnsFromEns = opts.eth ?? (async () => null);
  (plugin as any).ethereum.resolveDnsFromAbstractEns = opts.eth ?? (async () => null);
  return plugin;
}

describe('handover middleware: DS->NS rewrite (HIP-5)', () => {
  it('answers a single-label DS query with the original DS response when the synthetic NS lookup has no authority', async () => {
    const node = makeNode();

    // The original DS query resolves normally; the synthetic NS lookup for
    // the same name returns no records (empty authority).
    const plugin = makeReadyPlugin(node, {
      resolveHNS: async (_req: any, _name: string, type: number) => {
        const msg = new wire.Message();
        if (type === wire.types.DS) {
          msg.answer.push(new wire.Record({ type: wire.types.DS, name: 'foo' }));
          msg.code = wire.codes.NOERROR;
        }
        return msg;
      }
    });

    const req = { question: [new wire.Question('foo', wire.types.DS)] };
    const res = await node.ns.middle!('foo.', req);

    // Must be the original DS response (has an answer), not the empty
    // NS-typed message the synthetic rewrite produced. Without the fix the
    // empty-authority NS response would be returned (answer.length === 0).
    expect(res.answer.length).toBe(1);
  });
});

describe('handover middleware: dual-mode HIP-5 TLDs', () => {
  it('relays off-chain answers untouched without consulting eth', async () => {
    const node = makeNode();
    const answer = new wire.Message();
    answer.code = wire.codes.NOERROR;
    answer.answer.push(aRecord('foo.hns.'));

    let ethCalls = 0;
    const plugin = setupDualPlugin(node, {
      offchain: answer,
      eth: () => { ethCalls++; return null; }
    });

    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(res.code).toBe(wire.codes.NOERROR);
    expect(res.answer.map((rr: any) => rr.type)).toEqual([wire.types.A]);
    expect(ethCalls).toBe(0);

    // The cached referral must not be mutated.
    const referral = await (plugin as any).resolveHNS();
    expect(markerRecords(referral).length).toBe(1);
  });

  it('stripHip5 drops the stale NS RRSIG and re-signs the pruned delegation', () => {
    const signed: number[] = [];
    const node = makeNode();
    node.ns.signRRSet = (rrset: any[], type: number) => {
      signed.push(rrset.length);
      // Same stale shape, different signature bytes so the re-signed
      // RRSIG is distinguishable from the referral's own.
      fakeSign(rrset, type, { ...STALE_ROOT_SIG, signature: 'ZnJlc2g=' });
    };
    const plugin = init(node as any);
    plugin.ready = true;

    // dual-mode referral carrying the root NS RRSIG over the unpruned RRset.
    const dual = signedDualReferral();
    const out = plugin.stripHip5(dual);

    // The HIP-5 marker is gone; only the real nameserver remains.
    const nsTargets = out.authority
      .filter((rr: any) => rr.type === wire.types.NS)
      .map((rr: any) => rr.data.ns);
    expect(nsTargets).toEqual([LABEL_NS]);

    // The stale NS RRSIG (covering marker + real NS) must be replaced by a
    // fresh one over the pruned subset, exactly once.
    const nsSigs = out.authority.filter((rr: any) =>
      rr.type === wire.types.RRSIG && rr.data.typeCovered === wire.types.NS);
    expect(nsSigs.length).toBe(1);
    expect(signed).toEqual([1]);
  });

  it('relays a DNSSEC referral stripped via the middleware with no leftover RRSIG', async () => {
    const node = makeNode();

    // Regression for the full relay path (the no-recursor fallback reaches
    // stripHip5 with the raw referral): a stale NS RRSIG covering the
    // unpruned RRset used to survive the marker strip, which a validating
    // resolver rejects as bogus (SERVFAIL). The pruned delegation must
    // never ship a signature it no longer matches.
    const plugin = setupDualPlugin(node, {
      offchain: null,
      referral: () => dualReferral({ ttl: 0, dnssec: true })
    });

    const res = await node.ns.middle!('hns.', question(wire.types.A));

    // The real delegation survives; the marker and any RRSIG (stale root
    // signature included) do not.
    expect(markerRecords(res).length).toBe(0);
    expect(res.authority.some((rr: any) => rr.data.ns === LABEL_NS)).toBe(true);
    expect(res.authority.some((rr: any) => rr.type === wire.types.RRSIG)).toBe(false);
  });

  it('stripHip5 preserves answer/additional sections and never mutates the input', () => {
    const node = makeNode();
    const plugin = init(node as any);
    plugin.ready = true;

    const answer = wire.Record.fromJSON({
      class: 'IN', name: 'foo.hns.', ttl: 60, type: 'A', data: { address: '9.9.9.9' }
    });
    const dual = signedDualReferral();
    dual.answer.push(answer);
    const before = dual.authority.slice();

    const out = plugin.stripHip5(dual);

    // Answer and glue survive the copy untouched.
    expect(out.answer).toEqual([answer]);
    expect(out.additional.map((rr: any) => rr.data.address)).toEqual([GLUE_ADDR]);

    // Input comes from hsd's resolver cache: markers still present after
    // the strip.
    expect(markerRecords(dual).length).toBe(1);
    expect(dual.authority).toEqual(before);
  });

  it('treats an upstream SERVFAIL as off-chain failure and falls through to eth', async () => {
    const node = makeNode();

    let ethCalls = 0;
    const plugin = setupDualPlugin(node, {
      offchain: { code: wire.codes.SERVFAIL },
      eth: () => { ethCalls++; return null; }
    });

    // A broken off-chain zone must never mask an on-chain name: the
    // middleware falls through as if the off-chain attempt never happened.
    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(ethCalls).toBeGreaterThan(0);
    expect(markerRecords(res).length).toBe(0);
  });

  it('resolves eth-minted names after an off-chain NXDOMAIN', async () => {
    const node = makeNode();
    const nxdomain = nxdomainMessage();

    const aRec = aRecordBytes('foo.hns.');
    const plugin = setupDualPlugin(node, {
      offchain: nxdomain,
      eth: (_name, type) => type === wire.types.A ? aRec : null
    });

    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(res.answer.length).toBe(1);
    expect(res.answer[0].type).toBe(wire.types.A);
    expect(markerRecords(res).length).toBe(0);
  });

  it('relays the negative proof when a name exists neither on- nor off-chain', async () => {
    const node = makeNode();
    const nxdomain = nxdomainMessage();
    nxdomain.authority.push(soaRecord('hns.'));

    const plugin = setupDualPlugin(node, { offchain: nxdomain });

    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(res.code).toBe(wire.codes.NXDOMAIN);
    expect(res.authority.some((rr: any) => rr.type === wire.types.SOA)).toBe(true);
    expect(markerRecords(res).length).toBe(0);
  });

  it('asks the off-chain resolver by the exact qname and type', async () => {
    const node = makeNode();
    const answer = new wire.Message();
    answer.code = wire.codes.NOERROR;

    const plugin = setupDualPlugin(node, { offchain: answer });
    const res = await node.ns.middle!('hns.', question(wire.types.A));

    expect(res.code).toBe(wire.codes.NOERROR);

    const lookups = (plugin as any).offchain.lookups;
    expect(lookups).toHaveLength(1);
    // bns normalizes the qname to a fully-qualified form; match on the name
    // minus any trailing dot.
    expect(lookups[0].name.replace(/\.$/, '')).toBe('foo.hns');
    expect(lookups[0].type).toBe(wire.types.A);
  });

  it('returns null from resolveOffchain when the off-chain resolver explodes', async () => {
    const node = makeNode();
    const plugin = makeReadyPlugin(node, {
      offchain: {
        lookup: async () => { throw new Error('socket exploded'); }
      }
    });

    const out = await (plugin as any).resolveOffchain('foo.hns', wire.types.A);
    expect(out).toBeNull();
  });

  it('keeps the HIP-5 marker visible in NS delegations for on-chain names', async () => {
    const node = makeNode();
    const nxdomain = nxdomainMessage();

    const aRec = aRecordBytes('foo.hns.');
    // No NS data on the eth side; A probe proves the name is on-chain.
    const plugin = setupDualPlugin(node, {
      offchain: nxdomain,
      eth: (_name, type) => type === wire.types.A ? aRec : null
    });

    const res = await node.ns.middle!('hns.', question(wire.types.NS));
    expect(res.answer.length).toBe(0);
    expect(res.authority.map((rr: any) => rr.type)).toContain(wire.types.NS);
    expect(markerRecords(res).length).toBe(1);
    expect(res.aa).toBe(false);
  });

  it('never leaks the HIP-5 marker for off-chain NS requests', async () => {
    const node = makeNode();
    const nxdomain = nxdomainMessage();

    const plugin = setupDualPlugin(node, { offchain: nxdomain });

    const res = await node.ns.middle!('hns.', question(wire.types.NS));
    expect(markerRecords(res).length).toBe(0);

    // The cached referral must not be mutated.
    const referral = await (plugin as any).resolveHNS();
    expect(markerRecords(referral).length).toBe(1);
  });

  it('falls back to eth-first and strips the marker when off-chain resolving is unavailable', async () => {
    const node = makeNode();
    let ethCalls = 0;
    const plugin = setupDualPlugin(node, {
      offchain: null,
      eth: () => { ethCalls++; return null; }
    });

    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(ethCalls).toBeGreaterThan(0);
    // The referral carries the marker; the stripped response must not.
    expect(markerRecords(res).length).toBe(0);
    expect(res.authority.some((rr: any) => rr.type === wire.types.NS)).toBe(true);
  });

  it('passes marker-free referrals through without invoking the off-chain resolver', async () => {
    const node = makeNode();

    // ICANN-mirror shape: the referral's NS RRset contains only real
    // nameservers, no HIP-5 markers. The parent recursive resolver must
    // follow this delegation itself; a full in-process off-chain recursion
    // would resolve the name twice and its answer was discarded.
    const referral = plainReferral();
    const answer = new wire.Message();
    answer.code = wire.codes.NOERROR;
    const plugin = makeReadyPlugin(node, {
      resolveHNS: async () => referral,
      offchain: makeOffchainStub(answer)
    });
    const lookups = plugin.offchain.lookups as { name: string; type: number }[];

    for (const qtype of [wire.types.A, wire.types.NS]) {
      const res = await node.ns.middle!('hns.', question(qtype));

      // (a) the off-chain resolver was never asked to resolve anything.
      expect(lookups).toHaveLength(0);

      // (b) the HNS root response is returned unmodified: it is the same
      // referral object, wire-encoding-wise untouched, real NS included.
      expect(res.encode().equals(referral.encode())).toBe(true);
      expect(res.authority.some((rr: any) => rr.data.ns === LABEL_NS)).toBe(true);
      expect(markerRecords(res).length).toBe(0);
    }
  });

  it('serves the bare TLD NS referral with the HIP-5 marker intact', async () => {
    const node = makeNode();
    const plugin = setupDualPlugin(node, { offchain: null });

    const res = await node.ns.middle!('hns.', question(wire.types.NS, 'hns'));
    expect(markerRecords(res).length).toBe(1);
    expect(res.authority.some((rr: any) => rr.data.ns === LABEL_NS)).toBe(true);
  });

  it('preserves upstream behavior for pure HIP-5 TLDs: eth answer then SOA', async () => {
    const node = makeNode();
    const ethOnly = new wire.Message();
    ethOnly.code = wire.codes.NOERROR;
    ethOnly.authority.push(
      wire.Record.fromJSON({ class: 'IN', name: 'pure.', ttl: 0, type: 'NS', data: { ns: MARKER_NS } })
    );

    const plugin = makeReadyPlugin(node, {
      resolveHNS: async () => ethOnly,
      offchain: makeOffchainStub(null)
    });
    (plugin as any).ethereum.resolveDnsFromEns = async () => null;

    // Pure-eth miss: hidden referral, signed negative response.
    const res = await node.ns.middle!('pure.', question(wire.types.A, 'foo.pure'));
    expect(res.answer.length).toBe(0);
    expect(markerRecords(res).length).toBe(0);
    expect(res.authority.some((rr: any) => rr.type === wire.types.NSEC)).toBe(true);

    // Pure-eth hit: authoritative injected answer.
    const aRec = aRecordBytes('foo.pure.', '5.6.7.8');
    (plugin as any).ethereum.resolveDnsFromEns = async () => aRec;
    (plugin as any).ethereum.resolveDnsFromAbstractEns = async () => aRec;
    const hit = await node.ns.middle!('pure.', question(wire.types.A, 'foo.pure'));
    expect(hit.answer.length).toBe(1);
    expect(hit.answer[0].type).toBe(wire.types.A);
  });
});

describe('handover middleware: silent-path logging', () => {
  it('logs exactly one debug line when refusing a pre-activation query', async () => {
    const logs: any[][] = [];
    const node = makeNode(logs);
    // A freshly inited plugin is not yet active — the only state the gate
    // fires in — so no readiness override here.
    const plugin = init(node as any);
    expect(plugin.ready).toBe(false);

    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(res.code).toBe(wire.codes.REFUSED);
    expect(logs).toEqual([
      ['Middleware hit while not active, refusing: %s', 'foo.hns.']
    ]);
  });

  it('logs the hit line for a successful .eth answer', async () => {
    const logs: any[][] = [];
    const node = makeNode(logs);
    const plugin = makeReadyPlugin(node);
    const aRec = aRecordBytes('foo.eth.');
    (plugin as any).ethereum.resolveDnsFromEns = async () => aRec;

    const res = await node.ns.middle!('eth.', question(wire.types.A, 'foo.eth'));
    expect(res.answer.length).toBe(1);
    expect(res.answer[0].type).toBe(wire.types.A);
    // data is wire-encoded, so the log carries the byte length.
    expect(logs).toEqual([
      ['ENS lookup: %s %s -> %d byte answer', 'foo.eth.', wire.types.A, aRec.length]
    ]);
  });

  it('logs the miss line when the ENS resolver returns nothing', async () => {
    const logs: any[][] = [];
    const node = makeNode(logs);
    const plugin = makeReadyPlugin(node);
    (plugin as any).ethereum.resolveDnsFromEns = async () => null;

    const res = await node.ns.middle!('eth.', question(wire.types.A, 'foo.eth'));
    expect(res.answer.length).toBe(0);
    expect(res.authority.some((rr: any) => rr.type === wire.types.NSEC)).toBe(true);
    expect(logs).toEqual([
      ['ENS lookup: %s %s -> miss, returning NODATA', 'foo.eth.', wire.types.A]
    ]);
  });

  it('logs the relay line when an off-chain negative becomes the final answer', async () => {
    const logs: any[][] = [];
    const node = makeNode(logs);
    const nxdomain = nxdomainMessage();
    nxdomain.authority.push(soaRecord('hns.'));

    setupDualPlugin(node, { offchain: nxdomain });

    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(res.code).toBe(wire.codes.NXDOMAIN);

    // The marker intercept also logs; only the relay line must be exact.
    const relay = logs.find(
      (a) => a[0] === 'Relaying off-chain negative for %s (rcode %d)'
    );
    expect(relay).toEqual([
      'Relaying off-chain negative for %s (rcode %d)',
      'foo.hns.',
      wire.codes.NXDOMAIN
    ]);
  });
});

describe('handover plugin activation retry', () => {
  it('does not throw on a failing Ethereum client and retries in the background', async () => {
    vi.useFakeTimers();

    const node = makeNode();
    const plugin = init(node as any);

    // Simulate helios rejecting state proofs ("distance to target block
    // exceeds maximum proof window"): init() fails, but activation must not
    // propagate the error to hsd's openPlugins (that crash-loops the node).
    let fail = true;
    (plugin as any).ethereum.init = async () => {
      if (fail) {
        throw new Error('distance to target block exceeds maximum proof window');
      }
    };

    await expect(plugin.activate()).resolves.toBeUndefined();
    expect(plugin.ready).toBe(false);

    // The retry runner (60s interval) recovers once the client works again.
    fail = false;
    await vi.advanceTimersByTimeAsync(60 * 1000);
    expect(plugin.ready).toBe(true);
    expect(plugin.activationAbort).toBe(null);

    plugin.close();
    vi.useRealTimers();
  });

  it('deduplicates concurrent activate() calls', async () => {
    vi.useFakeTimers();

    const node = makeNode();
    const plugin = init(node as any);
    let calls = 0;
    (plugin as any).ethereum.init = async () => {
      calls++;
      throw new Error('out of sync');
    };

    const p1 = plugin.activate();
    const p2 = plugin.activate();

    await expect(p1).resolves.toBeUndefined();
    await expect(p2).resolves.toBeUndefined();
    // Second call returned immediately because a retry runner was running.
    await vi.advanceTimersByTimeAsync(60 * 1000);
    expect(calls).toBe(2);
    expect(plugin.ready).toBe(false);

    plugin.close();
    vi.useRealTimers();
  });
});

describe('handover middleware: resolver.<name> probe', () => {
  // Fire a probe for the given target name as the middleware would receive
  // it: the probe is just an ordinary name — 'resolver' label prefixed to
  // the target — under the target's own TLD.
  async function probe(node: FakeNode, target = 'foo.hns.', type = wire.types.TXT): Promise<any> {
    return node.ns.middle!(
      `${target.slice(0, -1).split('.').pop()}.`,
      question(type, `resolver.${target.slice(0, -1)}.`)
    );
  }

  // Single-string TXT payload the probe answers carry.
  function probeTXT(res: any): string {
    expect(res.aa).toBe(true);
    expect(res.answer.length).toBe(1);
    const rr = res.answer[0];
    expect(rr.type).toBe(wire.types.TXT);
    return rr.data.txt.map((s: any) => String(s)).join('');
  }

  it('reports ens for a direct .eth name without consulting the root zone', async () => {
    const node = makeNode();

    const plugin = makeReadyPlugin(node, {
      resolveHNS: vi.fn(async () => new wire.Message())
    });
    (plugin as any).ethereum.resolveDnsFromEns = vi.fn(async () => null);

    const res = await probe(node, 'foo.eth.');

    expect(probeTXT(res)).toBe('resolver=ens');
    expect(plugin.resolveHNS).not.toHaveBeenCalled();
    expect(plugin.ethereum.resolveDnsFromEns).not.toHaveBeenCalled();
  });

  it('reports ens for an on-chain name under a dual-mode TLD', async () => {
    const node = makeNode();
    const aRec = aRecordBytes('name.hns.');

    const plugin = setupDualPlugin(node, {
      eth: (_name, type) => type === wire.types.A ? aRec : null
    });
    (plugin as any).resolveHNS = vi.fn((plugin as any).resolveHNS);

    const res = await probe(node, 'name.hns.');

    expect(probeTXT(res)).toBe('resolver=ens');
    // Decision is the isMintedOnChain A/CNAME probe through the referral
    // marker, exactly like the routing below.
    expect(plugin.resolveHNS).toHaveBeenCalledTimes(1);
    // sendProbe hands the target to the root lookup as a normal name,
    // matching how the rest of the middleware passes names around.
    expect((plugin.resolveHNS as any).mock.calls[0][1]).toBe('name.hns.');
    expect((plugin.resolveHNS as any).mock.calls[0][2]).toBe(wire.types.NS);
  });

  it('reports hns for an off-chain name under a dual-mode TLD', async () => {
    const node = makeNode();

    const plugin = setupDualPlugin(node, {
      eth: () => null
    });

    const res = await probe(node, 'name.hns.');

    expect(probeTXT(res)).toBe('resolver=hns');
    // The probe must not go near the off-chain resolver: determinism is the
    // point, the marker + mint probe alone decide.
    expect(plugin.offchain.lookups.length).toBe(0);
  });

  it('reports hns for a marker-free delegation (minted TLD or ICANN mirror)', async () => {
    const node = makeNode();

    const plugin = makeReadyPlugin(node, {
      resolveHNS: async () => plainReferral()
    });
    (plugin as any).ethereum.resolveDnsFromEns = vi.fn(async () => null);
    (plugin as any).ethereum.resolveDnsFromAbstractEns = vi.fn(async () => null);

    const res = await probe(node, 'name.com.');

    expect(probeTXT(res)).toBe('resolver=hns');
    expect(plugin.ethereum.resolveDnsFromEns).not.toHaveBeenCalled();
  });

  it('reports dns when the Handshake root zone has no delegation', async () => {
    const node = makeNode();

    const plugin = makeReadyPlugin(node, {
      resolveHNS: async () => nxdomainMessage()
    });

    const res = await probe(node, 'nope.notreal.');

    expect(probeTXT(res)).toBe('resolver=dns');
  });

  it('answers non-TXT probes with a NODATA negative', async () => {
    const node = makeNode();

    const plugin = makeReadyPlugin(node, {
      resolveHNS: vi.fn(async () => new wire.Message())
    });
    (plugin as any).ethereum.resolveDnsFromEns = vi.fn(async () => null);

    const res = await probe(node, 'foo.eth.', wire.types.A);

    expect(res.aa).toBe(true);
    expect(res.answer.length).toBe(0);
    expect(plugin.ethereum.resolveDnsFromEns).not.toHaveBeenCalled();
  });

  it('does not treat the bare "resolver." name (or non-probe names) as a probe', async () => {
    const node = makeNode();

    const plugin = makeReadyPlugin(node, {
      resolveHNS: vi.fn(async () => new wire.Message())
    });

    // No reserved TLD exists: a single-label "resolver." falls through to
    // the normal root-zone path instead of probe interception.
    for (const name of ['resolver.', 'resolverfoo.hns.', 'x.resolverfoo.hns.']) {
      const req = { question: [new wire.Question(name, wire.types.TXT)] };
      await node.ns.middle!('resolver.', req);
    }

    expect(plugin.resolveHNS).toHaveBeenCalled();
  });

  it('answers SERVFAIL when Ethereum is unhealthy during the mint probe', async () => {
    const node = makeNode();

    const plugin: any = setupDualPlugin(node, {
      offchain: null,
      eth: () => {
        throw new EthereumUnhealthyError('helios down', new Error('helios down'));
      }
    });

    const res = await probe(node, 'name.hns.');

    // Non-cacheable: recursive resolvers must re-probe once the RPC recovers.
    expect(res.code).toBe(wire.codes.SERVFAIL);
  });
});

describe('handover middleware: TLSA records', () => {
  // DANE service query: a '_443._tcp.' label prefix on a hostname under the
  // hns TLD (svc.hns). The leading '_<port>._tcp.' labels are ordinary qname
  // labels — nothing in this middleware special-cases them, so the referral,
  // off-chain and on-chain branches must handle a TLSA question exactly like
  // any other type.
  const TLSA_NAME = '_443._tcp.svc.hns.';

  it('relays an off-chain TLSA answer untouched without consulting eth', async () => {
    const node = makeNode();
    const answer = new wire.Message();
    answer.code = wire.codes.NOERROR;
    answer.answer.push(tlsaRecord());

    let ethCalls = 0;
    const plugin = setupDualPlugin(node, {
      offchain: answer,
      eth: () => { ethCalls++; return null; }
    });

    const res = await node.ns.middle!('hns.', question(wire.types.TLSA, TLSA_NAME));

    // A dual-mode TLD resolves off-chain first; the TLSA RRset comes back
    // exactly as the recursor produced it, eth never consulted.
    expect(res.code).toBe(wire.codes.NOERROR);
    expect(res.answer.map((rr: any) => rr.type)).toEqual([wire.types.TLSA]);
    expect(res.answer[0].data.usage).toBe(3);
    expect(res.answer[0].name).toBe('_443._tcp.svc.hns.');
    expect(ethCalls).toBe(0);
  });

  it('injects an on-chain TLSA answer after the off-chain NXDOMAIN', async () => {
    const node = makeNode();
    const nxdomain = nxdomainMessage();
    const tlsa = tlsaRecordBytes(TLSA_NAME);

    const plugin = setupDualPlugin(node, {
      offchain: nxdomain,
      eth: (_name, type) => type === wire.types.TLSA ? tlsa : null
    });

    const res = await node.ns.middle!('hns.', question(wire.types.TLSA, TLSA_NAME));

    // The HIP-5 (EIP-1185) marker path resolves the name on-chain; sendData
    // places the TLSA record in the authoritative answer section.
    expect(res.aa).toBe(true);
    expect(res.answer.map((rr: any) => rr.type)).toEqual([wire.types.TLSA]);
    expect(res.answer[0].data.certificate.toString('hex')).toBe('0123456789abcdef');
  });

  it('answers a direct .eth TLSA query authoritatively', async () => {
    const node = makeNode();
    const plugin = makeReadyPlugin(node);
    const tlsa = tlsaRecordBytes('_443._tcp.svc.eth.');

    (plugin as any).ethereum.resolveDnsFromEns = async () => tlsa;

    const res = await node.ns.middle!(
      'eth.',
      question(wire.types.TLSA, '_443._tcp.svc.eth.')
    );

    // The whole .eth zone is served from the ENS resolver; a TLSA qtype is
    // an authoritative answer, not a referral.
    expect(res.aa).toBe(true);
    expect(res.answer.map((rr: any) => rr.type)).toEqual([wire.types.TLSA]);
  });
});
