import { describe, it, expect, vi } from 'vitest';
import bns from 'bns';
import { init } from '../src/handover.ts';
import { encodeRecord } from './helpers.ts';

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

function makeNode(): FakeNode {
  return {
    ns: {
      signRRSet() {},
      toSOA: () => new wire.Record({ name: '.', type: wire.types.SOA, data: new wire.SOARecord() })
    },
    config: { str: () => 'http://127.0.0.1:8545' },
    logger: { context: () => ({ debug() {}, warning() {}, info() {} }) },
    chain: {}
  };
}

const LABEL_NS = 'ns1.namebase.io.';
const MARKER_NS = '0x667ab1d9f98817ffb28cd61b911f921181c669b3._eth.';

// Root-zone referral for a dual-mode TLD: a real delegation plus the HIP-5
// marker sharing the same NS RRset (see shakeshift.com/name/hns).
function makeDualReferral(): typeof wire.Message.prototype {
  const msg = new wire.Message();
  msg.code = wire.codes.NOERROR;
  msg.authority.push(
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl: 0, type: 'NS', data: { ns: LABEL_NS } }),
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl: 0, type: 'NS', data: { ns: MARKER_NS } }),
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl: 0, type: 'DS', data: { keyTag: 6070, algorithm: 13, digestType: 2, digest: '00' } })
  );
  return msg;
}

function markerRecords(msg: typeof wire.Message.prototype): any[] {
  return msg.authority.filter((rr: any) => {
    return rr.type === wire.types.NS && rr.data.ns === MARKER_NS;
  });
}

// Same surface as OffchainResolver, without sockets or recursion: prime()
// captures the priming context, lookup() answers from the canned message.
function makeOffchainStub(answer: any): any {
  return {
    primed: null,
    prime(tld: string, realNS: any[], referral: any) {
      this.primed = { tld, realNS, referral };
    },
    open: async () => {},
    lookup: async () => answer
  };
}

function setupDualPlugin(node: FakeNode, opts: {
  offchain?: any | null;
  eth?: (name: string, type: number) => Buffer | null;
}): any {
  const plugin = init(node as any);
  plugin.ready = true;
  (plugin as any).resolveHNS = async () => makeDualReferral();
  (plugin as any).offchain = opts.offchain === null
    ? null
    : makeOffchainStub(opts.offchain);
  (plugin as any).ethereum.resolveDnsFromEns = opts.eth ?? (async () => null);
  (plugin as any).ethereum.resolveDnsFromAbstractEns = opts.eth ?? (async () => null);
  return plugin;
}

describe('handover middleware: DS->NS rewrite (HIP-5)', () => {
  it('answers a single-label DS query with the original DS response when the synthetic NS lookup has no authority', async () => {
    const node = makeNode();
    const plugin = init(node as any);
    plugin.ready = true;

    // The original DS query resolves normally; the synthetic NS lookup for
    // the same name returns no records (empty authority).
    (plugin as any).resolveHNS = async (_req: any, _name: string, type: number) => {
      const msg = new wire.Message();
      if (type === wire.types.DS) {
        msg.answer.push(new wire.Record({ type: wire.types.DS, name: 'foo' }));
        msg.code = wire.codes.NOERROR;
      }
      return msg;
    };

    const req = { question: [new wire.Question('foo', wire.types.DS)] };
    const res = await node.ns.middle!('foo.', req);

    // Must be the original DS response (has an answer), not the empty
    // NS-typed message the synthetic rewrite produced. Without the fix the
    // empty-authority NS response would be returned (answer.length === 0).
    expect(res.answer.length).toBe(1);
  });
});

describe('handover middleware: dual-mode HIP-5 TLDs', () => {
  const question = (type: number, name = 'foo.hns') => ({
    question: [new wire.Question(name, type)]
  });

  it('relays off-chain answers untouched without consulting eth', async () => {
    const node = makeNode();
    const answer = new wire.Message();
    answer.code = wire.codes.NOERROR;
    answer.answer.push(wire.Record.fromJSON({ class: 'IN',
      name: 'foo.hns.', ttl: 60, type: 'A', data: { address: '1.2.3.4' }
    }));

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
    const nxdomain = new wire.Message();
    nxdomain.code = wire.codes.NXDOMAIN;

    const aRecord = encodeRecord({
      class: 'IN', name: 'foo.hns.', ttl: 60, type: 'A', data: { address: '1.2.3.4' }
    });
    const plugin = setupDualPlugin(node, {
      offchain: nxdomain,
      eth: (_name, type) => type === wire.types.A ? aRecord : null
    });

    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(res.answer.length).toBe(1);
    expect(res.answer[0].type).toBe(wire.types.A);
    expect(markerRecords(res).length).toBe(0);
  });

  it('relays the negative proof when a name exists neither on- nor off-chain', async () => {
    const node = makeNode();
    const nxdomain = new wire.Message();
    nxdomain.code = wire.codes.NXDOMAIN;
    nxdomain.authority.push(wire.Record.fromJSON({ class: 'IN',
      name: 'hns.', ttl: 0, type: 'SOA',
      data: { ns: 'ns1.namebase.io.', mbox: '.', serial: 1, refresh: 0,
        retry: 0, expire: 0, minttl: 0 }
    }));

    const plugin = setupDualPlugin(node, { offchain: nxdomain });

    const res = await node.ns.middle!('hns.', question(wire.types.A));
    expect(res.code).toBe(wire.codes.NXDOMAIN);
    expect(res.authority.some((rr: any) => rr.type === wire.types.SOA)).toBe(true);
    expect(markerRecords(res).length).toBe(0);
  });

  it('asks the off-chain resolver by qname without any priming context', async () => {
    const node = makeNode();
    const answer = new wire.Message();
    answer.code = wire.codes.NOERROR;

    const plugin = setupDualPlugin(node, { offchain: answer });
    const res = await node.ns.middle!('hns.', question(wire.types.A));

    expect(res.code).toBe(wire.codes.NOERROR);

    // Referral sections are no longer handed to the resolver by hand:
    // the stub derives everything from its own HNS root mirror.
    const { primed } = (plugin as any).offchain;
    expect(primed).toBeNull();
  });

  it('returns null from resolveOffchain when the off-chain resolver explodes', async () => {
    const node = makeNode();
    const plugin = init(node as any);
    plugin.ready = true;
    (plugin as any).offchain = {
      lookup: async () => { throw new Error('socket exploded'); }
    };

    const out = await (plugin as any).resolveOffchain('foo.hns', wire.types.A);
    expect(out).toBeNull();
  });

  it('keeps the HIP-5 marker visible in NS delegations for on-chain names', async () => {
    const node = makeNode();
    const nxdomain = new wire.Message();
    nxdomain.code = wire.codes.NXDOMAIN;

    const aRecord = encodeRecord({
      class: 'IN', name: 'foo.hns.', ttl: 60, type: 'A', data: { address: '1.2.3.4' }
    });
    // No NS data on the eth side; A probe proves the name is on-chain.
    const plugin = setupDualPlugin(node, {
      offchain: nxdomain,
      eth: (_name, type) => type === wire.types.A ? aRecord : null
    });

    const res = await node.ns.middle!('hns.', question(wire.types.NS));
    expect(res.answer.length).toBe(0);
    expect(res.authority.map((rr: any) => rr.type)).toContain(wire.types.NS);
    expect(markerRecords(res).length).toBe(1);
    expect(res.aa).toBe(false);
  });

  it('never leaks the HIP-5 marker for off-chain NS requests', async () => {
    const node = makeNode();
    const nxdomain = new wire.Message();
    nxdomain.code = wire.codes.NXDOMAIN;

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

    const plugin = init(node as any);
    plugin.ready = true;
    (plugin as any).resolveHNS = async () => ethOnly;
    (plugin as any).offchain = makeOffchainStub(null);
    (plugin as any).ethereum.resolveDnsFromEns = async () => null;

    // Pure-eth miss: hidden referral, signed negative response.
    const res = await node.ns.middle!('pure.', question(wire.types.A, 'foo.pure'));
    expect(res.answer.length).toBe(0);
    expect(markerRecords(res).length).toBe(0);
    expect(res.authority.some((rr: any) => rr.type === wire.types.NSEC)).toBe(true);

    // Pure-eth hit: authoritative injected answer.
    const aRecord = encodeRecord({
      class: 'IN', name: 'foo.pure.', ttl: 60, type: 'A', data: { address: '5.6.7.8' }
    });
    (plugin as any).ethereum.resolveDnsFromEns = async () => aRecord;
    (plugin as any).ethereum.resolveDnsFromAbstractEns = async () => aRecord;
    const hit = await node.ns.middle!('pure.', question(wire.types.A, 'foo.pure'));
    expect(hit.answer.length).toBe(1);
    expect(hit.answer[0].type).toBe(wire.types.A);
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
