import { describe, it, expect } from 'vitest';
import bns from 'bns';
import Ethereum, {
  DEFAULT_RPC_URL,
  RPC_TIMEOUT_MS,
  UNHEALTHY_COOLDOWN_MS,
  EthereumUnhealthyError
} from '../src/ethereum.ts';
import { init } from '../src/handover.ts';
import {
  DNS_NAME,
  MockClient,
  aRecordBytes,
  makeEth,
  makeEthWithResolver,
  question,
  setARecord
} from './helpers.ts';

const { wire } = bns;

// A clock the test controls, so the unhealthy cooldown can be stepped over
// without fake timers leaking into other suites.
class ManualClock {
  time = 1_000_000;

  now = (): number => this.time;
}

// RPC client stub that always fails, counting every attempt so the
// fail-fast path can be proven by the ABSENCE of additional calls.
class FailingClient {
  calls = 0;

  readContract = async (): Promise<any> => {
    this.calls++;
    throw new Error('connect ECONNREFUSED 127.0.0.1:8545');
  };
}

// Same stub, but recovers for every call after the first.
class ScriptedClient {
  calls = 0;

  readContract = async (): Promise<any> => {
    this.calls++;

    if (this.calls <= 1) {
      throw new Error('connect ECONNREFUSED 127.0.0.1:8545');
    }

    return '0x1111111111111111111111111111111111111111';
  };
}

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
    config: { str: () => DEFAULT_RPC_URL },
    logger: { context: () => ({ debug() {}, warning() {}, info() {} }) },
    chain: {}
  };
}

describe('Ethereum health gate', () => {
  it('surfaces the first RPC failure and fails fast on the next call', async () => {
    const clock = new ManualClock();
    const client = new FailingClient();
    const eth = new Ethereum({ client: client as any, now: clock.now });

    expect(eth.isHealthy()).toBe(true);

    // First call runs the RPC and surfaces the underlying failure.
    await expect(
      eth.resolveDnsFromEns('foo.eth', wire.types.A)
    ).rejects.toThrow('ECONNREFUSED');
    expect(client.calls).toBe(1);
    expect(eth.isHealthy()).toBe(false);

    // Second call never touches the RPC: fail fast, zero attempts.
    await expect(
      eth.resolveDnsFromEns('foo.eth', wire.types.A)
    ).rejects.toBeInstanceOf(EthereumUnhealthyError);
    expect(client.calls).toBe(1);
  });

  it('retries the RPC after the cooldown and marks healthy again on success', async () => {
    const clock = new ManualClock();
    const client = new ScriptedClient();
    const eth = new Ethereum({ client: client as any, now: clock.now });

    await expect(
      eth.resolveDnsFromEns('foo.eth.', wire.types.A)
    ).rejects.toThrow('ECONNREFUSED');
    expect(eth.isHealthy()).toBe(false);

    // Still inside the cooldown: fail fast.
    clock.time += UNHEALTHY_COOLDOWN_MS - 1;
    await expect(
      eth.resolveDnsFromEns('foo.eth.', wire.types.A)
    ).rejects.toBeInstanceOf(EthereumUnhealthyError);
    expect(client.calls).toBe(1);

    // Cooldown elapsed: the next query gets a real RPC attempt (resolver
    // read + dnsRecord read), and answers normally again.
    clock.time += 1;
    const data = await eth.resolveDnsFromEns('foo.eth.', wire.types.A);
    expect(client.calls).toBe(3);
    expect(eth.isHealthy()).toBe(true);
    expect(data).toBeInstanceOf(Buffer);
  });
});

describe('Ethereum healthy path', () => {
  it('stays healthy on success and passes results through', async () => {
    const [eth, mock] = makeEthWithResolver();
    setARecord(eth, mock);

    expect(eth.isHealthy()).toBe(true);

    const data = await eth.resolveDnsFromEns(DNS_NAME, wire.types.A);
    expect(data).toBeInstanceOf(Buffer);
    expect(eth.isHealthy()).toBe(true);

    // A miss is not a failure either: the RPC answered (unregistered node
    // reads back as the zero address), so health holds.
    const [emptyEth, emptyMock] = makeEthWithResolver();
    const miss = await emptyEth.resolveDnsFromEns(DNS_NAME, wire.types.A);
    expect(miss).toBeNull();
    expect(emptyMock.calls.length).toBeGreaterThan(0);
    expect(emptyEth.isHealthy()).toBe(true);
  });

  it('health is per-instance regardless of injected clients', async () => {
    const clock = new ManualClock();
    const failing = new FailingClient();
    const eth = new Ethereum({ client: failing as any, now: clock.now });
    const other = makeEth();

    await expect(
      eth.resolveDnsFromEns('foo.eth', wire.types.A)
    ).rejects.toThrow('ECONNREFUSED');

    expect(eth.isHealthy()).toBe(false);
    expect(other.isHealthy()).toBe(true);
  });
});

describe('Ethereum client transport configuration', () => {
  it('applies the 2s timeout and disables transport retries', () => {
    const eth = new Ethereum({ rpcUrl: DEFAULT_RPC_URL });
    const transport = (eth.client as any).transport;

    expect(transport.timeout).toBe(RPC_TIMEOUT_MS);
    expect(transport.retryCount).toBe(0);
    expect(transport.url).toBe(DEFAULT_RPC_URL);
  });

  it('never touches the transport when an injected client is used', () => {
    const eth = new Ethereum({ client: new MockClient() as any });
    const transport = (eth.client as any).transport;

    expect(transport).toBeFalsy();
  });
});

describe('handover middleware: SERVFAIL for unhealthy RPC', () => {
  it('answers SERVFAIL, not an SOA negative, when the Ethereum RPC is down', async () => {
    const clock = new ManualClock();
    const client = new FailingClient();
    const eth = new Ethereum({ client: client as any, now: clock.now });

    // Trip the health gate with one doomed call (mirrors what a query just
    // before a helios restart would have done).
    await expect(
      eth.resolveDnsFromEns('foo.eth', wire.types.A)
    ).rejects.toThrow('ECONNREFUSED');

    const node = makeNode();
    const plugin = init(node as any);
    plugin.ready = true;
    plugin.ethereum = eth;

    const res = await node.ns.middle!('eth.', question(wire.types.A, 'foo.eth'));

    expect(res.code).toBe(wire.codes.SERVFAIL);
    // No NSEC/SOA authority records: a dead RPC must not look like a
    // provable, cacheable negative.
    expect(res.authority.length).toBe(0);

    // Fail fast on the follow-up query too: still SERVFAIL, and the RPC
    // was never asked again.
    const res2 = await node.ns.middle!('eth.', question(wire.types.A, 'other.eth'));
    expect(res2.code).toBe(wire.codes.SERVFAIL);
    expect(client.calls).toBe(1);
  });

  it('keeps the SOA fallback for contract misses (non-unhealthy errors)', async () => {
    const node = makeNode();
    const plugin = init(node as any);
    plugin.ready = true;

    // A mock with no canned responses: the registry call returns the zero
    // address, i.e. a genuine on-chain miss, not unavailability.
    const eth = makeEth();
    plugin.ethereum = eth;

    const res = await node.ns.middle!('eth.', question(wire.types.A, 'bar.eth'));

    // sendSOA shape: authoritative NSEC-covered negative, not SERVFAIL.
    expect(res.code).toBe(wire.codes.NOERROR);
    expect(res.aa).toBe(true);
    expect(res.authority.some((rr: any) => rr.type === wire.types.NSEC)).toBe(true);
    expect(res.code).not.toBe(wire.codes.SERVFAIL);

    // And an A answer still flows through unchanged.
    const hitEth = makeEth();
    hitEth.resolveDnsFromEns = async () => aRecordBytes('baz.eth.');
    plugin.ethereum = hitEth;

    const hit = await node.ns.middle!('eth.', question(wire.types.A, 'baz.eth'));
    expect(hit.answer.length).toBe(1);
    expect(hit.answer[0].type).toBe(wire.types.A);
  });

  it('answers SERVFAIL when the dual-mode marker path hits a dead RPC', async () => {
    const clock = new ManualClock();
    const client = new FailingClient();
    const eth = new Ethereum({ client: client as any, now: clock.now });

    await expect(
      eth.resolveDnsFromEns('foo.hns', wire.types.A)
    ).rejects.toThrow('ECONNREFUSED');

    const node = makeNode();
    const plugin = init(node as any);
    plugin.ready = true;
    plugin.ethereum = eth;

    // Dual-mode referral with a HIP-5 marker (see helpers.dualReferral).
    const MARKER_NS = '0x667ab1d9f98817ffb28cd61b911f921181c669b3._eth.';
    const dual = new wire.Message();
    dual.code = wire.codes.NOERROR;
    dual.authority.push(
      wire.Record.fromJSON({
        class: 'IN', name: 'hns.', ttl: 0, type: 'NS', data: { ns: MARKER_NS }
      })
    );
    plugin.resolveHNS = async () =>
      dual;
    plugin.offchain = null;

    const res = await node.ns.middle!('hns.', question(wire.types.A, 'foo.hns'));
    expect(res.code).toBe(wire.codes.SERVFAIL);
    expect(res.authority.length).toBe(0);
  });
});
