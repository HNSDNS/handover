import { describe, it, expect, vi } from 'vitest';
import bns from 'bns';
import { init } from '../src/handover.ts';

const { wire } = bns;

interface FakeNode {
  ns: { middle?: (tld: string, req: any) => Promise<any> };
  config: { str: () => string };
  logger: { context: () => { debug: (...a: any[]) => void; warning: (...a: any[]) => void } };
  chain: object;
}

function makeNode(): FakeNode {
  return {
    ns: {},
    config: { str: () => 'http://127.0.0.1:8545' },
    logger: { context: () => ({ debug() {}, warning() {}, info() {} }) },
    chain: {}
  };
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
