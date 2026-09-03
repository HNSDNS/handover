import { describe, it, expect } from 'vitest';
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
    logger: { context: () => ({ debug() {}, warning() {} }) },
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
