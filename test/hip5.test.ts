import { describe, it, expect } from 'vitest';
import bns from 'bns';
import * as hip5 from '../src/hip5.ts';
import { LABEL_NS, makeRRSIG, soaRecord, STALE_ROOT_SIG } from './helpers.ts';

const { wire } = bns;

function nsRR(target: string): any {
  return wire.Record.fromJSON({
    class: 'IN',
    name: 'hns.',
    ttl: 3600,
    type: 'NS',
    data: { ns: target }
  });
}

function rrsigNS(): any {
  return makeRRSIG([nsRR(LABEL_NS)], wire.types.NS, STALE_ROOT_SIG);
}

describe('hip5 marker classification', () => {
  it('classifies HIP-5 markers case-insensitively across zones', () => {
    // DNS names are case-insensitive; a mixed-case delegation must be a
    // marker for both the middleware and the off-chain mirror.
    for (const target of [
      '0xabc._eth.',
      '0xabc.eth.',
      '0xabc._ETH.',
      '0xabc._Eth.',
      '0xabc.ETH.',
      '0xabc.Eth.'
    ]) {
      expect(hip5.hip5Target(target)).not.toBeNull();
      expect(hip5.isHip5NS(nsRR(target))).toBe(true);
    }
  });

  it('treats real nameserver targets as non-markers', () => {
    for (const target of [LABEL_NS, 'a.b.c.', 'ns.hns.']) {
      expect(hip5.hip5Target(target)).toBeNull();
      expect(hip5.isHip5NS(nsRR(target))).toBe(false);
    }
  });
});

describe('hip5 authority pruning', () => {
  it('prunes markers, drops the stale NS RRSIG, and re-signs the rest', () => {
    const signed: any[][] = [];
    const referral = [
      nsRR(LABEL_NS),
      nsRR('0xabc._eth.'),
      rrsigNS()
    ];

    const out = hip5.pruneHip5Authority(referral, (nsSet, type) => {
      expect(type).toBe(wire.types.NS);
      // Snapshot before appending: the signer mutates the array itself.
      signed.push(nsSet.slice());
      nsSet.push(rrsigNS());
    });

    expect(out.map((rr: any) => rr.type)).toEqual([
      wire.types.NS, wire.types.RRSIG
    ]);
    expect(out[0].data.ns).toBe(LABEL_NS);
    // The signer saw exactly the marker-free NS group.
    expect(signed.length).toBe(1);
    expect(signed[0].length).toBe(1);

    // Input section untouched.
    expect(referral.length).toBe(3);
    expect(hip5.isHip5NS(referral[1])).toBe(true);
  });

  it('relays a marker-free authority untouched without a fresh signature', () => {
    const referral = [soaRecord('hns.'), nsRR(LABEL_NS), rrsigNS()];

    const out = hip5.pruneHip5Authority(referral, () => {
      throw new Error('signer must not run');
    });

    expect(out).toEqual(referral);
  });

  it('prunes silently when no signer is provided', () => {
    const referral = [
      nsRR(LABEL_NS),
      nsRR('0xabc._eth.'),
      rrsigNS()
    ];

    const out = hip5.pruneHip5Authority(referral);

    expect(out.length).toBe(1);
    expect(out[0].data.ns).toBe(LABEL_NS);
    expect(referral.length).toBe(3);
  });

  it('prunes every marker in the section, not just the first owner', () => {
    const otherMarker = wire.Record.fromJSON({
      class: 'IN', name: 'pure.', ttl: 0, type: 'NS', data: { ns: '0xabc._eth.' }
    });
    const otherReal = wire.Record.fromJSON({
      class: 'IN', name: 'pure.', ttl: 0, type: 'NS', data: { ns: 'ns2.pure.io.' }
    });

    const out = hip5.pruneHip5Authority(
      [nsRR(LABEL_NS), nsRR('0xabc._eth.'), otherMarker, otherReal]
    );

    // All HIP-5 NS targets go; real NS records under any owner stay.
    expect(out).toEqual([nsRR(LABEL_NS), otherReal]);
  });
});
