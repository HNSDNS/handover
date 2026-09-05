import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import bns from 'bns';
import OffchainResolver from '../src/offchain.ts';

const { wire, util, dnssec } = bns;

const LABEL_NS = 'ns1.namebase.io.';
const MARKER_NS_RR = {
  class: 'IN', name: 'hns.', ttl: 3600, type: 'NS',
  data: { ns: '0x667ab1d9f98817ffb28cd61b911f921181c669b3._eth.' }
};

// Signature-like RRSIG records the root carries; stripped/re-signed by the
// mirror in the same way as the real thing.
function fakeSign(rrset: any[], type: number): void {
  const rr = wire.Record.fromJSON({
    class: 'IN', name: rrset[0].name, ttl: rrset[0].ttl, type: 'RRSIG',
    data: {
      typeCovered: wire.typesByVal[type],
      labels: 2,
      origTTL: rrset[0].ttl,
      expiration: 99999,
      inception: 0,
      serial: 0,
      keyTag: 1,
      algorithm: 13,
      signerName: '.',
      signature: 'c2lnbmF0dXJl'
    }
  });
  rrset.push(rr);
}

function dualReferral(): any {
  const msg = new wire.Message();
  msg.code = wire.codes.NOERROR;
  msg.authority.push(
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl: 3600, type: 'NS', data: { ns: LABEL_NS } }),
    wire.Record.fromJSON(MARKER_NS_RR),
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl: 3600, type: 'DS', data: { keyTag: 6070, algorithm: 13, digestType: 2, digest: '00' } }),
    // Old NS signature from the root; covers the unpruned RRset.
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl: 3600, type: 'RRSIG', data: { typeCovered: 'NS', labels: 1, origTTL: 21600, expiration: 9, inception: 0, serial: 0, keyTag: 1, algorithm: 13, signerName: '.', signature: 'b2xk' } })
  );
  msg.additional.push(
    wire.Record.fromJSON({ class: 'IN', name: LABEL_NS, ttl: 3600, type: 'A', data: { address: '1.2.3.4' } })
  );
  return msg;
}

// Minimal root-zone fronts the mirror would open with.
function rootKeys(): any {
  const msg = new wire.Message();
  msg.code = wire.codes.NOERROR;
  const ksk = wire.Record.fromJSON({
    class: 'IN', name: '.', ttl: 10800, type: 'DNSKEY',
    data: { flags: 257, protocol: 3, algorithm: 13, publicKey: 'A2c' }
  });
  msg.answer.push(ksk);
  return msg;
}

const question = (name: string, type: number) => ({
  question: [new wire.Question(name, type)]
});

let stub: OffchainResolver;
let signs: number;

beforeAll(async () => {
  signs = 0;

  stub = new OffchainResolver({
    resolve: async (name: string, type: number) => {
      if (util.equal(name, '.') && type === wire.types.DNSKEY) {
        return rootKeys();
      }

      if (name.startsWith('missing.')) {
        const msg = new wire.Message();
        msg.code = wire.codes.NXDOMAIN;
        return msg;
      }

      return dualReferral();
    },
    sign: (rrset, type) => {
      signs++;
      fakeSign(rrset, type);
    }
  });

  await stub.open();
});

afterAll(async () => {
  await stub.close();
});

describe('offchain mirror zone', () => {
  it('relays the referral marker-free, re-signs the pruned only', async () => {
    const before = signs;
    const res = await stub.resolve(question('pinner.hns.', wire.types.A), {});

    const nsRRs = res.authority.filter((rr: any) => rr.type === wire.types.NS);
    expect(nsRRs.map((rr: any) => rr.data.ns)).toEqual([LABEL_NS]);
    expect(res.authority.some((rr: any) => {
      return rr.type === wire.types.RRSIG && rr.data.typeCovered === wire.types.NS;
    })).toBe(true);
    // DS relayed untouched with its... original rrset intact.
    expect(res.authority.some((rr: any) => rr.type === wire.types.DS)).toBe(true);
    expect(res.additional.map((rr: any) => rr.data.address)).toEqual(['1.2.3.4']);
    // One re-signing round for the pruned delegation.
    expect(signs).toBe(before + 1);
  });

  it('relays an untouched referral byte-for-byte when no marker is present', async () => {
    const before = signs;
    // A non-dual referral: marker white-list, nothing pruned.
    const np = dualReferral();
    np.authority = np.authority.filter(
      (rr: any) => rr.type !== wire.types.NS || !rr.data.ns.endsWith('._eth.')
    );

    const local = new OffchainResolver({
      resolve: async () => np,
      sign: (rrs, type) => fakeSign(rrs, type)
    });

    const res = await local.resolve(question('pinner.hns.', wire.types.A), {});
    expect(res.authority).toEqual(np.authority);
    expect(signs).toBe(before);

    await local.close();
  });

  it('anchors the trust to the root KSK and mirrors root DNSKEY', async () => {
    const res = await stub.resolve(question('.', wire.types.DNSKEY), {});
    expect(res.answer.length).toBe(1);
    expect(res.answer[0].data.flags & wire.keyFlags.KSK).toBeTruthy();
  });

  it('retries a failed bring-up from scratch instead of replaying a rejected memo', async () => {
    let failKSK = true;

    const local = new OffchainResolver({
      resolve: async (name: string, type: number) => {
        if (util.equal(name, '.') && type === wire.types.DNSKEY && failKSK) {
          throw new Error('no KSK yet');
        }

        if (util.equal(name, '.') && type === wire.types.DNSKEY) {
          return rootKeys();
        }

        return dualReferral();
      },
      sign: (rrset, type) => fakeSign(rrset, type)
    });

    await expect(local.open()).rejects.toThrow('no KSK yet');

    // The memo must be cleared: a later lookup brings the stub up anew.
    failKSK = false;
    await expect(local.open()).resolves.toBeUndefined();
    expect(local.stubAddress).not.toBeNull();

    await local.close();
  });

  it('converts unknown names through the same mirror', async () => {
    const res = await stub.resolve(question('missing.hns.', wire.types.A), {});
    expect(res.code).toBe(wire.codes.NXDOMAIN);
  });
});
