import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import bns from 'bns';
import OffchainResolver from '../src/offchain.ts';
import {
  fakeSign,
  GLUE_ADDR,
  LABEL_NS,
  nxdomainMessage,
  question,
  signedDualReferral
} from './helpers.ts';

const { wire, util } = bns;

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

// The mirror's root-side resolver hook: fronts the stub opening with the
// root KSK and answers everything else with the dual-mode referral.
// `failKSK` is read at call time so a retry test can flip it mid-flight.
type MirrorFixture = { failKSK?: boolean };

function mirrorResolver(fixture: MirrorFixture = {}) {
  return async (name: string, type: number) => {
    if (util.equal(name, '.') && type === wire.types.DNSKEY) {
      if (fixture.failKSK === true) {
        throw new Error('no KSK yet');
      }
      return rootKeys();
    }

    if (name.startsWith('missing.')) {
      return nxdomainMessage();
    }

    return signedDualReferral();
  };
}

// A resolver whose root bring-up never settles, at a fast timeout so the
// deadline tests stay deterministic.
function stalledResolver(): OffchainResolver {
  return new OffchainResolver({
    resolve: async () => new Promise(() => {}),
    sign: () => {}
  }, undefined, 10);
}

let stub: OffchainResolver;
let signs: number;

beforeAll(async () => {
  signs = 0;

  stub = new OffchainResolver({
    resolve: mirrorResolver(),
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
    const res = await stub.resolve(question(wire.types.A, 'pinner.hns.'), {});

    const nsRRs = res.authority.filter((rr: any) => rr.type === wire.types.NS);
    expect(nsRRs.map((rr: any) => rr.data.ns)).toEqual([LABEL_NS]);
    expect(res.authority.some((rr: any) => {
      return rr.type === wire.types.RRSIG && rr.data.typeCovered === wire.types.NS;
    })).toBe(true);
    // DS relayed untouched with its... original rrset intact.
    expect(res.authority.some((rr: any) => rr.type === wire.types.DS)).toBe(true);
    expect(res.additional.map((rr: any) => rr.data.address)).toEqual([GLUE_ADDR]);
    // One re-signing round for the pruned delegation.
    expect(signs).toBe(before + 1);
  });

  it('relays an untouched referral byte-for-byte when no marker is present', async () => {
    const before = signs;
    // A non-dual referral: marker white-list, nothing pruned.
    const np = signedDualReferral();
    np.authority = np.authority.filter(
      (rr: any) => rr.type !== wire.types.NS || !rr.data.ns.endsWith('._eth.')
    );

    const local = new OffchainResolver({
      resolve: async () => np,
      sign: (rrs, type) => fakeSign(rrs, type)
    });

    const res = await local.resolve(question(wire.types.A, 'pinner.hns.'), {});
    expect(res.authority).toEqual(np.authority);
    expect(signs).toBe(before);

    await local.close();
  });

  it('anchors the trust to the root KSK and mirrors root DNSKEY', async () => {
    const res = await stub.resolve(question(wire.types.DNSKEY, '.'), {});
    expect(res.answer.length).toBe(1);
    expect(res.answer[0].data.flags & wire.keyFlags.KSK).toBeTruthy();
  });

  it('does not wedge later off-chain lookups when the bring-up stalls open', async () => {
    // The root DNSKEY relay used to pin the anchor never settles, so the
    // bring-up would hang forever. Before the timeout guard that hung ==
    // every lookup joined the same pending `open()` memo and stalled.
    // A short timeout keeps the test fast and deterministic.
    const local = stalledResolver();

    await expect(
      local.lookup('pinner.hns.', wire.types.A)
    ).rejects.toThrow(/failed to open within timeout/);

    await local.close();
  });

  it('close() does not block on a never-settling bring-up', async () => {
    const local = stalledResolver();

    // open() never settles: the hooks.resolve promise is permanent.
    const openP = local.open().catch(() => {});

    const start = Date.now();
    await local.close();
    const elapsed = Date.now() - start;

    await openP;
    expect(elapsed).toBeLessThan(2000);
  });

  it('releases bring-up resources on timeout so a retry binds fresh', async () => {
    let gate: ((v?: unknown) => void) | null = null;
    let stall = true;

    const local = new OffchainResolver({
      resolve: async (name: string, type: number) => {
        if (util.equal(name, '.') && type === wire.types.DNSKEY) {
          if (stall) {
            return new Promise((resolve) => { gate = resolve; });
          }
          return rootKeys();
        }
        return signedDualReferral();
      },
      sign: fakeSign
    }, undefined, 20);

    // First bring-up stalls on the root DNSKEY relay and hits the deadline;
    // the finally-guard must tear down the stub bound along the way.
    await expect(local.open()).rejects.toThrow(/failed to open within timeout/);

    gate!();
    stall = false;

    // Second attempt starts from a clean slate and fully opens.
    await expect(local.open()).resolves.toBeUndefined();
    expect(local.stubAddress).not.toBeNull();

    await expect(local.close()).resolves.toBeUndefined();
  });

  it('normalizes a malformed request to SERVFAIL instead of throwing', async () => {
    const local = new OffchainResolver({
      resolve: async () => {
        throw new Error('resolver should not be reached');
      },
      sign: () => {}
    });

    // Missing question array entirely.
    const missing = await local.resolve({}, {});
    expect(missing.code).toBe(wire.codes.SERVFAIL);

    // Present but empty question array.
    const empty = await local.resolve({ question: [] }, {});
    expect(empty.code).toBe(wire.codes.SERVFAIL);

    await local.close();
  });

  it('retries a failed bring-up from scratch instead of replaying a rejected memo', async () => {
    const fixture: MirrorFixture = { failKSK: true };

    const local = new OffchainResolver({
      resolve: mirrorResolver(fixture),
      sign: (rrset, type) => fakeSign(rrset, type)
    });

    await expect(local.open()).rejects.toThrow('no KSK yet');

    // The memo must be cleared: a later lookup brings the stub up anew.
    fixture.failKSK = false;
    await expect(local.open()).resolves.toBeUndefined();
    expect(local.stubAddress).not.toBeNull();

    await local.close();
  });

  it('converts unknown names through the same mirror', async () => {
    const res = await stub.resolve(question(wire.types.A, 'missing.hns.'), {});
    expect(res.code).toBe(wire.codes.NXDOMAIN);
  });
});
