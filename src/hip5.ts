import bns from 'bns';

const { util, wire } = bns;
const { types } = wire;

// Zones an NS delegation target can point into to trigger a HIP-5
// referral: plain 'eth' (main ENS registry) and '_eth' (alternate,
// forked ENS whose contract is the Ethereum address in the NS record).
// Plain object instead of an enum keeps the TS buildless
// (erasableSyntaxOnly).
export type Hip5Zone = 'eth' | '_eth';

export const HIP5_ZONES = {
  ETH: 'eth',
  ABSTRACT: '_eth'
} as const;

// Root-zone qnames for the HIP-5 lookup TLDs ('eth.', '_eth.').
export const HIP5_ZONE_DOT = HIP5_ZONES.ETH + '.';
export const HIP5_ABSTRACT_DOT = HIP5_ZONES.ABSTRACT + '.';

function isHip5Zone(value: string): value is Hip5Zone {
  return value === HIP5_ZONES.ETH || value === HIP5_ZONES.ABSTRACT;
}

// Last DNS label of an NS delegation target (bns strips the trailing
// dot). Returns the HIP-5 zone the target delegates into, null otherwise.
// DNS names are case-insensitive: the label is lowercased so a delegation
// like `Foo._Eth.` is classified identically to the lowercase form. Both
// the middleware and the off-chain mirror must agree here, otherwise a
// marker is treated as a real nameserver by one path and stripped by the
// other.
export function hip5Target(ns: string): Hip5Zone | null {
  const name = String(ns).toLowerCase();
  const ending = util.label(name, util.split(name), -1);
  return isHip5Zone(ending) ? ending : null;
}

// An NS record whose target is a HIP-5 marker delegation rather than a
// resolvable nameserver.
export function isHip5NS(rr: any): boolean {
  return rr.type === types.NS && hip5Target(rr.data.ns) !== null;
}

// Prune HIP-5 marker NS records from an authority section, drop the now-stale
// NS RRSIG that covered the unpruned RRset, and (when a signer is given and
// real NS records remain) re-sign what's left. Used by both stripHip5() in
// the middleware and the off-chain mirror so the two pruned referrals can't
// diverge — a referral that keeps the old NS signature over a reduced record
// set is rejected as bogus by a validating resolver (SERVFAIL).
//
// The signer must append its RRSIG to the array it is given (hsd's
// signRRSet / the mirror's hooks.sign both do). This is the canonical
// statement of the signer contract; other call sites reference it.
export function pruneHip5Authority(
  authority: any[],
  sign?: (nsSet: any[], type: number) => void
): any[] {
  const markers = authority.filter(isHip5NS);

  if (markers.length === 0) {
    return authority;
  }

  const nsOwner = markers[0].name;

  // Marker-free NS records of the delegation, re-signed as a group.
  const nsSet: any[] = [];

  for (const rr of authority) {
    if (rr.type === types.NS && !isHip5NS(rr) && util.equal(rr.name, nsOwner)) {
      nsSet.push(rr);
    }
  }

  if (nsSet.length > 0 && sign) {
    sign(nsSet, types.NS);
  }

  const out: any[] = [];

  for (const rr of authority) {
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

  return out;
}
