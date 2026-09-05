import {
  concat,
  createPublicClient,
  decodeAbiParameters,
  getAddress as checksumAddress,
  getContract,
  http,
  keccak256,
  padHex,
  toHex,
  type Address,
  type Hash,
  type Hex
} from 'viem';
import { mainnet } from 'viem/chains';
import { normalize } from 'viem/ens';
import LRU from 'blru';
import bns from 'bns';
import { HIP5_ZONES, hip5Target } from './hip5.ts';

const { wire, util, encoding } = bns;

export const ENS_ADDRESS: Address = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';
export const ZERO_ADDRESS: Address = '0x0000000000000000000000000000000000000000';
export const DEFAULT_RPC_URL = 'http://127.0.0.1:8545';
const CACHE_TTL = 30 * 60 * 1000;

// ENS root TLD sentinel: its node's official resolver must never be used to
// answer for arbitrary *.eth names (it has no wildcard resolver). Derived
// from the shared HIP-5 definition so the sentinel can't drift from the zone
// the resolver plugin routes on.
const ETH_TLD = HIP5_ZONES.ETH;

const CACHE_TAGS = {
  DNS: 0,
  RESOLVER: 1
};

// ENS resolver selectors (mirror ethers' Resolver).
const ADDR_SELECTOR: Hex = '0x3b3b57de';  // addr(bytes32)
const TEXT_SELECTOR: Hex = '0x59d1d43c';  // text(bytes32,string)
const HASH_ZERO: Hex = ('0x' + '00'.repeat(32)) as Hex;

// Hot-path regexes (name/address hashing runs once per label per query),
// hoisted to module scope so they are not re-created on every call.
const RE_ASCII = /^[\x00-\x7f]*$/;
const RE_SIMPLE_LABEL = /^[a-z0-9-]*$/i;
const RE_LABEL_PARTITION = /^((.*)\.)?([^.]+)$/;
const RE_HEX_ADDRESS = /^(0x)?([0-9a-fA-F]{40})$/;
const RE_MIXED_CASE = /([A-F].*[a-f])|([a-f].*[A-F])/;
const RE_ICAP = /^XE[0-9]{2}[0-9A-Za-z]{30,31}$/;
const RE_HEX_STRING = /^0x[0-9a-fA-F]*$/;

// UTF-8 encode a label for hashing. Deliberately NOT viem's toBytes/hex parse:
// a label that looks like hex ('0xdead') must be hashed as its UTF-8 bytes,
// exactly as ethers' toUtf8Bytes did — toBytes would hex-decode it and hash
// the wrong node.
function toUtf8(label: string): Uint8Array {
  return new TextEncoder().encode(label);
}

// IBAN letter->value map (ethers' ibanLookup), used for ICAP addresses.
const IBAN_DIGIT: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < 10; i++) m[String(i)] = i;
  for (let i = 0; i < 26; i++) m[String.fromCharCode(65 + i)] = 10 + i;
  return m;
})();

// Parity with ethers@5.0.11 @ethersproject/strings nameprep for the input
// space this plugin actually sees (DNS wire labels are ASCII): the fast path
// passes lowercase [a-z0-9-] labels verbatim (which covers punycode `xn--`),
// and the full IDNA path handles hyphen rules and the 63-char limit. Labels
// that ethers hashes (punycode, underscore) must NOT throw.
function nameprepLabel(label: string): string {
  if (RE_SIMPLE_LABEL.test(label) && label.length <= 59) {
    return label.toLowerCase();
  }

  // Non-ASCII labels: ENSIP-15 normalize does NFKC + case-folding like
  // ethers' nameprep, but it throws or maps differently on some codepoints
  // (e.g. `İ`, `ß`, `ς`, `Σ`) that ethers accepted. These are unreachable via
  // the plugin — DNS wire labels are ASCII/punycode — so this only affects
  // direct calls with exotic Unicode.
  if (!RE_ASCII.test(label)) {
    return normalize(label);
  }

  // ASCII but not the fast path (underscores, or 60-63 chars): apply the
  // IDNA rules ethers applies after case-folding.
  const lower = label.toLowerCase();

  if (
    lower.startsWith('-') ||
    (lower[2] === '-' && lower[3] === '-') ||
    lower.endsWith('-')
  ) {
    throw new Error('invalid hyphen');
  }

  if (lower.length > 63) {
    throw new Error('too long');
  }

  return lower;
}

// ethers' IBAN (ICAP direct) checksum.
function ibanChecksum(address: string): string {
  const a = address.toUpperCase();
  const reordered = a.substring(4) + a.substring(0, 2) + '00';
  let expanded = reordered
    .split('')
    .map((c) => String(IBAN_DIGIT[c]))
    .join('');

  // 15 digits is the safe integer boundary ethers uses
  while (expanded.length >= 15) {
    const block = expanded.substring(0, 15);
    expanded = String(parseInt(block, 10) % 97) + expanded.substring(block.length);
  }

  let checksum = String(98 - (parseInt(expanded, 10) % 97));
  while (checksum.length < 2) checksum = '0' + checksum;

  return checksum;
}

// Parses an address the way ethers@5.0.10 getAddress did: 40-hex (missing
// 0x allowed) returns the checksummed form (throwing only on mixed-case bad
// checksum, accepting all-lower/all-upper), and ICAP/IBAN direct-mode
// addresses are converted. Anything else throws.
function toEthersAddress(name: string): Address {
  const hexMatch = RE_HEX_ADDRESS.exec(name);

  if (hexMatch) {
    const withPrefix = hexMatch[1] ? hexMatch[0] : '0x' + hexMatch[0];
    const checksummed = checksumAddress(withPrefix);

    if (RE_MIXED_CASE.test(withPrefix) && checksummed !== withPrefix) {
      throw new Error(`bad address checksum: ${name}`);
    }

    return checksummed;
  }

  if (RE_ICAP.test(name)) {
    if (name.substring(2, 4) !== ibanChecksum(name)) {
      throw new Error(`bad icap checksum: ${name}`);
    }

    let value = 0n;
    for (const ch of name.substring(4)) {
      value = value * 36n + BigInt(IBAN_DIGIT[ch.toUpperCase()]);
    }

    let hex = value.toString(16);
    while (hex.length < 40) hex = '0' + hex;

    return checksumAddress('0x' + hex);
  }

  throw new Error(`invalid address: ${name}`);
}

// Parses the return of an addr(bytes32) eth_call the way ethers'
// Resolver.getAddress did (providers 5.0.23 formatter.callAddress):
// non-32-byte words and the zero address yield null; a bad EIP-55
// checksum throws.
function parseAddressWord(result: Hex): Address | null {
  if (!result) {
    return null;
  }

  // isHexString(value, 32): must be exactly one 32-byte word (the empty
  // result '0x' fails this length check too). A malformed length maps to
  // null (ethers' RPC layer threw a SERVER_ERROR on an odd-length hex
  // round-trip; real nodes return even-length hex, so this only differs
  // for a hostile/malformed RPC response).
  if (result.length !== 66) {
    return null;
  }

  const addr = ('0x' + result.slice(-40)) as Address;

  if (
    result.toLowerCase() === HASH_ZERO ||
    addr.toLowerCase() === ZERO_ADDRESS
  ) {
    return null;
  }

  // ethers hexlifies the whole eth_call result (lowercasing it) before
  // getAddress, so a case-bearing word never trips a checksum error here.
  return toEthersAddress(addr.toLowerCase());
}

// ABI-encodes a text() key as [pointer@0x40, length, key padded to a word]:
// the nodehash consumes the first slot, so the string pointer targets offset
// 64. Matches ethers' Resolver.getText key encoding.
function encodeTextKey(key: string): Hex {
  const raw = toUtf8(key);
  const rem = raw.length % 32;
  const pad = rem === 0 ? 0 : 32 - rem;
  const keyPart =
    pad === 0 ? toHex(raw) : toHex(concat([raw, new Uint8Array(pad)]));

  return concat([
    padHex('0x40', { size: 32 }),
    padHex(toHex(BigInt(raw.length)), { size: 32 }),
    keyPart
  ]) as Hex;
}

const CONTRACT_ABI = [
  {
    stateMutability: 'view',
    type: 'function',
    inputs: [{ name: 'node', type: 'bytes32' }],
    outputs: [{ name: '', type: 'address' }],
    name: 'resolver'
  }
];

const RESOLVER_ABI = [
  {
    stateMutability: 'view',
    type: 'function',
    inputs: [{ name: 'nodehash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'address' }],
    name: 'addr'
  },
  {
    stateMutability: 'view',
    type: 'function',
    inputs: [{ name: 'nodehash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'string' }],
    name: 'name'
  },
  {
    stateMutability: 'view',
    type: 'function',
    inputs: [
      { name: 'nodehash', type: 'bytes32' },
      { name: 'key', type: 'string' }
    ],
    outputs: [{ name: '', type: 'string' }],
    name: 'text'
  },
  {
    stateMutability: 'view',
    type: 'function',
    inputs: [{ name: 'nodehash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bytes' }],
    name: 'contenthash'
  },
  {
    stateMutability: 'view',
    type: 'function',
    inputs: [
      { name: 'node', type: 'bytes32' },
      { name: 'name', type: 'bytes32' },
      { name: 'resource', type: 'uint16' }
    ],
    outputs: [{ name: '', type: 'bytes' }],
    name: 'dnsRecord'
  },
  {
    stateMutability: 'view',
    type: 'function',
    inputs: [
      { name: 'node', type: 'bytes32' },
      { name: 'name', type: 'bytes32' }
    ],
    outputs: [{ name: '', type: 'bool' }],
    name: 'hasDNSRecords'
  }
] as const;

export interface EthereumOptions {
  /** URL of an Ethereum JSON-RPC endpoint, ideally a local Helios light client. */
  rpcUrl?: string;
  /** View call client (for testing). */
  client?: any;
}

export default class Ethereum {
  rpcUrl: string;
  keccak256 = keccak256;
  client: any;
  ensRegistry: any;
  ensResolver: any = null;
  cache: EthereumCache;

  constructor(options: EthereumOptions = {}) {
    this.rpcUrl = options.rpcUrl || DEFAULT_RPC_URL;

    this.client = options.client || createPublicClient({
      chain: mainnet,
      transport: http(this.rpcUrl)
    });

    this.ensRegistry = getContract({
      address: ENS_ADDRESS,
      abi: CONTRACT_ABI,
      client: this.client
    });
    this.cache = new EthereumCache(3000);
  }

  async init() {
    this.ensResolver = await this.getEnsResolver(ETH_TLD);
  }

  async getEnsResolver(name: string): Promise<any> {
    return this.getResolver(name, ENS_ADDRESS);
  }

  async getResolverFromRegistry(name: string, registry: any): Promise<any> {
    const resolverAddr = await this.#readResolverAddress(
      registry,
      this.namehash(util.trimFQDN(name))
    );

    if (resolverAddr === null) {
      return null;
    }

    return getContract({
      address: resolverAddr as Address,
      abi: RESOLVER_ABI,
      client: this.client
    });
  }

  async getResolver(name: string, registryAddress: string): Promise<any> {
    const cache = this.cache.getResolver(name, registryAddress);
    if (cache) {
      return cache;
    }

    const registry = this.getAbstractEnsRegistry(registryAddress);
    const resolver = await this.getResolverFromRegistry(name, registry);

    this.cache.setResolver(name, registryAddress, resolver);
    return resolver;
  }

  getAbstractEnsRegistry(address: string): any {
    return getContract({
      address: address as Address,
      abi: CONTRACT_ABI,
      client: this.client
    });
  }

  // ENS registry resolver lookup for a node: the resolver address, or null
  // when the node is unregistered (the registry returns the zero address).
  // Shared by the cached getResolver path and the resolveEns* convenience
  // APIs so registry/zero-address handling stays in one place.
  async #readResolverAddress(registry: any, node: Hash): Promise<string | null> {
    const address = (await registry.read.resolver([node])) as string;
    return address.toLowerCase() === ZERO_ADDRESS ? null : address;
  }

  // Registry lookup shared by the resolveEns* convenience APIs: the resolver
  // address for a node, or null when the node is unregistered (the registry
  // returns the zero address).
  async #nodeResolverAddress(node: Hash): Promise<string | null> {
    return this.#readResolverAddress(this.ensRegistry, node);
  }

  // Mirrors ethers@5.0.x BaseProvider behavior (the version the original
  // plugin shipped with): a SINGLE exact-node resolver lookup, no parent walk
  // and no EIP-2544 wildcard handling. resolveEnsAddress/resolveEnsText are
  // convenience APIs only — the hsd middleware DNS path runs entirely through
  // the cached getResolver/getResolverFromRegistry and is unaffected.
  //
  // Like ethers' _getResolver, a failing registry eth_call propagates (throws)
  // rather than being swallowed.

  async resolveEnsAddress(name: string): Promise<Address | null> {
    if (typeof name !== 'string') {
      throw new Error('invalid ENS name');
    }

    // A passed-in address is not an ENS name, so resolve it directly:
    // - a valid 40-hex address short-circuits and is returned checksummed;
    // - any other hexstring (too short, or mixed-case with a bad EIP-55
    //   checksum) is NOT an ENS name either — it must not be silently sent
    //   to the registry as if it were a label, so the address error is
    //   re-thrown rather than falling through to an ENS lookup. This matches
    //   ethers' resolveName, which patched exactly this misbehavior after
    //   https://github.com/ethers-io/ethers.js/issues/694.
    try {
      return toEthersAddress(name);
    } catch (e) {
      // ethers re-throws for ANY hexstring (isHexString allows odd length and
      // bare '0x'), so '0x123'/'0x' throw instead of being treated as names.
      if (RE_HEX_STRING.test(name)) {
        throw e;
      }
    }

    const node = this.namehash(name);
    const resolverAddress = await this.#nodeResolverAddress(node);

    if (!resolverAddress) {
      return null;
    }

    // registry/addr call errors propagate (throw), like ethers 5.0.x, which
    // had no try/catch on either call.
    const result = (await this.client.call({
      address: resolverAddress as Address,
      data: concat([ADDR_SELECTOR, node])
    })) as Hex;

    return parseAddressWord(result);
  }

  async resolveEnsText(name: string, key: string): Promise<string | null> {
    if (key == null) {
      // ethers' toUtf8Bytes threw on null/undefined
      throw new Error('invalid text key');
    }
    // non-string primitives (e.g. a number) encode as the empty key, matching
    // ethers' toUtf8Bytes which read `.length` and found none.
    key = typeof key === 'string' ? key : '';

    const node = this.namehash(name);
    const resolverAddress = await this.#nodeResolverAddress(node);

    if (!resolverAddress) {
      return null;
    }

    // like ethers 5.0.x, call errors propagate (throw); only an empty result
    // maps to null.
    const result = (await this.client.call({
      address: resolverAddress as Address,
      data: concat([TEXT_SELECTOR, node, encodeTextKey(key)])
    })) as Hex;

    if (!result || result === '0x') {
      return null;
    }

    const text = decodeAbiParameters([{ type: 'string' }], result)[0];

    // an on-chain empty string reads back as null, matching ethers' getText.
    // (A hostile resolver returning invalid UTF-8 would yield U+FFFD via the
    // lenient decoder here where ethers' toUtf8String threw; not reachable via
    // the middleware.)
    return text === '' ? null : text;
  }

  async resolveDnsFromEns(
    name: string,
    type: number,
    node?: string
  ): Promise<Buffer | null> {
    // The canonical ENS registry is an ordinary registry address; route
    // through the shared caching resolver path.
    return this.resolveDnsFromRegistry(name, type, ENS_ADDRESS, node);
  }

  async getRRSet(
    name: string,
    type: number,
    node: string,
    resolver: any
  ): Promise<Buffer | null> {
    if (!resolver) {
      return null;
    }

    let record: any = this.cache.getRecord(
      name,
      type,
      resolver.address
    );

    if (!record) {
      record = await resolver.read.dnsRecord(
        [
          this.namehash(util.trimFQDN(node)),
          this.hashDnsName(name),
          BigInt(type)
        ]
      );

      this.cache.setRecord(name, type, resolver.address, record);
    }

    if (!record || record === '0x') {
      return null;
    }

    return Buffer.from(record.slice(2), 'hex');
  }

  // Fetch an RR set for `name`/`type`; when answering an NS query, follow it
  // with the matching DS records so DNSSEC proofs can be built (NS + DS are
  // expected together in the response).
  async #getRRSetWithDS(
    name: string,
    type: number,
    node: string,
    resolver: any
  ): Promise<Buffer | null> {
    const rrSet = await this.getRRSet(name, type, node, resolver);

    if (!rrSet) {
      return null;
    }

    if (type === wire.types.NS) {
      const dsSet = await this.getRRSet(name, wire.types.DS, node, resolver);

      if (dsSet) {
        return Buffer.concat([rrSet, dsSet]);
      }
    }

    return rrSet;
  }

  async resolveDnsWithResolver(
    name: string,
    type: number,
    node: string,
    resolver: any
  ): Promise<Buffer | null> {
    const rrSet = await this.#getRRSetWithDS(name, type, node, resolver);

    if (rrSet) {
      return rrSet;
    }

    // NS/CNAME fallback. Per the RFC, if NS/CNAME exists no other record
    // types should be present, but EIP-1185 doesn't give us the full zone;
    // for correctly set-up zones this isn't an issue.

    // NS lookups use the node name, not the qname. Ideally we'd keep adding
    // labels to the left, from node to qname, until we find a delegation —
    // but that adds too many lookups.
    const sname = util.fqdn(node);
    const nsSet = await this.#getRRSetWithDS(
      sname,
      wire.types.NS,
      node,
      resolver
    );

    if (nsSet) {
      return nsSet;
    }

    // Last resort: a CNAME on the qname.
    return this.getRRSet(name, wire.types.CNAME, node, resolver);
  }

  // A HIP-5 referral to an abstract (forked) ENS registry has the NS target
  // form "<40-byte address>._eth.".
  async resolveDnsFromAbstractEns(
    name: string,
    type: number,
    ns: string,
    node?: string
  ): Promise<Buffer | null> {
    if (!node) {
      node = this.toNode(name);
    }

    // Classify the zone through the shared HIP-5 parser so a mixed-case
    // marker like "<addr>._Eth." resolves the same as the lowercase form
    // (hip5Target lowercases the final label).
    if (hip5Target(ns) !== HIP5_ZONES.ABSTRACT) {
      return null;
    }

    const labels = util.trimFQDN(ns).split('.');
    const addr = labels[0];

    if (addr.length !== 42) {
      return null;
    }

    return this.resolveDnsFromRegistry(name, type, addr, node);
  }

  async resolveDnsFromRegistry(
    name: string,
    type: number,
    registryAddress: string,
    node?: string
  ): Promise<Buffer | null> {
    if (!node) {
      node = this.toNode(name);
    }

    const resolver = await this.getResolver(
      util.trimFQDN(node),
      registryAddress
    );

    return this.resolveDnsWithResolver(name, type, node, resolver);
  }

  // Mirrors ethers@5.0.11 @ethersproject/hash namehash: repeatedly partition
  // off the right-most label, nameprep it, and fold it into the node hash.
  // This is what lets punycode (`xn--`) and underscore labels hash normally
  // instead of being rejected by ENSIP-15.
  namehash(name: string): Hash {
    if (typeof name !== 'string') {
      throw new Error('invalid ENS name');
    }

    let result: Hash = HASH_ZERO;

    for (let current = name; current.length > 0;) {
      const partition = RE_LABEL_PARTITION.exec(current);

      if (!partition) {
        // e.g. a trailing dot yields a name that doesn't partition; ethers
        // threw on this too.
        throw new Error(`invalid ENS name: ${name}`);
      }

      const label = nameprepLabel(partition[3]);
      const labelHash = keccak256(toUtf8(label));
      result = keccak256(concat([result, labelHash]));

      current = partition[2] || '';
    }

    return result;
  }

  hashDnsName(name: string): Hash {
    const dnsName = encoding.packName(name);
    return this.keccak256(toHex(dnsName));
  }

  toNode(name: string): string {
    let node = name;
    const labels = util.trimFQDN(name).split('.');

    if (labels.length > 1) {
      node = labels.slice(-2).join('.');
    }

    return node;
  }
}

class EthereumCache {
  cache: any;

  constructor(size: number) {
    this.cache = new LRU(size);
  }

  setRecord(
    name: string,
    type: number,
    resolverAddress: string,
    record?: string
  ): void {
    if (!record) {
      record = '0x';
    }

    this.cache.set(this.toDnsKey(name, type, resolverAddress), {
      time: Date.now(),
      record
    });
  }

  getRecord(
    name: string,
    type: number,
    resolverAddress: string
  ): string | null {
    const item = this.getItem(this.toDnsKey(name, type, resolverAddress));

    return item ? item.record : null;
  }

  setResolver(
    node: string,
    registryAddress: string,
    resolver: any
  ): void {
    if (!resolver) {
      return;
    }

    this.cache.set(this.toResolverKey(node, registryAddress), {
      time: Date.now(),
      resolver
    });
  }

  getResolver(node: string, registryAddress: string): any {
    const item = this.getItem(this.toResolverKey(node, registryAddress));

    return item ? item.resolver : null;
  }

  // Shared time-aware LRU read: a missing or expired entry reads as null.
  // Expired entries stay in the LRU until they are overwritten or evicted.
  getItem(key: string): any | null {
    const item = this.cache.get(key);

    if (!item || Date.now() > item.time + CACHE_TTL) {
      return null;
    }

    return item;
  }

  toDnsKey(name: string, type: number, resolverAddress: string): string {
    return `${CACHE_TAGS.DNS};${name};${type};${resolverAddress}`;
  }

  toResolverKey(node: string, registryAddress: string): string {
    return `${CACHE_TAGS.RESOLVER};${node};${registryAddress}`;
  }
}
