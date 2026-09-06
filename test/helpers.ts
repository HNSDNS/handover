import bns from 'bns';
import { BufferReader } from 'bufio';
import Ethereum, {
  DEFAULT_RPC_URL,
  ENS_ADDRESS,
  ZERO_ADDRESS
} from '../src/ethereum.ts';

const { wire } = bns;
const { Message } = wire;

export const RESOLVER_ADDRESS = '0x30200E0cb040F38E474E53EF437c95A1bE723b2B';
export const ABSTRACT_ADDRESS = '0x36fc69f0983E536D1787cC83f481581f22CCA2A1';
export const DNS_NAME = 'fuckingfucker.eth.';
export const DNS_NODE = 'fuckingfucker.eth';
export const A_RECORD_IP = '184.73.82.1';

/**
 * Minimal stand-in for a viem PublicClient. Ethereum routes every read
 * through client.readContract, so intercepting here exercises the whole
 * resolution path against canned responses.
 */
export class MockClient {
  calls: unknown[] = [];
  responses = new Map<string, any>();

  // arrow-function field: viem's getContract() detaches the read fn from
  // the client, so `this` must be captured lexically, not via the receiver.
  readContract = async (args: any): Promise<any> => {
    this.calls.push(args);

    const contract = args.address.toLowerCase();
    const [first, second, third] = args.args.map((a: any) => String(a).toLowerCase());

    if (args.functionName === 'resolver') {
      return this.responses.get(`resolver:${contract}:${first}`) ?? ZERO_ADDRESS;
    }

    if (args.functionName === 'dnsRecord') {
      const key = `dnsRecord:${contract}:${first}:${second}:${third}`;
      return this.responses.get(key) ?? '0x';
    }

    throw new Error(`unexpected call: ${args.functionName}`);
  }

  callHandler: (args: any) => string = () => '0x';

  // Low-level eth_call used by the resolveEns* convenience methods
  call = async (args: any): Promise<string> => {
    this.calls.push({ kind: 'call', ...args });
    return this.callHandler(args);
  }
}

export function makeEth(mock?: MockClient): Ethereum {
  return new Ethereum({ client: mock ?? new MockClient() });
}

// Production defaults, reused so test fixtures can't drift from the real
// constants.
export { DEFAULT_RPC_URL, ZERO_ADDRESS };

// The canonical glue address for dual-mode referral fixtures and the A
// answers middleware tests assert against.
export const GLUE_ADDR = '1.2.3.4';

export function aRecord(name: string, address: string = GLUE_ADDR, ttl = 60): any {
  return wire.Record.fromJSON({
    class: 'IN', name, ttl, type: 'A', data: { address }
  });
}

// Wire-encoded form, as the middleware's eth side actually returns it.
export function aRecordBytes(name: string, address: string = GLUE_ADDR, ttl = 60): Buffer {
  return aRecord(name, address, ttl).encode();
}

// Wire-encoded TLSA (DANE) record, as the middleware's eth side returns it
// for EIP-1185 datasets. A DANE service query is a '_<port>._tcp.' label
// prefix on a hostname — e.g. the TLSA for the host svc.hns (TLD hns) is
// '_443._tcp.svc.hns.' Fixtures use the test-only 'svc' host under the hns
// TLD so no real domain is referenced.
export function tlsaRecord(name = '_443._tcp.svc.hns.', ttl = 3600): any {
  return wire.Record.fromJSON({
    class: 'IN', name, ttl, type: 'TLSA',
    data: { usage: 3, selector: 1, matchingType: 1, certificate: '0123456789abcdef' }
  });
}

export function tlsaRecordBytes(name = '_443._tcp.svc.hns.', ttl = 3600): Buffer {
  return tlsaRecord(name, ttl).encode();
}

// Convenience for tests that need both the instance and its mock client,
// without pre-creating the mock themselves.
export function makeEthWithMock(): [Ethereum, MockClient] {
  const mock = new MockClient();
  return [makeEth(mock), mock];
}

// The most common test setup: a fresh mock wired so DNS_NODE resolves to
// RESOLVER_ADDRESS. Used throughout the resolveEnsAddress/resolveEnsText
// suites, which all exercise the exact-node resolver path.
export function makeEthWithResolver(): [Ethereum, MockClient] {
  const [eth, mock] = makeEthWithMock();
  setResolver(eth, mock, DNS_NODE, RESOLVER_ADDRESS);
  return [eth, mock];
}

// Full A-record setup for DNS_NAME against `registry`/`resolver`: encodes the
// record and installs both the resolver() mapping and the dnsRecord response.
export function setARecord(
  eth: Ethereum,
  mock: MockClient,
  registry: string = ENS_ADDRESS,
  resolver: string = RESOLVER_ADDRESS
): Buffer {
  const record = encodeARecord(DNS_NAME, A_RECORD_IP);

  setResolverOn(eth, mock, registry, DNS_NODE, resolver);
  setRecord(eth, mock, resolver, DNS_NODE, DNS_NAME, wire.types.A, record);

  return record;
}

export function encodeRecord(json: object): Buffer {
  return wire.Record.fromJSON(json).encode();
}

function encodeARecord(name: string, address: string): Buffer {
  return encodeRecord({
    name,
    ttl: 60,
    class: 'IN',
    type: 'A',
    data: { address }
  });
}

export function decodeRecords(data: Buffer): any[] {
  const records = [];
  const br = new BufferReader(data);

  while (br.left() > 0) {
    records.push(wire.Record.read(br));
  }

  return records;
}

export function setResolverOn(
  eth: Ethereum,
  mock: MockClient,
  registry: string,
  name: string,
  resolverAddr: string
): void {
  mock.responses.set(
    `resolver:${registry.toLowerCase()}:${eth.namehash(name.toLowerCase())}`,
    resolverAddr
  );
}

export function setResolver(
  eth: Ethereum,
  mock: MockClient,
  name: string,
  contract: string
): void {
  setResolverOn(eth, mock, ENS_ADDRESS, name, contract);
}

export function setRecord(
  eth: Ethereum,
  mock: MockClient,
  contract: string,
  node: string,
  dnsName: string,
  type: number,
  value: Buffer
): void {
  mock.responses.set(
    `dnsRecord:${contract.toLowerCase()}:` +
    `${eth.namehash(node.toLowerCase())}:` +
    `${eth.hashDnsName(dnsName)}:${type}`,
    '0x' + value.toString('hex')
  );
}

// Shared dual-mode referral fixture for the HIP-5 middleware and the
// off-chain mirror tests. Constants live here so marker syntax and the
// delegation shape can't drift between the two suites.
export const LABEL_NS = 'ns1.namebase.io.';
export const MARKER_NS = '0x667ab1d9f98817ffb28cd61b911f921181c669b3._eth.';

export interface FakeRRSIGOptions {
  labels?: number;
  origTTL?: number;
  expiration?: number;
  signature?: string;
}

// Field values of the stale root NS signature a dual-mode referral carries
// before pruning: it covers marker + real NS, so post-prune it is bogus and
// every suite must model the same stale shape.
export const STALE_ROOT_SIG: FakeRRSIGOptions = {
  labels: 1,
  origTTL: 21600,
  expiration: 9,
  signature: 'b2xk'
};

// Canonical RRSIG fixture for a given rrset: the fake signer record every
// suite builds. Only intentional per-suite differences are overridable —
// field shape and the append contract change in one place, not three.
export function makeRRSIG(rrset: any[], type: number, opts: FakeRRSIGOptions = {}): any {
  return wire.Record.fromJSON({
    class: 'IN', name: rrset[0].name, ttl: rrset[0].ttl, type: 'RRSIG',
    data: {
      typeCovered: wire.typesByVal[type],
      labels: opts.labels ?? 2,
      origTTL: opts.origTTL ?? rrset[0].ttl,
      expiration: opts.expiration ?? 99999,
      inception: 0,
      serial: 0,
      keyTag: 1,
      algorithm: 13,
      signerName: '.',
      signature: opts.signature ?? 'c2lnbmF0dXJl'
    }
  });
}

// Signer hook matching hsd's signRRSet contract: appends the RRSIG to the
// array it is given.
export function fakeSign(rrset: any[], type: number, opts: FakeRRSIGOptions = {}): void {
  rrset.push(makeRRSIG(rrset, type, opts));
}

export interface DualReferralOptions {
  // TTL applied to the authority records.
  ttl?: number;
  // Include the root NS RRSIG covering the unpruned referral.
  dnssec?: boolean;
  // A-glue address for LABEL_NS, or null to omit glue.
  glueAddr?: string | null;
}

// Root-zone referral for a dual-mode TLD: a real delegation plus the HIP-5
// marker sharing the same NS RRset (see shakeshift.com/name/hns).
export function dualReferral(opts: DualReferralOptions = {}): InstanceType<typeof Message> {
  const { ttl = 3600, dnssec = false, glueAddr = null } = opts;
  const msg = new Message();
  msg.code = wire.codes.NOERROR;
  msg.authority.push(
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl, type: 'NS', data: { ns: LABEL_NS } }),
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl, type: 'NS', data: { ns: MARKER_NS } }),
    wire.Record.fromJSON({ class: 'IN', name: 'hns.', ttl, type: 'DS', data: { keyTag: 6070, algorithm: 13, digestType: 2, digest: '00' } })
  );

  if (dnssec) {
    // Old NS signature from the root; covers the unpruned RRset.
    msg.authority.push(makeRRSIG(msg.authority, wire.types.NS, STALE_ROOT_SIG));
  }

  if (glueAddr) {
    msg.additional.push(
      wire.Record.fromJSON({ class: 'IN', name: LABEL_NS, ttl, type: 'A', data: { address: glueAddr } })
    );
  }

  return msg;
}

// The root's negative proof matching the dual-mode delegation shape.
export function soaRecord(name: string, ttl = 0): any {
  return wire.Record.fromJSON({
    class: 'IN', name, ttl, type: 'SOA',
    data: { ns: LABEL_NS, mbox: '.', serial: 1, refresh: 0, retry: 0, expire: 0, minttl: 0 }
  });
}

// The canonical signed dual-mode referral both suites use: DNSSEC referral
// with A-glue on `LABEL_NS` at the standard TTL.
export function signedDualReferral(
  opts: DualReferralOptions = {}
): InstanceType<typeof Message> {
  return dualReferral({ ttl: 3600, dnssec: true, glueAddr: '1.2.3.4', ...opts });
}

// Canonical question wrapper for middleware / stub request objects.
export function question(type: number, name = 'foo.hns') {
  return { question: [new wire.Question(name, type)] };
}

// Standard NXDOMAIN negative response (optionally proof-bearing).
export function nxdomainMessage(authority?: any[]): InstanceType<typeof Message> {
  const msg = new Message();
  msg.code = wire.codes.NXDOMAIN;
  if (authority) {
    msg.authority.push(...authority);
  }
  return msg;
}
