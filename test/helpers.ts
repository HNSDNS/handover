import bns from 'bns';
import { BufferReader } from 'bufio';
import Ethereum, { ENS_ADDRESS } from '../src/ethereum.ts';

const { wire } = bns;

export const RESOLVER_ADDRESS = '0x30200E0cb040F38E474E53EF437c95A1bE723b2B';
export const ABSTRACT_ADDRESS = '0x36fc69f0983E536D1787cC83f481581f22CCA2A1';
export const DNS_NAME = 'fuckingfucker.eth.';
export const DNS_NODE = 'fuckingfucker.eth';
export const A_RECORD_IP = '184.73.82.1';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

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
