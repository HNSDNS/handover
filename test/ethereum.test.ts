import { describe, it, expect } from 'vitest';
import bns from 'bns';
import { encodeAbiParameters } from 'viem';
import {
  RESOLVER_ADDRESS,
  ABSTRACT_ADDRESS,
  DNS_NAME,
  DNS_NODE,
  A_RECORD_IP,
  makeEth,
  makeEthWithMock,
  makeEthWithResolver,
  encodeRecord,
  decodeRecords,
  setResolver,
  setRecord,
  setARecord
} from './helpers.ts';

const { wire } = bns;

describe('lib/ethereum', () => {
  describe('toNode()', () => {
    it('keeps the last two labels', () => {
      const eth = makeEth();
      expect(eth.toNode('foo.bar.baz.eth.')).toBe('baz.eth');
      expect(eth.toNode('example')).toBe('example');
    });
  });

  describe('namehash()', () => {
    // Hardcoded outputs from ethers utils.namehash (verified against 5.0.x
    // and 5.7.x). viem namehash alone does NOT normalize; these guard that the
    // plugin stays bit-for-bit compatible with the original ethers path.
    it('matches ethers utils.namehash bit-for-bit', () => {
      const eth = makeEth();
      const cases: Array<[string, string]> = [
        ['myname.eth', '0x6cbc8d00d20a89e588f430e62b937a6402557bf0bc2127fb1378457331aa463d'],
        // uppercase is case-folded like ethers did
        ['MyName.eth', '0x6cbc8d00d20a89e588f430e62b937a6402557bf0bc2127fb1378457331aa463d'],
        // fullwidth characters are NFKC-mapped to ASCII
        ['Ｉｓｔａｎｂｕｌ.eth', '0xfa352f51a0128494fbd7f981b40b2494a048bab1f752cbbfbb09dc66a6f047ec'],
        // soft hyphen (prohibited) is removed
        ['café\u00AD.eth', '0xa7369e1df22e06ec6d91162508e400d7af475860638f927e6d1085bb0134a74a'],
        // real, lowercased names are unchanged
        ['fuckingfucker.eth', '0x7b2df66718e3f65df66e686e6a53bb581a13575ab1390522a0650094df29f19c']
      ];

      for (const [input, expected] of cases) {
        expect(eth.namehash(input), input).toBe(expected);
      }
    });

    it('hashes punycode (xn--) and underscore labels like ethers nameprep', () => {
      const eth = makeEth();

      // ethers@5.0.11 values (nameprep passes these through, ENSIP-15 would not)
      expect(eth.namehash('xn--caf-dma.eth')).toBe(
        '0xdd27588bc3afa51ad47246943c881d01914fbfd190c3393ba61c3cc1aa7a1c3f'
      );
      expect(eth.namehash('my_domain.eth')).toBe(
        '0x9744d67177d9310e6b8d29331b6ec57517c11dfcb6a13410a78fd57c11e09883'
      );
    });

    it('hashes hex-shaped labels as UTF-8, not as hex (matches ethers)', () => {
      const eth = makeEth();

      // ethers hashed '0xdead' as UTF-8 bytes; a viem toBytes() would have
      // hex-decoded it, hashing the wrong node (reachable via DNS).
      expect(eth.namehash('0xdead.eth')).toBe(
        '0x427b3fa6e34e5d1a14a70492aece78350a9b5594fc67f3c34271cc978bc759ca'
      );
    });
  });

  describe('hashDnsName()', () => {
    it('hashes the DNS wire encoding of the name', () => {
      const eth = makeEth();
      const hash = eth.hashDnsName(DNS_NAME);

      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
      expect(hash).toBe(eth.hashDnsName(DNS_NAME));
    });
  });

  describe('EIP-1185 resolution from the canonical registry', () => {
    it('resolves an A record', async () => {
      const [eth, mock] = makeEthWithMock();
      setARecord(eth, mock);

      const data = await eth.resolveDnsFromEns(DNS_NAME, 1); // type A
      expect(data).toBeTruthy();

      const records = decodeRecords(data!);
      expect(records).toHaveLength(1);
      expect(records[0].type).toBe(1);
      expect(records[0].data.address).toBe(A_RECORD_IP);

      // exactly two reads: one resolver() and one dnsRecord()
      expect(mock.calls).toHaveLength(2);
    });

    it('serves subsequent lookups from cache', async () => {
      const [eth, mock] = makeEthWithMock();
      setARecord(eth, mock);

      await eth.resolveDnsFromEns(DNS_NAME, 1);
      expect(mock.calls).toHaveLength(2);

      await eth.resolveDnsFromEns(DNS_NAME, 1);

      // every read served from the LRU cache
      expect(mock.calls).toHaveLength(2);
    });

    it('includes DS records in NS responses', async () => {
      const [eth, mock] = makeEthWithMock();
      const ns = encodeRecord({
        name: DNS_NAME,
        ttl: 60,
        class: 'IN',
        type: 'NS',
        data: { ns: 'something._eth.' }
      });
      const ds = encodeRecord({
        name: DNS_NAME,
        ttl: 60,
        class: 'IN',
        type: 'DS',
        data: { keyTag: 1, algorithm: 8, digestType: 2, digest: 'abcd' }
      });

      setResolver(eth, mock, DNS_NODE, RESOLVER_ADDRESS);
      setRecord(eth, mock, RESOLVER_ADDRESS, DNS_NODE, DNS_NAME, wire.types.NS, ns);
      setRecord(eth, mock, RESOLVER_ADDRESS, DNS_NODE, DNS_NAME, wire.types.DS, ds);

      const data = await eth.resolveDnsFromEns(DNS_NAME, wire.types.NS);
      expect(data).toBeTruthy();

      const records = decodeRecords(data!);
      expect(records).toHaveLength(2);
      expect(records[0].type).toBe(wire.types.NS);
      expect(records[1].type).toBe(wire.types.DS);
    });
  });

  describe('abstract (forked) ENS registries', () => {
    it('resolves records via the registry named in the NS record', async () => {
      const [eth, mock] = makeEthWithMock();
      const ns = `${ABSTRACT_ADDRESS}._eth.`;

      // the forked registry (named in the NS record) maps the node to
      // its own resolver, which also serves the DNS records
      setARecord(eth, mock, ABSTRACT_ADDRESS, ABSTRACT_ADDRESS);

      const data = await eth.resolveDnsFromAbstractEns(DNS_NAME, 1, ns);
      expect(data).toBeTruthy();

      const records = decodeRecords(data!);
      expect(records).toHaveLength(1);
      expect(records[0].type).toBe(1);
      expect(records[0].data.address).toBe(A_RECORD_IP);

      // must query the forked registry, not the canonical ENS registry
      expect((mock.calls[0] as any).address.toLowerCase()).toBe(
        ABSTRACT_ADDRESS.toLowerCase()
      );
    });

    it('rejects a malformed _eth NS referral', async () => {
      const eth = makeEth();
      await expect(
        eth.resolveDnsFromAbstractEns(DNS_NAME, 1, 'badformat')
      ).resolves.toBeNull();
    });
  });

  describe('resolveEnsAddress()', () => {
    // Checksummed form of the Binance address used for the all-upper and
    // ICAP tests below.
    const CHECKSUMMED_ADDR = '0x9be05aF9fC0C340a92d09b71193a5B8Db4EBd9BB';

    function addressWord(addr: string): string {
      return '0x' + '00'.repeat(12) + addr.slice(2);
    }

    it('resolves an exact node with a resolver (plain addr call)', async () => {
      const [eth, mock] = makeEthWithResolver();
      const target = '0x1234567890123456789012345678901234567890';

      mock.callHandler = () => addressWord(target);

      const addr = await eth.resolveEnsAddress(DNS_NODE);
      expect(addr?.toLowerCase()).toBe(target);
    });

    it('returns a valid address input as-is (no ENS lookup)', async () => {
      const eth = makeEth();

      const addr = await eth.resolveEnsAddress(
        '0x1234567890abcdef1234567890abcdef12345678'
      );
      expect(addr?.toLowerCase()).toBe('0x1234567890abcdef1234567890abcdef12345678');
    });

    it('returns a valid mixed-case checksummed address as-is', async () => {
      const eth = makeEth();

      const addr = await eth.resolveEnsAddress(CHECKSUMMED_ADDR);
      expect(addr).toBe(CHECKSUMMED_ADDR);
    });

    it('accepts an all-uppercase address (checksummed, no ENS lookup)', async () => {
      const eth = makeEth();
      const upper = '0x' + '9be05af9fc0c340a92d09b71193a5b8db4ebd9bb'.toUpperCase();

      const addr = await eth.resolveEnsAddress(upper);

      // ethers accepted all-uppercase and returned the checksummed form
      expect(addr).toBe(CHECKSUMMED_ADDR);
    });

    it('throws on a mixed-case address with a bad checksum', async () => {
      const eth = makeEth();

      // valid hex shape, wrong checksum casing
      await expect(
        eth.resolveEnsAddress('0x1234567890aBcDeF1234567890aBcDeF12345678')
      ).rejects.toThrow();
    });

    it('throws on an odd-length / bare-0x hexstring (not an ENS name)', async () => {
      const eth = makeEth();

      await expect(eth.resolveEnsAddress('0x123')).rejects.toThrow();
      await expect(eth.resolveEnsAddress('0x')).rejects.toThrow();
    });

    it('converts an ICAP address without an ENS lookup', async () => {
      const eth = makeEth();

      // direct-mode ICAP for 0x9be05aF9... (Binance)
      const addr = await eth.resolveEnsAddress(
        'XE07I7HP5NK465ZEHLKB2FE15FAHWU9GGQJ'
      );
      expect(addr).toBe(CHECKSUMMED_ADDR);
    });

    it('maps a malformed (non-32-byte) addr return to null', async () => {
      const [eth, mock] = makeEthWithResolver();

      // 64-byte return word: ethers callAddress returns null
      mock.callHandler = () => '0x' + '11'.repeat(64);

      await expect(eth.resolveEnsAddress(DNS_NODE)).resolves.toBeNull();
    });

    it('returns null for an unregistered name', async () => {
      const [eth, mock] = makeEthWithMock();

      await expect(eth.resolveEnsAddress(DNS_NODE)).resolves.toBeNull();
    });

    it('uses ONLY the exact node (no parent-walk for subdomains)', async () => {
      const [eth, mock] = makeEthWithMock();

      // parent has a resolver but the exact subdomain node does not
      setResolver(eth, mock, DNS_NODE, RESOLVER_ADDRESS);

      // ethers 5.0.x performs an exact-node lookup only: no wildcard fallback
      await expect(eth.resolveEnsAddress(`sub.${DNS_NODE}`)).resolves.toBeNull();
    });
  });

  describe('resolveEnsText()', () => {
    it('returns null for an unregistered name', async () => {
      const [eth, mock] = makeEthWithMock();

      await expect(eth.resolveEnsText(DNS_NODE, 'avatar')).resolves.toBeNull();
    });

    it('reads a text record from the exact-node resolver', async () => {
      const [eth, mock] = makeEthWithResolver();
      const value = 'https://example.com/avatar.png';

      mock.callHandler = () =>
        encodeAbiParameters([{ type: 'string' }], [value]);

      await expect(eth.resolveEnsText(DNS_NODE, 'avatar')).resolves.toBe(value);
    });

    it('maps an on-chain empty text value to null', async () => {
      const [eth, mock] = makeEthWithResolver();

      mock.callHandler = () => encodeAbiParameters([{ type: 'string' }], ['']);

      await expect(eth.resolveEnsText(DNS_NODE, 'avatar')).resolves.toBeNull();
    });

    it('throws on a null/undefined key like ethers', async () => {
      const [eth, mock] = makeEthWithResolver();

      await expect(eth.resolveEnsText(DNS_NODE, null as any)).rejects.toThrow();
      await expect(
        eth.resolveEnsText(DNS_NODE, undefined as any)
      ).rejects.toThrow();
    });

    it('coerces a numeric key to the empty key without throwing', async () => {
      const [eth, mock] = makeEthWithResolver();

      mock.callHandler = () => '0x';

      await expect(eth.resolveEnsText(DNS_NODE, 123 as any)).resolves.toBeNull();
    });

    it('propagates resolver call errors (does not swallow)', async () => {
      const [eth, mock] = makeEthWithResolver();

      mock.callHandler = () => {
        throw new Error('connection refused');
      };

      // ethers 5.0.x gets no try/catch on the text() call
      await expect(eth.resolveEnsText(DNS_NODE, 'avatar')).rejects.toThrow(
        'connection refused'
      );
    });
  });
});
