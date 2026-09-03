import { describe, it, expect, beforeAll } from 'vitest';
import bns from 'bns';
import Ethereum from '../src/ethereum.ts';
import { DNS_NAME, decodeRecords } from './helpers.ts';

const { wire } = bns;

// Live tests talk to a real chain. Point HANDOVER_RPC_URL at a local
// Helios light client (or any full node) to run them:
//
//   helios ethereum --execution-rpc $ETH_RPC_URL
//   HANDOVER_RPC_URL=http://127.0.0.1:8545 vitest run
const rpcUrl = process.env.HANDOVER_RPC_URL;

const suite = rpcUrl ? describe : describe.skip;

suite('lib/ethereum (live, against HANDOVER_RPC_URL)', () => {
  let eth: Ethereum;

  beforeAll(() => {
    eth = new Ethereum({ rpcUrl });
  });

  it('initializes against the chain', async () => {
    await eth.init();
    expect(eth.ensResolver).toBeTruthy();
  });

  it('resolves an EIP-1185 A record from ENS', async () => {
    const data = await eth.resolveDnsFromEns(DNS_NAME, wire.types.A);
    expect(data).toBeTruthy();

    const records = decodeRecords(data!);
    expect(records.length).toBeGreaterThan(0);
    expect(records[0].type).toBe(wire.types.A);
  });
});
