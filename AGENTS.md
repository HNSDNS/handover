# Project Guide

## Overview

`handover` is an [hsd](https://github.com/handshake-org/hsd) plugin (Handshake
full node, v8+) that enables DNS resolution on external networks like Ethereum
(ENS / EIP-1185 / HIP-0005).

**This is the HNSDNS fork** of [imperviousinc/handover](https://github.com/imperviousinc/handover).
It is **not published to npm** — installs must come from this git repo
(`npm install HNSDNS/handover` from inside `hsd`, or a symlink for
development). Do not write install instructions pointing at the npm registry
or the upstream repo.

## Requirements

- **Node.js >= 24** — hard requirement, see "ESM + TypeScript" below
- **hsd ^8.0.0** — the consuming host, loaded as its plugin
- **Helios** (or any `eth_call`-capable Ethereum JSON-RPC) — expected at
  `http://127.0.0.1:8545` by default (the `handover-rpc-url` option)

## Architecture

**How hsd loads this plugin** (verified against hsd source): hsd's `bin/node`
constructs the node with `loader: require`, so `--plugins handover` is a plain
CommonJS `require('handover')` resolved from hsd's own `node_modules` tree.
The module must export an object with `init(node)` (required, returns the
plugin instance), optional `open()`/`close()` lifecycle hooks, and an
optional `id` (`'handover'` here — registering it is what makes hsd
auto-prefix config options as `handover-*` / env `HSD_HANDOVER_*`).

- `src/handover.ts` — plugin entry + resolver middleware. A middleware is
  added to the HNS root resolver: queries rooted in `.eth`/`._eth` are
  resolved via ENS, bypassing Handshake; ordinary HNS results with an NS
  record rooted in `.eth`/`._eth` are resolved against Ethereum (HIP-5), plus
  a qname-minimisation workaround (empty response w/ SOA when only the TLD
  label is seen).
- `src/ethereum.ts` — ENS / EIP-1185 DNS resolution over [viem](https://viem.sh)
  against the configured RPC.
- `src/ambient.d.ts` — `declare module` types for the untyped CJS deps
  (`bns`, `blru`, `bufio`); import these as default imports and destructure.

Ethereum access points at the configurable `handover-rpc-url` (default
`http://127.0.0.1:8545`), i.e. a local [Helios](https://github.com/a16z/helios)
light client run as a separate process, not embedded.

## ESM + TypeScript (no build step)

This project is deliberately **buildless**:

- ESM-only (`"type": "module"`), entry is `src/handover.ts`; tsconfig has
  `erasableSyntaxOnly` + `allowImportingTsExtensions`, `noEmit`.
- Node >= 24 natively strips TypeScript types, and Node >= 22.12 supports
  synchronous `require()` of ESM; hsd loads the plugin via CJS `require`,
  so both features combined make the raw `.ts` entry work.
- **Do not add a build step, transpilation, or non-erasable TS syntax**
  (no enums, namespaces, parameter properties, or legacy decorators). Do not
  add top-level await (incompatible with synchronous `require(esm)`).

## Build & Test

```bash
npm test           # vitest run
npm run typecheck  # tsc --noEmit
npm run test:live  # gated by HANDOVER_RPC_URL env (default 127.0.0.1:8545)
```

- Unit tests are offline (mocked JSON-RPC). Live tests talk to a real chain.
- `test/helpers.ts` provides a `MockClient`; note its `readContract` is an
  arrow field (viem's `getContract` detaches `this`), keep it that way.
- Full hsd integration test: from an hsd checkout,
  `node_modules/handover/test/handover-plugin-test.sh`.

## Plugin quirks / conventions

- viem's `toBytes` is **hex-aware**: strings matching `/^0x/i` are hex-decoded
  instead of UTF-8. Never feed user-derived strings (labels, text keys) to it
  where the original ethers code used `toUtf8Bytes`.
- CJS deps (`bns` etc.) are untyped: `import bns from 'bns'` then destructure;
  add types in `src/ambient.d.ts`.
- The resolver middleware intentionally keeps parity with the audited original
  hsd logic — avoid gratuitous restructuring of its branches.