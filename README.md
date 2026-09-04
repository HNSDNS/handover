# Handover

This is the **HNSDNS fork** of [imperviousinc/handover](https://github.com/imperviousinc/handover):
a plugin for `hsd` (Handshake full node, v8+) that enables DNS resolution on
external networks like Ethereum (ENS / EIP-1185).

> **Fork notice:** install from this repo's git URL (see below). An `npm
> install handover` from the registry or installing from the upstream repo
> gets you the old, pre-refactor version — not this code.

## Requirements

- **Node.js >= 24** (native ESM + TypeScript type stripping — no build step)
- **hsd ^8.0.0** (loaded as a plugin)
- **Helios** (or any Ethereum JSON-RPC endpoint that supports `eth_call`)

## Architecture

Handover no longer talks to a hosted JSON-RPC provider directly. Instead it
points at a **local Helios light client** (`http://127.0.0.1:8545`), which wraps
an upstream RPC and verifies responses trustlessly against the consensus layer:

```
hsd --plugins handover ──► Handover ──► http://127.0.0.1:8545 (Helios)
                                            │  light-client verification
                                            ▼
                                    upstream RPC (e.g. Alchemy/Infura)
```

Running Helios as a **separate process** (not embedded) keeps the hsd plugin
small and lets you reuse a single verified RPC endpoint across dapps.

## Installation & Usage

Install and run Helios first:

```
curl https://raw.githubusercontent.com/a16z/helios/master/heliosup/install | bash
heliosup
helios ethereum --execution-rpc $ETH_RPC_URL
```

Helios now serves a verified local RPC at `http://127.0.0.1:8545`.

### Install the plugin into hsd

hsd loads plugins listed with `--plugins` through a plain CommonJS `require()`
call made from inside hsd itself, so the plugin must end up in **hsd's**
`node_modules` tree. Install it from this repo with npm's GitHub shorthand:

```
cd /path/to/hsd

npm install HNSDNS/handover
```

`npm install HNSDNS/handover` installs directly from git (the default branch)
— the package is not published to npm. To pin a specific commit:

```
npm install HNSDNS/handover#<commit-sha>
```

Because the plugin has no build step (TypeScript is run directly via Node
type stripping), the git install needs nothing besides npm's own dep
resolution. npm will also auto-install the plugin's peer dependencies
(`bns`, `blru`, `bufio` and a nested `hsd` copy) into the plugin's
`node_modules` — that nested `hsd` is dead weight but harmless; the running
node is the one you already have.

`npm install <user>/<repo>` as a shorthand for `git+https://...`; both of
these are equivalent:

```
npm install git+https://github.com/HNSDNS/handover.git
npm install git+ssh://git@github.com/HNSDNS/handover.git
```

### How hsd loads a plugin

When you run `hsd --plugins handover`, hsd calls `plugin = loader('handover')`
with a plain `require()` executed from hsd's own context. The module must
export an object with:

- **`init(node)`** (required) — called at node construction to instantiate the
  plugin; must return a plugin instance
- **`open()`** / **`close()`** — optional lifecycle hooks called when hsd
  starts up / shuts down
- **`id`** (optional) — registers the plugin so it can be looked up with
  `node.get('handover')`

Because the plugin's `id` is registered, hsd auto-prefixes this plugin's
config options: any `--handover-<option>` CLI flag, `HSD_HANDOVER_<OPTION>`
environment variable, or `handover-<option>` line in `hsd.conf` is fed to the
plugin's config object. That's why `--handover-rpc-url` is a familiar, native
hsd-style option.

The plugin entry is an ESM TypeScript file (`src/handover.ts`). A raw
`require()` of an ESM module would normally fail, but Node >= 22.12 supports
synchronous `require()` of ESM — and Node >= 24 additionally strips
TypeScript types natively. Combined, hsd can load this `.ts` module straight
from `node_modules` with no build step. This is why **Node.js >= 24** is a
hard requirement.

### Configure

Tell the plugin where your Helios / RPC endpoint lives (config params work like
any other hsd option):

Command line:

```
hsd \
 --plugins=handover \
 --handover-rpc-url=http://127.0.0.1:8545
```

Environment variable:

```
export HSD_HANDOVER_RPC_URL=http://127.0.0.1:8545
hsd --plugins handover
```

Configuration file (`~/.hsd/hsd.conf`):

```
handover-rpc-url: http://127.0.0.1:8545
plugins: handover
```

You should see this in the log:

```
[info] (handover) handover external network resolver plugin is active!
```

> **Upgrading hsd?** If coming from an earlier major, pass `--chain-migrate=4`
> and `--wallet-migrate=7` the first time you run v8.

Resolve an ENS name directly without Handshake:

```
$ dig @127.0.0.1 -p 5350 fuckingfucker.eth +short
184.73.82.1
```

Resolve a decentralized subdomain of a Handshake TLD:

```
$ dig @127.0.0.1 -p 5350 certified.badass +short
184.73.82.1
```

## Resolving HNS names on Ethereum

See [HIP-0005](https://github.com/handshake-org/HIPs/pull/10) for more details.

Notice how the NS record was set for this Handshake domain:

```
$ hsd-rpc getnameresource badass

{
  "records": [
    {
      "type": "NS",
      "ns": "0x36fc69f0983E536D1787cC83f481581f22CCA2A1._eth."
    }
  ]
}
```

The `_eth` TLD indicates an abstract (forked) ENS contract on Ethereum, appended
to the contract's address. On Ethereum, the domain `certified.badass` was registered
with this contract, and its DNS records were set using [EIP-1185](https://eips.ethereum.org/EIPS/eip-1185).

## Explanation

When `hsd` is run with this plugin, a middleware function is added to the HNS root
resolver that intercepts queries as they come in. If the query is rooted in either
`.eth` or `._eth` TLD, the name is resolved directly using ENS, bypassing Handshake.

Otherwise, HNS resolution proceeds normally. However, the results are inspected
by the plugin before being returned. If a domain has an NS record rooted in either
`.eth` or `._eth`, the plugin uses the NS address and the original query string
to resolve the user's request on Ethereum. If an answer is found there, it is
sent back to the recursive resolver.

One more complication: recursive resolvers (like unbound) may have
`qname-minimisation` set, so they begin recursion by querying only the TLD
rather than sending the full query string. To deal with this, if the plugin
detects a NS pointing to `.eth` or `._eth` but does not have a full query string
(i.e. only one label, `.badass`) the plugin returns an empty response with SOA. This tricks the recursive resolver into making a new
request with the full query string (i.e. `certified.badass`).

## Development

The plugin is authored in TypeScript and runs directly on Node 24 via native
type stripping — no build step. ESM-only; hsd loads it through `require()`
(`require(esm)`), which is supported on Node >= 22.12.

To install it into hsd for development (symlink):

```
git clone https://github.com/HNSDNS/handover
cd handover
npm install

cd /path/to/hsd/repo
ln -s /path/to/handover /node_modules/handover

export NODE_PRESERVE_SYMLINKS=1
hsd --plugins handover
```

If you need `sudo` to listen on port `53`:

```
export NODE_PRESERVE_SYMLINKS=1
sudo -E hsd --plugins handover --rs-port 53
```

## Testing

Unit / plugin-load tests (offline, mocked Ethereum JSON-RPC):

```
npm test
npm run typecheck
```

Live tests talk to a real chain. Point them at your local Helios (or any node):

```
helios ethereum --execution-rpc $ETH_RPC_URL
HANDOVER_RPC_URL=http://127.0.0.1:8545 npm run test:live
```

Run the full hsd integration test (requires hsd installed alongside):

```
cd /path/to/hsd
node_modules/handover/test/handover-plugin-test.sh
```

## Credit

This plugin relies on the [viem](https://viem.sh) library (the low-level engine
behind the [wagmi](https://wagmi.sh) stack), and the
[Helios](https://github.com/a16z/helios) Ethereum light client.

Inspiration comes from [hsd-ens-resolution](https://github.com/tynes/hsd-ens-resolution)
by the very handsome and super-friendly [@tynes](https://github.com/tynes).

Thanks to [@rithvikvibhu](https://github.com/rithvikvibhu) for the name "handover".
