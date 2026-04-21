# dnssec-audit monorepo

[![CI](https://github.com/d3servelabs/dnssec-audit-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/d3servelabs/dnssec-audit-ts/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@namefi/dnssec-audit.svg)](https://www.npmjs.com/package/@namefi/dnssec-audit)

A pure-TypeScript DNSSEC chain-of-trust stack: a library + CLI, a glass-UI
web app, and a Chrome extension — all sharing the same walker and running
entirely in the browser via DNS-over-HTTPS.

## Packages

| Path | Name | Published | Description |
|---|---|---|---|
| [`packages/dnssec-audit`](./packages/dnssec-audit) | [`@namefi/dnssec-audit`](https://www.npmjs.com/package/@namefi/dnssec-audit) | public on npm | Pure-TS DNSSEC walker, exporter, offline validator. |
| [`packages/shared`](./packages/shared) | `@namefi/dnssec-ui-shared` | private | Preact components and CSS shared by the webapp and extension. |
| [`packages/webapp`](./packages/webapp) | `@namefi/dnssec-webapp` | private — deployed to [dnssec.tools.namefi.io](https://dnssec.tools.namefi.io) | Preact + Vite glass-UI single-page app. |
| [`packages/chrome-extension`](./packages/chrome-extension) | `@namefi/dnssec-chrome-extension` | private — Chrome Web Store | Manifest V3 popup reusing the shared UI. |

All packages are currently pinned at **v2.1.0**.

## Quick start

```bash
npm install

# run the library's tests
npm test

# start the webapp locally
npm run dev:webapp        # http://localhost:5173

# watch-build the Chrome extension
npm run dev:chrome-extension
# then load packages/chrome-extension/dist/ as an unpacked extension

# build every publishable / deployable artifact
npm run build
```

## The library — `@namefi/dnssec-audit`

See [`packages/dnssec-audit/README.md`](./packages/dnssec-audit/README.md) for
the full API. Quick look:

```ts
import { DoHResolver, walk } from "@namefi/dnssec-audit";

const resolver = new DoHResolver("https://cloudflare-dns.com/dns-query");
const res = await walk("cloudflare.com.", 1, resolver);
console.log(res.verdict); // "secure-positive"
```

CLIs:

```bash
npx @namefi/dnssec-audit dnssec-export --domain cloudflare.com
npx @namefi/dnssec-audit dnssec-validate --domain cloudflare.com --verbose
```

Or via workspace scripts during development:

```bash
npm run export -- --domain cloudflare.com
npm run validate -- --domain cloudflare.com --verbose
```

### Publishing

```bash
npm run build -w packages/dnssec-audit
npm publish -w packages/dnssec-audit --access public
```

`publishConfig.access` is already `public`. `prepublishOnly` runs the build.

## The webapp

Minimalist, high-end glassmorphism UI: frosted-glass card over a deep bokeh
background, 1px white border highlight, soft diffused shadows. Accepts one or
more domains (space / comma / newline separated) and runs the walker entirely
client-side against a chosen DoH endpoint — your domain list never leaves
the browser.

Deploy target: **https://dnssec.tools.namefi.io** (static host, `dist/`
contents served at the root).

```bash
npm run dev:webapp         # live dev server
npm run build -w packages/webapp
# packages/webapp/dist/ is ready to upload
```

URL parameters:
- `?d=example.com,foo.com` — pre-fill domains
- `?t=AAAA` — default query type

## The Chrome extension

Manifest V3, popup-only. Opens with the current tab's hostname pre-filled
and offers a one-click deep link to the full webapp.

```bash
npm run build -w packages/chrome-extension
# then in chrome://extensions enable Developer Mode and
# "Load unpacked" → packages/chrome-extension/dist
```

The extension declares `host_permissions` only for the three public DoH
endpoints it uses (Cloudflare / Google / Quad9).

## Architecture

```
          ┌─────────────────────────────────────────────────┐
          │ @namefi/dnssec-audit (pure-TS, zero-dep)        │
          │  wire · canonical · crypto · nsec · walker      │
          │  resolver (DoH / Recording / JSONL)             │
          └──────────────┬──────────────────────────────────┘
                         │
          ┌──────────────┴───────────────┐
          │ @namefi/dnssec-ui-shared     │
          │  checkDomain()               │
          │  <DnssecChecker />  <BrandHeader />
          │  styles.css (glass tokens)   │
          └──────┬─────────────────┬─────┘
                 │                 │
   ┌─────────────┴─────┐   ┌───────┴──────────────┐
   │ webapp            │   │ chrome-extension     │
   │ Preact + Vite     │   │ Preact + MV3 popup   │
   │ dnssec.tools…     │   │ Chrome Web Store     │
   └───────────────────┘   └──────────────────────┘
```

The walker is the same code path the npm package exposes — the UI packages
are a thin Preact shell around `DoHResolver` + `walk()`.

## Browser compatibility

The core only uses `Uint8Array`, `DataView`, `TextEncoder`, `fetch`, and
`crypto.subtle`. No `Buffer`, no Node shims. Requires a browser that
supports the Ed25519 algorithm in WebCrypto (Chrome 133+, Safari 17+,
Firefox 130+); other DNSSEC algorithms have broader support.

## Also See

- [d3servelabs/dnssec-audit-py](https://github.com/d3servelabs/dnssec-audit-py) — Python implementation.

## License

[MIT](LICENSE) © 2026 D3Serve Labs Inc. dba Namefi (https://namefi.io)
