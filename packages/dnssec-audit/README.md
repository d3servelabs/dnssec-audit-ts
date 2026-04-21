# @namefi/dnssec-audit

[![CI](https://github.com/d3servelabs/dnssec-audit-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/d3servelabs/dnssec-audit-ts/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@namefi/dnssec-audit.svg)](https://www.npmjs.com/package/@namefi/dnssec-audit)

A pure-TypeScript library (and pair of CLIs) that (1) **exports** the full
DNSSEC chain of trust for a domain to a JSONL file, and (2) **validates** it
cryptographically offline from that JSONL alone — no network, no `dig`, no
native dependencies.

Same modules run in Node and in the browser (only `Uint8Array`, `fetch`, and
`crypto.subtle`). The `@namefi/dnssec.tools` web app and Chrome extension in
this monorepo are both built on top of this package.

## Install

```bash
npm install @namefi/dnssec-audit
```

Requires Node 22.6+ (for `node --experimental-strip-types` when running the TS
sources directly) or any modern browser when consumed via a bundler.

## Library usage

```ts
import { DoHResolver, walk } from "@namefi/dnssec-audit";

const resolver = new DoHResolver("https://cloudflare-dns.com/dns-query");
const result = await walk("prettysafe.xyz.", /* A */ 1, resolver);

console.log(result.verdict); // "secure-positive" | "secure-nodata" | "secure-nxdomain" | "insecure" | "bogus"
for (const step of result.steps) {
  console.log(step.kind, step.ok, step.detail);
}
```

Individual sub-paths are also available:

```ts
import { walk } from "@namefi/dnssec-audit/walker";
import { DoHResolver, JSONLResolver, RecordingResolver } from "@namefi/dnssec-audit/resolver";
import { ROOT_TRUST_ANCHORS } from "@namefi/dnssec-audit/trust-anchor";
```

## CLIs

Installing with `-g` (or via `npx`) exposes two binaries:

### Export

```bash
dnssec-export \
     --domain prettysafe.xyz \
     [--type A] \
     [--resolver https://cloudflare-dns.com/dns-query] \
     [--out prettysafe.xyz-dnssec.jsonl]
```

Writes one JSON object per line:
- 1 `header` (tool version, timestamp, walker verdict/steps)
- N `trust-anchor` lines (IANA root DS records, informational)
- M `response` lines (one per DoH query, with base64 wire-format response)

### Validate

```bash
dnssec-validate \
     --domain prettysafe.xyz \
     [--type A] \
     [--at 2026-04-21T00:00:00Z] \
     [--in prettysafe.xyz-dnssec.jsonl] \
     [--verbose]
```

Exits `0` on `secure-positive | secure-nodata | secure-nxdomain`, non-zero
otherwise (including `insecure` and `bogus`).

## Verdicts

| Verdict           | Meaning                                                          |
|-------------------|------------------------------------------------------------------|
| `secure-positive` | Full chain root → ... → qname; answer RRset signature verified.  |
| `secure-nodata`   | Chain verified; NSEC/NSEC3 proves the type does not exist.       |
| `secure-nxdomain` | Chain verified; NSEC/NSEC3 proves the name does not exist.       |
| `insecure`        | Proof of no DS at a delegation point (incl. NSEC3 opt-out).      |
| `bogus`           | Required signature, digest, or denial proof failed verification. |

## Supported algorithms

| DNSKEY algorithm                | Num       | Status                        |
|---------------------------------|-----------|-------------------------------|
| RSA/SHA-256                     | 8         | supported                     |
| RSA/SHA-512                     | 10        | supported                     |
| ECDSA Curve P-256               | 13        | supported                     |
| ECDSA Curve P-384               | 14        | supported                     |
| Ed25519                         | 15        | supported                     |
| RSA/SHA-1, RSA/SHA-1-NSEC3, DSA | 5 / 7 / 3 | not implemented (deprecated)  |

DS digest types: SHA-1 (1), SHA-256 (2), SHA-384 (4).

## License

[MIT](https://github.com/d3servelabs/dnssec-audit-ts/blob/main/LICENSE) © 2026 D3Serve Labs Inc. dba Namefi (https://namefi.io)
