# dnssec-audit-ts

A pair of TypeScript scripts that (1) **export** the full DNSSEC chain of trust
for a domain to a JSONL file, and (2) **validate** it cryptographically offline
from that JSONL alone — no network, no `dig`, no native dependencies.

The same `src/` modules run in Node today and in a browser later (all code uses
`Uint8Array`, `fetch`, and `crypto.subtle` — no `Buffer`, no Node-only APIs).

## Why

- **Reproducible audits.** Capture the exact signatures a resolver returned at
  a point in time, then verify them any time afterwards without trusting
  anything except the IANA root trust anchor.
- **Portable.** No `dig`, no native crypto libraries. Two CLI files and a small
  pure-TypeScript core.
- **Uniform.** One walker handles positive answers, NSEC / NSEC3 NODATA,
  NSEC / NSEC3 NXDOMAIN, and NSEC3-opt-out insecure delegation.

## Requirements

- Node 22.6+ (for `node --experimental-strip-types`, running `.ts` directly)
- No runtime dependencies; TypeScript + `@types/node` as dev-only

```
npm install
```

## Usage

### Export

```
node --experimental-strip-types export-dnssec.ts \
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

```
node --experimental-strip-types validate-dnssec.ts \
     --domain prettysafe.xyz \
     [--type A] \
     [--at 2026-04-21T00:00:00Z] \
     [--in prettysafe.xyz-dnssec.jsonl] \
     [--verbose]
```

Exits `0` on `secure-positive | secure-nodata | secure-nxdomain`, non-zero
otherwise (including `insecure` and `bogus`).

### npm scripts

```
npm run export -- --domain prettysafe.xyz
npm run validate -- --domain prettysafe.xyz --verbose
npm run typecheck
```

## Verdicts

| Verdict           | Meaning                                                          |
|-------------------|------------------------------------------------------------------|
| `secure-positive` | Full chain root → ... → qname; answer RRset signature verified.  |
| `secure-nodata`   | Chain verified; NSEC/NSEC3 proves the type does not exist.       |
| `secure-nxdomain` | Chain verified; NSEC/NSEC3 proves the name does not exist.       |
| `insecure`        | Proof of no DS at a delegation point (incl. NSEC3 opt-out).      |
| `bogus`           | Required signature, digest, or denial proof failed verification. |

## Design

```
          dig  ─────────────────────── replaced by pure-TS + fetch
          │
          ▼
┌────────────────────┐    ┌────────────────────┐
│ export-dnssec.ts   │    │ validate-dnssec.ts │
│  (Node, online)    │    │  (Node/browser,    │
│                    │    │   offline)         │
└─────────┬──────────┘    └─────────┬──────────┘
          │                         │
          │ RecordingResolver       │ JSONLResolver
          │ wraps DoHResolver       │ reads JSONL
          └──────────┬──────────────┘
                     ▼
               src/walker.ts
                     │
      ┌──────────────┼───────────────┐
      ▼              ▼               ▼
  src/wire.ts   src/canonical.ts  src/crypto.ts
  (DNS codec)   (RFC 4034 canon)  (Web Crypto)
                     │
                     ▼
                src/nsec.ts
           (NSEC & NSEC3 denial)
```

The walker is identical across both CLIs — only the `Resolver` differs. That
guarantees the validator sees the same DNS responses the exporter saw, byte for
byte (responses are stored as base64-encoded wire format).

### Chain walk

1. Query `. DNSKEY`. Match one DNSKEY's digest against an IANA root DS
   (trust anchor).  Verify the root DNSKEY RRset signature with that KSK.
2. For each zone between the root and the queried name:
   - Query `zone DS` in the parent.
   - If DS present: verify its RRSIG with the parent's keys, match a child
     DNSKEY's digest to a DS, query the child DNSKEY RRset and verify.
   - If DS absent with valid NSEC/NSEC3 NODATA: mark insecure below here.
3. Query `qname qtype`.
   - Positive: verify the answer RRset's RRSIG with the signing zone's keys.
   - Denial: dispatch to NSEC or NSEC3 verifier (closest encloser, covering
     next-closer, wildcard).

## Supported algorithms

| DNSKEY algorithm        | Num | Status          |
|-------------------------|-----|-----------------|
| RSA/SHA-256             | 8   | supported       |
| RSA/SHA-512             | 10  | supported       |
| ECDSA Curve P-256       | 13  | supported       |
| ECDSA Curve P-384       | 14  | supported       |
| Ed25519                 | 15  | supported       |
| RSA/SHA-1, RSA/SHA-1-NSEC3, DSA | 5 / 7 / 3 | not implemented (deprecated) |

DS digest types: SHA-1 (1), SHA-256 (2), SHA-384 (4).

## Browser reuse

`src/` uses only `Uint8Array`, `DataView`, `TextEncoder`, `fetch`, and
`crypto.subtle`. Only the two CLI entry files (`export-dnssec.ts`,
`validate-dnssec.ts`) import `node:fs` / `node:util`. Wrap the walker in a
web UI by:

1. `import { walk } from "./src/walker.ts"` (bundle with esbuild/vite).
2. Instantiate `DoHResolver` with any public DoH endpoint.
3. Collect responses as `{ wire_b64, qname, qtype, endpoint, timestamp }`.
4. Feed them back into `JSONLResolver` for offline re-verification.

No `Buffer` polyfill, no Node shims.

## JSONL schema

```jsonc
// Header (one per file)
{
  "kind": "header",
  "version": 1,
  "tool": "dnssec-audit-ts",
  "created": "2026-04-21T16:00:00Z",
  "domain": "prettysafe.xyz.",
  "qtype": 1,
  "resolver": "https://cloudflare-dns.com/dns-query",
  "walker_verdict": "secure-nxdomain",
  "walker_detail": "...",
  "walker_error": null,
  "walker_steps": [ /* ... */ ]
}

// Trust-anchor line(s) — informational snapshot; validator uses its own
// hardcoded IANA copy as the source of truth.
{
  "kind": "trust-anchor",
  "keyTag": 20326,
  "algorithm": 8,
  "digestType": 2,
  "digest_hex": "e06d44b8...",
  "notes": "IANA root KSK-2017"
}

// Captured DoH response (one per walker query)
{
  "kind": "response",
  "qname": "xyz.",
  "qtype": 43,
  "endpoint": "https://cloudflare-dns.com/dns-query",
  "timestamp": "2026-04-21T16:00:01.123Z",
  "wire_b64": "AAA..."
}
```

The validator decodes each `wire_b64` back to a `DNSMessage` and re-runs the
walker against that cache — signatures are verified against the original bytes,
so verification is byte-exact.

## Known limitations

- CNAME/DNAME chains are not followed. Point the exporter at the canonical
  target if you need to validate further.
- Wildcard-signed positive answers honour the RRSIG label count but aren't
  exercised in the test fixtures.
- No full NSEC3 walker of the whole zone — only the specific denial proof the
  resolver returned.
- Deprecated algorithms (RSA/SHA-1, DSA) are not implemented.

## License

MIT (or whatever you choose — no runtime deps imply no transitive licenses).
