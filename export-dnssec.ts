#!/usr/bin/env node
// Usage:
//   node --experimental-strip-types export-dnssec.ts --domain <d> [--type A] [--resolver URL] [--out <path>]
import { parseArgs } from "node:util";
import { writeFile } from "node:fs/promises";
import { DoHResolver, RecordingResolver } from "./src/resolver.ts";
import { walk } from "./src/walker.ts";
import { typeFromName, canonicalName } from "./src/wire.ts";
import { ROOT_TRUST_ANCHORS } from "./src/trust-anchor.ts";
import { bytesToHex } from "./src/util.ts";

async function main() {
  const { values } = parseArgs({
    options: {
      domain: { type: "string" },
      type: { type: "string", default: "A" },
      resolver: { type: "string", default: "https://cloudflare-dns.com/dns-query" },
      out: { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });
  if (!values.domain) {
    console.error("usage: export-dnssec.ts --domain <domain> [--type A] [--resolver URL] [--out file]");
    process.exit(2);
  }
  const domain = canonicalName(values.domain);
  const qtype = typeFromName(values.type as string);
  const outPath = (values.out as string | undefined) ?? `${domain.replace(/\.$/, "")}-dnssec.jsonl`;

  const doh = new DoHResolver(values.resolver as string);
  const rec = new RecordingResolver(doh);

  const startedAt = new Date().toISOString();
  let verdict = "unknown";
  let detail = "";
  let steps: unknown[] = [];
  let error: string | null = null;
  try {
    const res = await walk(domain, qtype, rec);
    verdict = res.verdict;
    detail = res.detail;
    steps = res.steps;
  } catch (e) {
    error = (e as Error).message;
  }

  // Build JSONL: first a header, then the trust anchor entries, then every captured response.
  const lines: string[] = [];
  lines.push(
    JSON.stringify({
      kind: "header",
      version: 1,
      tool: "dnssec-audit-ts",
      created: startedAt,
      domain,
      qtype,
      resolver: (values.resolver as string),
      walker_verdict: verdict,
      walker_detail: detail,
      walker_error: error,
      walker_steps: steps,
    }),
  );
  for (const ta of ROOT_TRUST_ANCHORS) {
    lines.push(
      JSON.stringify({
        kind: "trust-anchor",
        keyTag: ta.keyTag,
        algorithm: ta.algorithm,
        digestType: ta.digestType,
        digest_hex: bytesToHex(ta.digest),
        notes: ta.notes,
      }),
    );
  }
  for (const e of rec.entries) {
    lines.push(JSON.stringify(e));
  }

  await writeFile(outPath, lines.join("\n") + "\n", "utf8");
  console.log(`wrote ${rec.entries.length} DoH responses to ${outPath}`);
  console.log(`walker verdict: ${verdict}${detail ? " — " + detail : ""}`);
  if (error) {
    console.error(`walker error: ${error}`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
