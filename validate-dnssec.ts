#!/usr/bin/env node
// Usage:
//   node --experimental-strip-types validate-dnssec.ts --domain <d> [--type A] [--at <ISO>] [--in <path>]
import { parseArgs } from "node:util";
import { readFile } from "node:fs/promises";
import { JSONLResolver, type CapturedEntry } from "./src/resolver.ts";
import { walk } from "./src/walker.ts";
import { typeFromName, canonicalName } from "./src/wire.ts";
import { ROOT_TRUST_ANCHORS } from "./src/trust-anchor.ts";
import { bytesToHex } from "./src/util.ts";

async function main() {
  const { values } = parseArgs({
    options: {
      domain: { type: "string" },
      type: { type: "string", default: "A" },
      at: { type: "string" },
      in: { type: "string" },
      verbose: { type: "boolean", default: false },
    },
    strict: true,
    allowPositionals: false,
  });
  if (!values.domain) {
    console.error("usage: validate-dnssec.ts --domain <domain> [--type A] [--at <ISO>] [--in file]");
    process.exit(2);
  }
  const domain = canonicalName(values.domain);
  const qtype = typeFromName(values.type as string);
  const inPath = (values.in as string | undefined) ?? `${domain.replace(/\.$/, "")}-dnssec.jsonl`;
  const at = values.at ? new Date(values.at as string) : new Date();
  if (Number.isNaN(at.getTime())) {
    console.error(`invalid --at: ${values.at}`);
    process.exit(2);
  }

  const text = await readFile(inPath, "utf8");
  const lines = text.split("\n").filter((l) => l.length > 0);
  const captured: CapturedEntry[] = [];
  const jsonlTrustAnchors: { keyTag: number; algorithm: number; digestType: number; digest_hex: string }[] = [];
  let header: Record<string, unknown> | null = null;
  for (const line of lines) {
    const obj = JSON.parse(line);
    if (obj.kind === "header") header = obj;
    else if (obj.kind === "trust-anchor") jsonlTrustAnchors.push(obj);
    else if (obj.kind === "response") captured.push(obj as CapturedEntry);
  }
  if (!header) {
    console.error("JSONL has no header record");
    process.exit(2);
  }

  // Cross-check the JSONL's embedded trust anchors against the hardcoded IANA anchors.
  // The *source of truth* for validation is the hardcoded anchors; JSONL is informational.
  const hardcoded = new Set(
    ROOT_TRUST_ANCHORS.map((t) => `${t.keyTag}/${t.algorithm}/${t.digestType}/${bytesToHex(t.digest).toLowerCase()}`),
  );
  let jsonlMatches = true;
  for (const t of jsonlTrustAnchors) {
    const k = `${t.keyTag}/${t.algorithm}/${t.digestType}/${t.digest_hex.toLowerCase()}`;
    if (!hardcoded.has(k)) {
      jsonlMatches = false;
      break;
    }
  }
  if (!jsonlMatches) {
    console.warn("warning: JSONL trust-anchor entries differ from hardcoded IANA set — using hardcoded");
  }

  const resolver = new JSONLResolver(captured);
  const res = await walk(domain, qtype, resolver, { at });

  console.log(`domain:   ${domain}`);
  console.log(`qtype:    ${values.type}`);
  console.log(`at:       ${at.toISOString()}`);
  console.log(`input:    ${inPath} (${captured.length} captured responses)`);
  console.log(`verdict:  ${res.verdict}`);
  console.log(`detail:   ${res.detail}`);
  if (values.verbose) {
    console.log("steps:");
    for (const s of res.steps) {
      const tag = s.ok ? "OK " : "ERR";
      const scope = s.zone ?? s.qname ?? "";
      console.log(`  [${tag}] ${s.kind.padEnd(20)} ${scope.padEnd(30)} ${s.detail}`);
    }
  } else {
    console.log("(pass --verbose for step-by-step trace)");
  }

  const ok = res.verdict === "secure-positive" || res.verdict === "secure-nodata" || res.verdict === "secure-nxdomain";
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
