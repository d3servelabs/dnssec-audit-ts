import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { JSONLResolver, type CapturedEntry } from "../src/resolver.ts";
import { walk, type WalkResult } from "../src/walker.ts";
import { canonicalName } from "../src/wire.ts";

const here = dirname(fileURLToPath(import.meta.url));
const testdataDir = join(here, "..", "testdata");

type Verdict = WalkResult["verdict"];

interface Header {
  kind: "header";
  domain: string;
  qtype: number;
  created: string;
  walker_verdict: Verdict;
}

async function loadFixture(fileName: string): Promise<{
  header: Header;
  captured: CapturedEntry[];
  at: Date;
}> {
  const text = await readFile(join(testdataDir, fileName), "utf8");
  const lines = text.split("\n").filter((l) => l.length > 0);
  let header: Header | null = null;
  const captured: CapturedEntry[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    const obj = JSON.parse(line);
    if (obj.kind === "header") {
      header = obj as Header;
    } else if (obj.kind === "response") {
      const entry = obj as CapturedEntry;
      const key = `${canonicalName(entry.qname)}/${entry.qtype}`;
      if (seen.has(key)) {
        throw new Error(`fixture ${fileName} has duplicate response for ${key}`);
      }
      seen.add(key);
      captured.push(entry);
    }
  }
  if (!header) throw new Error(`fixture ${fileName} has no header`);
  const at = new Date(header.created);
  if (Number.isNaN(at.getTime())) {
    throw new Error(
      `fixture ${fileName} (domain=${header.domain}) has invalid header.created: ${header.created}`,
    );
  }
  return { header, captured, at };
}

async function validateFixture(fileName: string, expectedVerdict: Verdict) {
  const { header, captured, at } = await loadFixture(fileName);
  const resolver = new JSONLResolver(captured);
  const res = await walk(canonicalName(header.domain), header.qtype, resolver, { at });
  assert.equal(
    res.verdict,
    expectedVerdict,
    `verdict for ${fileName}: got ${res.verdict} (${res.detail})`,
  );
  for (const step of res.steps) {
    assert.ok(step.ok, `step failed for ${fileName}: ${step.kind} ${step.detail}`);
  }
}

test("cloudflare.com fixture validates as secure-positive", async () => {
  await validateFixture("cloudflare.com-dnssec.jsonl", "secure-positive");
});

test("prettysafe.xyz fixture validates as secure-nxdomain", async () => {
  await validateFixture("prettysafe.xyz-dnssec.jsonl", "secure-nxdomain");
});

test("header walker_verdict matches re-validation verdict", async () => {
  for (const file of ["cloudflare.com-dnssec.jsonl", "prettysafe.xyz-dnssec.jsonl"]) {
    const { header, captured, at } = await loadFixture(file);
    const resolver = new JSONLResolver(captured);
    const res = await walk(canonicalName(header.domain), header.qtype, resolver, { at });
    assert.equal(res.verdict, header.walker_verdict, `verdict mismatch for ${file}`);
  }
});
