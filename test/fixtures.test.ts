import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { JSONLResolver, type CapturedEntry } from "../src/resolver.ts";
import { walk } from "../src/walker.ts";
import { canonicalName } from "../src/wire.ts";

const here = dirname(fileURLToPath(import.meta.url));
const testdataDir = join(here, "..", "testdata");

interface Header {
  kind: "header";
  domain: string;
  qtype: number;
  created: string;
  walker_verdict: string;
}

async function loadFixture(fileName: string): Promise<{
  header: Header;
  captured: CapturedEntry[];
}> {
  const text = await readFile(join(testdataDir, fileName), "utf8");
  const lines = text.split("\n").filter((l) => l.length > 0);
  let header: Header | null = null;
  const captured: CapturedEntry[] = [];
  for (const line of lines) {
    const obj = JSON.parse(line);
    if (obj.kind === "header") header = obj as Header;
    else if (obj.kind === "response") captured.push(obj as CapturedEntry);
  }
  if (!header) throw new Error(`fixture ${fileName} has no header`);
  return { header, captured };
}

async function validateFixture(fileName: string, expectedVerdict: string) {
  const { header, captured } = await loadFixture(fileName);
  const at = new Date(header.created);
  const resolver = new JSONLResolver(captured);
  const res = await walk(canonicalName(header.domain), header.qtype, resolver, { at });
  assert.equal(
    res.verdict,
    expectedVerdict,
    `verdict for ${fileName}: got ${res.verdict} (${res.detail})`,
  );
  // Every recorded step should have succeeded for a secure verdict.
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
    const { header, captured } = await loadFixture(file);
    const at = new Date(header.created);
    const resolver = new JSONLResolver(captured);
    const res = await walk(canonicalName(header.domain), header.qtype, resolver, { at });
    assert.equal(res.verdict, header.walker_verdict, `verdict mismatch for ${file}`);
  }
});
