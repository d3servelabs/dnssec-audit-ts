import {
  DoHResolver,
  RecordingResolver,
  walk,
  canonicalName,
  typeFromName,
  type WalkResult,
  type WalkStep,
} from "@namefi/dnssec-audit";

export type Verdict = WalkResult["verdict"];

export interface DomainCheckResult {
  domain: string;
  canonical: string;
  qtype: number;
  qtypeName: string;
  resolver: string;
  startedAt: string;
  durationMs: number;
  verdict: Verdict | "error";
  detail: string;
  steps: WalkStep[];
  error?: string;
  queryCount: number;
}

export const DOH_ENDPOINTS: { label: string; url: string }[] = [
  { label: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { label: "Google", url: "https://dns.google/dns-query" },
  { label: "Quad9", url: "https://dns.quad9.net/dns-query" },
];

export const DEFAULT_DOH = DOH_ENDPOINTS[0].url;

export interface CheckOptions {
  /** DoH endpoint (defaults to Cloudflare). */
  resolver?: string;
  /** Record type; defaults to "A". */
  qtype?: string;
}

export async function checkDomain(
  domain: string,
  opts: CheckOptions = {},
): Promise<DomainCheckResult> {
  const resolverUrl = opts.resolver ?? DEFAULT_DOH;
  const qtypeName = (opts.qtype ?? "A").toUpperCase();
  const qtype = typeFromName(qtypeName);
  const canonical = canonicalName(domain);
  const startedAt = new Date().toISOString();
  const t0 = performance.now();

  const doh = new DoHResolver(resolverUrl);
  const rec = new RecordingResolver(doh);
  try {
    const res = await walk(canonical, qtype, rec);
    return {
      domain,
      canonical,
      qtype,
      qtypeName,
      resolver: resolverUrl,
      startedAt,
      durationMs: Math.round(performance.now() - t0),
      verdict: res.verdict,
      detail: res.detail,
      steps: res.steps,
      queryCount: rec.entries.length,
    };
  } catch (e) {
    return {
      domain,
      canonical,
      qtype,
      qtypeName,
      resolver: resolverUrl,
      startedAt,
      durationMs: Math.round(performance.now() - t0),
      verdict: "error",
      detail: (e as Error).message,
      steps: [],
      error: (e as Error).message,
      queryCount: rec.entries.length,
    };
  }
}

export function parseDomainInput(raw: string): string[] {
  return raw
    .split(/[\s,;\n]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function verdictLabel(v: Verdict | "error"): string {
  switch (v) {
    case "secure-positive":
      return "Secure";
    case "secure-nodata":
      return "Secure (no record)";
    case "secure-nxdomain":
      return "Secure (nonexistent)";
    case "insecure":
      return "Insecure";
    case "bogus":
      return "Bogus";
    case "error":
      return "Error";
  }
}

export function verdictTone(v: Verdict | "error"): "ok" | "warn" | "bad" {
  if (v === "secure-positive" || v === "secure-nodata" || v === "secure-nxdomain") return "ok";
  if (v === "insecure") return "warn";
  return "bad";
}
