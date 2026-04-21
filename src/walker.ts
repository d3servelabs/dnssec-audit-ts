import {
  type RR,
  type DNSMessage,
  TYPE,
  typeName,
  encodeName,
  canonicalName,
  nameLabels,
  parseDNSKEY,
  parseDS,
  parseRRSIG,
  computeKeyTag,
} from "./wire.ts";
import { ROOT_TRUST_ANCHORS } from "./trust-anchor.ts";
import type { Resolver } from "./resolver.ts";
import { prepareRRset, buildSigningInput } from "./canonical.ts";
import { verifySignature, dsDigest, isAlgoSupported, algoName } from "./crypto.ts";
import { bytesEqual, bytesToHex } from "./util.ts";
import { nsecDenial, nsec3Denial, type DenialVerdict } from "./nsec.ts";

export interface WalkStep {
  kind:
    | "root-trust-anchor"
    | "dnskey"
    | "ds"
    | "answer"
    | "denial"
    | "insecure"
    | "note";
  zone?: string;
  qname?: string;
  qtype?: string;
  ok: boolean;
  detail: string;
}

export interface WalkResult {
  qname: string;
  qtype: number;
  verdict:
    | "secure-positive"
    | "secure-nodata"
    | "secure-nxdomain"
    | "insecure"
    | "bogus";
  detail: string;
  steps: WalkStep[];
}

type ValidatedKeys = Map<string /* zone canonical */, RR[]>;

export async function walk(
  qname: string,
  qtype: number,
  resolver: Resolver,
  opts: { at?: Date } = {},
): Promise<WalkResult> {
  const at = opts.at ?? new Date();
  const qcanon = canonicalName(qname);
  const steps: WalkStep[] = [];
  const keys: ValidatedKeys = new Map();

  // ---- Step 1: establish root DNSKEY set via IANA trust anchors ----
  const rootResp = await resolver.query(".", TYPE.DNSKEY);
  const rootDNSKEYs = rootResp.message.answers.filter((r) => r.type === TYPE.DNSKEY && canonicalName(r.name) === ".");
  const rootRRSIGs = rootResp.message.answers.filter((r) => r.type === TYPE.RRSIG && canonicalName(r.name) === ".");
  if (rootDNSKEYs.length === 0) {
    return fail(qname, qtype, steps, "no DNSKEYs in root DNSKEY response");
  }

  let anchorMatched: { ta: (typeof ROOT_TRUST_ANCHORS)[number]; ksk: RR } | null = null;
  for (const ta of ROOT_TRUST_ANCHORS) {
    for (const k of rootDNSKEYs) {
      const kTag = computeKeyTag(k);
      if (kTag !== ta.keyTag) continue;
      const pk = parseDNSKEY(k);
      if (pk.algorithm !== ta.algorithm) continue;
      const digest = await dsDigest(ta.digestType, encodeName("."), k.rdata);
      if (bytesEqual(digest, ta.digest)) {
        anchorMatched = { ta, ksk: k };
        break;
      }
    }
    if (anchorMatched) break;
  }
  if (!anchorMatched) {
    return fail(qname, qtype, steps, "no root DNSKEY matched any IANA trust anchor");
  }
  steps.push({
    kind: "root-trust-anchor",
    zone: ".",
    ok: true,
    detail: `matched ${anchorMatched.ta.notes} (keyTag=${anchorMatched.ta.keyTag})`,
  });

  // Verify root DNSKEY RRset RRSIG signed by anchorMatched.ksk
  const rootVerified = await verifyRRSIGOverRRset(
    rootDNSKEYs,
    rootRRSIGs.filter((r) => {
      const rs = parseRRSIG(r);
      return rs.typeCovered === TYPE.DNSKEY;
    }),
    [anchorMatched.ksk],
    at,
  );
  if (!rootVerified.ok) {
    return fail(qname, qtype, steps, `root DNSKEY RRSIG: ${rootVerified.detail}`);
  }
  keys.set(".", rootDNSKEYs);
  steps.push({
    kind: "dnskey",
    zone: ".",
    ok: true,
    detail: `root DNSKEY RRset verified (${rootDNSKEYs.length} keys)`,
  });

  // ---- Step 2: walk labels from root toward qname establishing zone cuts ----
  // Candidate zones: each proper ancestor of qname, most-general first (excluding root).
  const labels = nameLabels(qcanon); // e.g. ["prettysafe", "xyz"] for "prettysafe.xyz."
  const candidates: string[] = [];
  for (let i = labels.length - 1; i >= 0; i--) {
    candidates.push(labels.slice(i).join(".") + ".");
  }
  // candidates for "prettysafe.xyz." => ["xyz.", "prettysafe.xyz."]

  let insecureAt: string | null = null;
  let deepestSigned = "."; // closest-to-qname zone whose keys are validated

  for (const zone of candidates) {
    // Query DS in the parent zone
    const parentZone = parentOf(zone);
    const dsResp = await resolver.query(zone, TYPE.DS);
    const dsRRs = dsResp.message.answers.filter((r) => r.type === TYPE.DS && canonicalName(r.name) === zone);
    const dsSigs = dsResp.message.answers.filter((r) => r.type === TYPE.RRSIG && canonicalName(r.name) === zone);

    if (dsRRs.length > 0) {
      // Positive DS — verify it's signed by parent's DNSKEYs
      const parentKeys = keys.get(parentZone);
      if (!parentKeys) {
        return fail(qname, qtype, steps, `missing parent keys for ${parentZone} when verifying DS of ${zone}`);
      }
      const dsVer = await verifyRRSIGOverRRset(
        dsRRs,
        dsSigs.filter((r) => parseRRSIG(r).typeCovered === TYPE.DS),
        parentKeys,
        at,
      );
      if (!dsVer.ok) return fail(qname, qtype, steps, `DS for ${zone}: ${dsVer.detail}`);
      steps.push({
        kind: "ds",
        zone,
        ok: true,
        detail: `DS RRset verified (${dsRRs.length} DS records)`,
      });

      // Fetch child DNSKEY, verify KSK digest matches a DS, then verify DNSKEY RRSIG
      const keyResp = await resolver.query(zone, TYPE.DNSKEY);
      const childDNSKEYs = keyResp.message.answers.filter(
        (r) => r.type === TYPE.DNSKEY && canonicalName(r.name) === zone,
      );
      const childKeySigs = keyResp.message.answers.filter(
        (r) => r.type === TYPE.RRSIG && canonicalName(r.name) === zone,
      );
      if (childDNSKEYs.length === 0) {
        return fail(qname, qtype, steps, `no DNSKEYs returned for ${zone}`);
      }
      // Find a DNSKEY whose DS digest matches one of dsRRs
      let matchedKsk: RR | null = null;
      for (const ds of dsRRs) {
        const dsRd = parseDS(ds);
        for (const k of childDNSKEYs) {
          if (computeKeyTag(k) !== dsRd.keyTag) continue;
          const pk = parseDNSKEY(k);
          if (pk.algorithm !== dsRd.algorithm) continue;
          let digest: Uint8Array;
          try {
            digest = await dsDigest(dsRd.digestType, encodeName(zone), k.rdata);
          } catch {
            continue;
          }
          if (bytesEqual(digest, dsRd.digest)) {
            matchedKsk = k;
            break;
          }
        }
        if (matchedKsk) break;
      }
      if (!matchedKsk) {
        return fail(
          qname,
          qtype,
          steps,
          `no DNSKEY at ${zone} matches any DS digest from parent`,
        );
      }
      const keyVer = await verifyRRSIGOverRRset(
        childDNSKEYs,
        childKeySigs.filter((r) => parseRRSIG(r).typeCovered === TYPE.DNSKEY),
        [matchedKsk],
        at,
      );
      if (!keyVer.ok) return fail(qname, qtype, steps, `DNSKEY RRSIG at ${zone}: ${keyVer.detail}`);
      keys.set(zone, childDNSKEYs);
      deepestSigned = zone;
      steps.push({
        kind: "dnskey",
        zone,
        ok: true,
        detail: `DNSKEY RRset verified (${childDNSKEYs.length} keys; KSK tag=${computeKeyTag(matchedKsk)})`,
      });
    } else {
      // No DS — need to see if this is (a) no zone cut, (b) insecure delegation, or (c) end of ancestors.
      // Check authority section for NSEC/NSEC3 denial of DS.
      const parentKeys = keys.get(parentZone);
      if (!parentKeys) {
        return fail(qname, qtype, steps, `missing parent keys for ${parentZone}`);
      }
      const ns = dsResp.message.authorities.filter((r) => r.type === TYPE.NSEC);
      const ns3 = dsResp.message.authorities.filter((r) => r.type === TYPE.NSEC3);
      const nsSigs = dsResp.message.authorities.filter((r) => r.type === TYPE.RRSIG);
      if (ns.length === 0 && ns3.length === 0) {
        // Could simply mean "not a zone cut" — treat as non-cut and continue without changing deepestSigned.
        steps.push({
          kind: "note",
          zone,
          ok: true,
          detail: `no DS and no NSEC/NSEC3 — ${zone} is not a zone cut`,
        });
        continue;
      }
      // Verify the NSEC/NSEC3 RRSIGs with parent keys
      const denialRRs = ns.length > 0 ? ns : ns3;
      const denialSigs = nsSigs.filter((r) => {
        const rs = parseRRSIG(r);
        return rs.typeCovered === (ns.length > 0 ? TYPE.NSEC : TYPE.NSEC3);
      });
      const ver = await verifyRRSIGsGrouped(denialRRs, denialSigs, parentKeys, at);
      if (!ver.ok) {
        return fail(qname, qtype, steps, `denial RRSIG at ${zone} (DS): ${ver.detail}`);
      }
      const verdict: DenialVerdict = ns.length > 0
        ? nsecDenial(zone, TYPE.DS, ns)
        : await nsec3Denial(zone, TYPE.DS, ns3);
      if (verdict.kind === "nodata" || verdict.kind === "insecure-delegation") {
        // Insecure delegation: zone is unsigned or delegation has no DS.
        insecureAt = zone;
        steps.push({
          kind: "insecure",
          zone,
          ok: true,
          detail: `no DS — delegation at ${zone} is insecure (${verdict.detail})`,
        });
        break;
      }
      if (verdict.kind === "nxdomain") {
        // Zone does not exist at all — and therefore qname below it can't either.
        return respond(qname, qtype, steps, "secure-nxdomain", `NXDOMAIN proven at ${zone}: ${verdict.detail}`);
      }
      return fail(qname, qtype, steps, `denial at ${zone}/DS did not prove NODATA/NXDOMAIN: ${verdict.detail}`);
    }
  }

  // ---- Step 3: leaf query ----
  const leaf = await resolver.query(qname, qtype);
  const ansRRs = leaf.message.answers.filter((r) => r.type === qtype && canonicalName(r.name) === qcanon);
  const ansSigs = leaf.message.answers.filter((r) => r.type === TYPE.RRSIG && canonicalName(r.name) === qcanon);

  if (insecureAt && isSubdomainOrEqual(qcanon, insecureAt)) {
    return respond(qname, qtype, steps, "insecure", `insecure delegation at ${insecureAt}; qname is below it`);
  }

  const signingZone = closestZone(qcanon, keys);
  if (ansRRs.length > 0) {
    const signingKeys = keys.get(signingZone);
    if (!signingKeys) return fail(qname, qtype, steps, `no validated DNSKEYs for signing zone ${signingZone}`);
    const ver = await verifyRRSIGOverRRset(
      ansRRs,
      ansSigs.filter((r) => parseRRSIG(r).typeCovered === qtype),
      signingKeys,
      at,
    );
    if (!ver.ok) return fail(qname, qtype, steps, `answer RRSIG: ${ver.detail}`);
    steps.push({
      kind: "answer",
      qname: qcanon,
      qtype: typeName(qtype),
      ok: true,
      detail: `RRSIG verified; ${ansRRs.length} ${typeName(qtype)} record(s)`,
    });
    return respond(qname, qtype, steps, "secure-positive", `answer RRset signed by ${signingZone}`);
  }

  // Denial — NSEC or NSEC3 in authority, signed by signing zone's keys
  const ns = leaf.message.authorities.filter((r) => r.type === TYPE.NSEC);
  const ns3 = leaf.message.authorities.filter((r) => r.type === TYPE.NSEC3);
  const nsSigs = leaf.message.authorities.filter((r) => r.type === TYPE.RRSIG);
  if (ns.length === 0 && ns3.length === 0) {
    return fail(qname, qtype, steps, `empty answer and no NSEC/NSEC3 in authority`);
  }
  const signingKeys = keys.get(signingZone);
  if (!signingKeys) return fail(qname, qtype, steps, `no validated DNSKEYs for ${signingZone}`);
  const denialRRs = ns.length > 0 ? ns : ns3;
  const denialType = ns.length > 0 ? TYPE.NSEC : TYPE.NSEC3;
  const denialSigs = nsSigs.filter((r) => parseRRSIG(r).typeCovered === denialType);
  const ver = await verifyRRSIGsGrouped(denialRRs, denialSigs, signingKeys, at);
  if (!ver.ok) return fail(qname, qtype, steps, `denial RRSIG: ${ver.detail}`);
  const verdict: DenialVerdict = ns.length > 0
    ? nsecDenial(qname, qtype, ns)
    : await nsec3Denial(qname, qtype, ns3);
  steps.push({
    kind: "denial",
    qname: qcanon,
    qtype: typeName(qtype),
    ok: verdict.kind === "nodata" || verdict.kind === "nxdomain",
    detail: `${verdict.kind}: ${verdict.detail}`,
  });
  if (verdict.kind === "nodata") return respond(qname, qtype, steps, "secure-nodata", verdict.detail);
  if (verdict.kind === "nxdomain") return respond(qname, qtype, steps, "secure-nxdomain", verdict.detail);
  if (verdict.kind === "insecure-delegation") return respond(qname, qtype, steps, "insecure", verdict.detail);
  return fail(qname, qtype, steps, verdict.detail);
}

// ----- helpers -----

function parentOf(zone: string): string {
  const c = canonicalName(zone);
  if (c === ".") return ".";
  const idx = c.indexOf(".");
  const rest = c.slice(idx + 1);
  return rest === "" ? "." : rest;
}

function closestZone(qname: string, keys: ValidatedKeys): string {
  let best = ".";
  const qn = canonicalName(qname);
  for (const z of keys.keys()) {
    if (isSubdomainOrEqual(qn, z) && z.length > best.length) best = z;
  }
  return best;
}

function isSubdomainOrEqual(sub: string, parent: string): boolean {
  const s = canonicalName(sub);
  const p = canonicalName(parent);
  if (p === ".") return true;
  if (s === p) return true;
  return s.endsWith("." + p);
}

// Verify each RRset (grouped by owner) against its covering RRSIG(s).
// Returns ok iff every distinct owner-group has at least one valid RRSIG.
async function verifyRRSIGsGrouped(
  rrs: RR[],
  rrsigs: RR[],
  candidateKeys: RR[],
  at: Date,
): Promise<{ ok: boolean; detail: string }> {
  if (rrs.length === 0) return { ok: false, detail: "empty RRset" };
  const groups = new Map<string, RR[]>();
  for (const r of rrs) {
    const k = canonicalName(r.name);
    const arr = groups.get(k);
    if (arr) arr.push(r);
    else groups.set(k, [r]);
  }
  const details: string[] = [];
  for (const [owner, set] of groups) {
    const ownerSigs = rrsigs.filter((r) => canonicalName(r.name) === owner);
    const r = await verifyRRSIGOverRRset(set, ownerSigs, candidateKeys, at);
    if (!r.ok) return { ok: false, detail: `${owner}: ${r.detail}` };
    details.push(`${owner}: ${r.detail}`);
  }
  return { ok: true, detail: details.join(" | ") };
}

async function verifyRRSIGOverRRset(
  rrset: RR[],
  rrsigs: RR[],
  candidateKeys: RR[],
  at: Date,
): Promise<{ ok: boolean; detail: string }> {
  if (rrset.length === 0) return { ok: false, detail: "empty RRset" };
  if (rrsigs.length === 0) return { ok: false, detail: "no RRSIGs covering this RRset" };
  const prepared = prepareRRset(rrset);
  const now = Math.floor(at.getTime() / 1000);

  const reasons: string[] = [];
  for (const sigRR of rrsigs) {
    const rsig = parseRRSIG(sigRR);
    if (rsig.typeCovered !== prepared.type) continue;
    if (canonicalName(rsig.signerName) !== closestSignerFor(prepared.ownerCanonical, candidateKeys)) {
      // Allow any candidate key's owner to match
    }
    if (now < rsig.signatureInception) {
      reasons.push(`RRSIG not yet valid (inception=${rsig.signatureInception} > now=${now})`);
      continue;
    }
    if (now > rsig.signatureExpiration) {
      reasons.push(`RRSIG expired (expiration=${rsig.signatureExpiration} < now=${now})`);
      continue;
    }
    if (!isAlgoSupported(rsig.algorithm)) {
      reasons.push(`unsupported algorithm ${algoName(rsig.algorithm)}`);
      continue;
    }
    // find a candidate key matching keyTag + algorithm, whose owner == signer name
    const match = candidateKeys.find((k) => {
      if (canonicalName(k.name) !== canonicalName(rsig.signerName)) return false;
      if (computeKeyTag(k) !== rsig.keyTag) return false;
      const pk = parseDNSKEY(k);
      return pk.algorithm === rsig.algorithm;
    });
    if (!match) {
      reasons.push(`no DNSKEY matched RRSIG keyTag=${rsig.keyTag} alg=${rsig.algorithm} signer=${rsig.signerName}`);
      continue;
    }
    const pk = parseDNSKEY(match);
    const signed = buildSigningInput(rsig, sigRR, prepared);
    let ok = false;
    try {
      ok = await verifySignature(rsig.algorithm, pk.publicKey, rsig.signature, signed);
    } catch (e) {
      reasons.push(`crypto error: ${(e as Error).message}`);
      continue;
    }
    if (ok) return { ok: true, detail: `verified with keyTag=${rsig.keyTag} alg=${algoName(rsig.algorithm)}` };
    reasons.push(`signature mismatch for keyTag=${rsig.keyTag}`);
  }
  return { ok: false, detail: reasons.join("; ") || "no applicable RRSIG" };
}

function closestSignerFor(_owner: string, _keys: RR[]): string {
  return ""; // placeholder; we don't currently filter by signer in this helper
}

function respond(
  qname: string,
  qtype: number,
  steps: WalkStep[],
  verdict: WalkResult["verdict"],
  detail: string,
): WalkResult {
  return { qname, qtype, verdict, detail, steps };
}

function fail(qname: string, qtype: number, steps: WalkStep[], detail: string): WalkResult {
  steps.push({ kind: "note", ok: false, detail });
  return { qname, qtype, verdict: "bogus", detail, steps };
}

export function formatHex(b: Uint8Array): string {
  return bytesToHex(b);
}
