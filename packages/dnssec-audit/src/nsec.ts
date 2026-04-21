import {
  type RR,
  type NSEC_RD,
  type NSEC3_RD,
  TYPE,
  encodeName,
  canonicalName,
  nameLabels,
  parseNSEC,
  parseNSEC3,
  typeBitmapHas,
} from "./wire.ts";
import { sha1 } from "./crypto.ts";
import { base32HexEncode, base32HexDecode, concat, bytesEqual } from "./util.ts";

// ----- canonical name comparison (RFC 4034 §6.1) -----

export function compareCanonicalNames(a: string, b: string): number {
  const la = nameLabels(canonicalName(a)).reverse();
  const lb = nameLabels(canonicalName(b)).reverse();
  const n = Math.min(la.length, lb.length);
  for (let i = 0; i < n; i++) {
    if (la[i] < lb[i]) return -1;
    if (la[i] > lb[i]) return 1;
  }
  return la.length - lb.length;
}

// NSEC "covers" qname iff qname lies strictly between the NSEC owner (exclusive)
// and the next-name (exclusive), in canonical order. For the zone-apex wraparound,
// next-name <= owner; the range wraps.
export function nsecCovers(ownerName: string, nextName: string, qname: string): boolean {
  const o = canonicalName(ownerName);
  const n = canonicalName(nextName);
  const q = canonicalName(qname);
  const cmpON = compareCanonicalNames(o, n);
  const cmpOQ = compareCanonicalNames(o, q);
  const cmpQN = compareCanonicalNames(q, n);
  if (cmpON < 0) {
    return cmpOQ < 0 && cmpQN < 0;
  }
  // wraparound at apex
  return cmpOQ < 0 || cmpQN < 0;
}

// ----- NSEC denial -----

export type DenialVerdict =
  | { kind: "nodata"; detail: string }
  | { kind: "nxdomain"; detail: string }
  | { kind: "insecure-delegation"; detail: string }
  | { kind: "fail"; detail: string };

export function nsecDenial(
  qname: string,
  qtype: number,
  nsecRRs: RR[],
): DenialVerdict {
  const q = canonicalName(qname);

  // NODATA: exact match, qtype not in bitmap
  for (const rr of nsecRRs) {
    if (canonicalName(rr.name) === q) {
      const rd = parseNSEC(rr);
      if (typeBitmapHas(rd.typeBitmap, qtype)) {
        return { kind: "fail", detail: `NSEC at ${rr.name} shows type ${qtype} present but answer was empty` };
      }
      return { kind: "nodata", detail: `NSEC at ${rr.name}: type ${qtype} absent from bitmap` };
    }
  }

  // NXDOMAIN: one NSEC covers qname (proves no such name) AND one covers the wildcard
  let coversName = false;
  let coversWildcard = false;
  let coverName = "";
  let coverWc = "";
  // Determine closest encloser: longest ancestor of qname whose name matches an NSEC owner,
  // or we can fall back to finding any NSEC whose owner is an ancestor.
  // For NSEC, the wildcard name to deny is "*.<closest-encloser>".
  // A simple approach: among NSECs that cover qname, the closest encloser is the
  // longest common ancestor; for wildcard denial we check for an NSEC covering
  // "*.<closest-encloser>".
  const ancestors: string[] = [];
  {
    const labels = nameLabels(q);
    for (let i = 0; i <= labels.length; i++) {
      ancestors.push(labels.slice(i).join(".") + (labels.length - i > 0 ? "." : ""));
    }
  }

  for (const rr of nsecRRs) {
    const rd = parseNSEC(rr);
    if (nsecCovers(rr.name, rd.nextName, q)) {
      coversName = true;
      coverName = rr.name;
      // Closest encloser is the longest ancestor of q that is also >= owner in canonical order.
      // Simpler: for NXDOMAIN, try each ancestor as potential closest encloser.
      for (const anc of ancestors) {
        const wc = "*." + (anc === "." ? "" : anc);
        const wcName = wc.endsWith(".") ? wc : wc + ".";
        for (const rr2 of nsecRRs) {
          const rd2 = parseNSEC(rr2);
          if (nsecCovers(rr2.name, rd2.nextName, wcName) ||
              canonicalName(rr2.name) === canonicalName(wcName)) {
            if (canonicalName(rr2.name) === canonicalName(wcName)) {
              // exact wildcard: must show qtype not in bitmap
              if (typeBitmapHas(rd2.typeBitmap, qtype)) continue;
            }
            coversWildcard = true;
            coverWc = rr2.name;
            break;
          }
        }
        if (coversWildcard) break;
      }
    }
  }
  if (coversName && coversWildcard) {
    return { kind: "nxdomain", detail: `NSEC covers ${q} via ${coverName}; wildcard denied via ${coverWc}` };
  }
  if (coversName) {
    return { kind: "fail", detail: `NSEC covers name but wildcard not denied` };
  }
  return { kind: "fail", detail: "NSEC records do not prove NODATA or NXDOMAIN" };
}

// ----- NSEC3 -----

export async function nsec3Hash(
  name: string,
  hashAlgorithm: number,
  iterations: number,
  salt: Uint8Array,
): Promise<Uint8Array> {
  if (hashAlgorithm !== 1) throw new Error(`unsupported NSEC3 hash algo ${hashAlgorithm}`);
  let buf = encodeName(canonicalName(name));
  let h = await sha1(concat(buf, salt));
  for (let i = 0; i < iterations; i++) {
    h = await sha1(concat(h, salt));
  }
  return h;
}

// NSEC3 owner-name = base32hex(hash).<zone>
function nsec3OwnerHash(ownerName: string): Uint8Array {
  const first = ownerName.split(".")[0];
  return base32HexDecode(first.toLowerCase());
}

function nsec3Zone(ownerName: string): string {
  const idx = ownerName.indexOf(".");
  const rest = ownerName.slice(idx + 1);
  return rest.endsWith(".") ? rest : rest + ".";
}

// Does NSEC3 hash-range (owner_hash, next_hash] cover `targetHash`?
// Ranges are strict-lower, strict-upper in the hash ring (per RFC 5155).
function nsec3Covers(ownerHash: Uint8Array, nextHash: Uint8Array, targetHash: Uint8Array): boolean {
  const cmp = (a: Uint8Array, b: Uint8Array) => {
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return 0;
  };
  const cmpON = cmp(ownerHash, nextHash);
  const cmpOT = cmp(ownerHash, targetHash);
  const cmpTN = cmp(targetHash, nextHash);
  if (cmpON < 0) return cmpOT < 0 && cmpTN < 0;
  // wraparound
  return cmpOT < 0 || cmpTN < 0;
}

export async function nsec3Denial(
  qname: string,
  qtype: number,
  nsec3RRs: RR[],
): Promise<DenialVerdict> {
  if (nsec3RRs.length === 0) return { kind: "fail", detail: "no NSEC3 records" };
  const first = parseNSEC3(nsec3RRs[0]);
  const salt = first.salt;
  const iters = first.iterations;
  const algo = first.hashAlgorithm;
  const zone = nsec3Zone(nsec3RRs[0].name);

  // Precompute (ownerHash, nextHash, rd) for each NSEC3
  const entries = nsec3RRs.map((rr) => {
    const rd = parseNSEC3(rr);
    return { rr, rd, ownerHash: nsec3OwnerHash(rr.name) };
  });

  // Consistency
  for (const e of entries) {
    if (e.rd.hashAlgorithm !== algo || e.rd.iterations !== iters || !bytesEqual(e.rd.salt, salt)) {
      return { kind: "fail", detail: `NSEC3 parameter mismatch among records` };
    }
  }

  // NODATA (exact match): hash(qname) matches an NSEC3 owner-hash, and qtype not in bitmap
  const qHash = await nsec3Hash(qname, algo, iters, salt);
  for (const e of entries) {
    if (bytesEqual(e.ownerHash, qHash)) {
      if (typeBitmapHas(e.rd.typeBitmap, qtype)) {
        return { kind: "fail", detail: `NSEC3 exact-match shows type ${qtype} present` };
      }
      // Special case: if qtype is DS and opt-out bit set and it's a delegation point,
      // this proves insecure delegation (handled at walker level too).
      return { kind: "nodata", detail: `NSEC3 exact match at hash ${base32HexEncode(qHash)}, type ${qtype} absent` };
    }
  }

  // NXDOMAIN: closest encloser proof
  // Find longest ancestor of qname whose hash matches some NSEC3 owner-hash (in the same zone)
  const labels = nameLabels(qname);
  let closestEncloser: string | null = null;
  let nextCloser: string | null = null;
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join(".") + ".";
    // Ensure it's inside the NSEC3 zone
    if (!canonicalName(candidate).endsWith(canonicalName(zone))) continue;
    const h = await nsec3Hash(candidate, algo, iters, salt);
    const matched = entries.find((e) => bytesEqual(e.ownerHash, h));
    if (matched) {
      closestEncloser = candidate;
      nextCloser = i === 0 ? null : labels.slice(i - 1).join(".") + ".";
      break;
    }
  }
  if (!closestEncloser) {
    return { kind: "fail", detail: "no closest encloser found in NSEC3 set" };
  }
  if (!nextCloser) {
    // qname == closestEncloser; this is actually an exact-match NODATA handled above.
    return { kind: "fail", detail: "qname == closest encloser without NODATA proof" };
  }

  // Covering NSEC3 for next-closer name
  const ncHash = await nsec3Hash(nextCloser, algo, iters, salt);
  const coveringNC = entries.find((e) => nsec3Covers(e.ownerHash, e.rd.nextHashedOwner, ncHash));
  if (!coveringNC) {
    return { kind: "fail", detail: "no NSEC3 covers next-closer name" };
  }

  // Wildcard proof: hash "*.<closest-encloser>"
  const wc = "*." + (closestEncloser === "." ? "" : closestEncloser);
  const wcName = wc.endsWith(".") ? wc : wc + ".";
  const wcHash = await nsec3Hash(wcName, algo, iters, salt);
  // Either an exact-match NSEC3 for the wildcard (NODATA-at-wildcard) or a covering one (NXDOMAIN)
  const exactWc = entries.find((e) => bytesEqual(e.ownerHash, wcHash));
  if (exactWc) {
    if (typeBitmapHas(exactWc.rd.typeBitmap, qtype)) {
      return { kind: "fail", detail: `wildcard ${wcName} has type ${qtype} in bitmap` };
    }
    return {
      kind: "nodata",
      detail: `NSEC3 wildcard NODATA: closest-encloser=${closestEncloser}, wildcard=${wcName}`,
    };
  }
  const coveringWc = entries.find((e) => nsec3Covers(e.ownerHash, e.rd.nextHashedOwner, wcHash));
  if (!coveringWc) {
    // With opt-out, covering next-closer alone can be "insecure" for a delegation point,
    // but without a wildcard proof we can't assert NXDOMAIN. If opt-out is set on the
    // covering-NC NSEC3, treat this as insecure delegation instead of a hard failure
    // when qtype is DS.
    if (qtype === TYPE.DS && coveringNC.rd.optOut) {
      return {
        kind: "insecure-delegation",
        detail: `NSEC3 opt-out: no DS, delegation to ${qname} is unsigned`,
      };
    }
    return { kind: "fail", detail: "no NSEC3 covers or matches the wildcard name" };
  }
  return {
    kind: "nxdomain",
    detail: `NSEC3 NXDOMAIN: closest-encloser=${closestEncloser}, next-closer=${nextCloser}, wildcard=${wcName}`,
  };
}
