import {
  type RR,
  type RRSIG_RD,
  TYPE,
  decodeName,
  encodeName,
  canonicalName,
} from "./wire.ts";
import { concat } from "./util.ts";

// RFC 4034 §6.2 — canonical RDATA form for RR types with embedded names.
// For types we verify RRSIGs over (DNSKEY, DS, NSEC, NSEC3, SOA, A, AAAA, RRSIG),
// only NSEC and SOA contain embedded domain names inside RDATA.
function canonicalRdata(rr: RR): Uint8Array {
  const msg = rr._msg;
  const start = rr._rdataOffset;
  const end = start + rr.rdata.length;

  switch (rr.type) {
    case TYPE.NSEC: {
      const { name, next } = decodeName(msg, start);
      const lcName = encodeName(canonicalName(name));
      const bitmap = msg.slice(next, end);
      return concat(lcName, bitmap);
    }
    case TYPE.SOA: {
      const { name: mname, next: n1 } = decodeName(msg, start);
      const { name: rname, next: n2 } = decodeName(msg, n1);
      const lcMname = encodeName(canonicalName(mname));
      const lcRname = encodeName(canonicalName(rname));
      const tail = msg.slice(n2, end);
      return concat(lcMname, lcRname, tail);
    }
    // DNSKEY, DS, NSEC3, A, AAAA, RRSIG have no compressible embedded names
    // (RRSIG's signer name is only used when signing RRSIGs, which DNSSEC doesn't do).
    default: {
      // Return a defensive copy — the original rdata slice is already uncompressed
      // for our supported types.
      return new Uint8Array(rr.rdata);
    }
  }
}

// RFC 4034 §6.3 — canonical RR ordering: sort by canonical RDATA byte-wise ascending.
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export interface PreparedRRset {
  ownerCanonical: string; // lower-cased fqdn with trailing dot
  type: number;
  class: number;
  records: { rr: RR; canonRdata: Uint8Array }[];
}

export function prepareRRset(rrs: RR[]): PreparedRRset {
  if (rrs.length === 0) throw new Error("empty RRset");
  const first = rrs[0];
  const owner = canonicalName(first.name);
  for (const r of rrs) {
    if (canonicalName(r.name) !== owner) throw new Error("mixed owners in RRset");
    if (r.type !== first.type) throw new Error("mixed types in RRset");
    if (r.class !== first.class) throw new Error("mixed classes in RRset");
  }
  const records = rrs.map((rr) => ({ rr, canonRdata: canonicalRdata(rr) }));
  records.sort((a, b) => compareBytes(a.canonRdata, b.canonRdata));
  return { ownerCanonical: owner, type: first.type, class: first.class, records };
}

// Build the signing input per RFC 4034 §3.1.8.1:
//   signature = sign( RRSIG_RDATA_minus_signature || RR(1) || RR(2) ... )
// where RRSIG_RDATA_minus_signature has the signer name in canonical form,
// and each RR is:
//   owner_canonical | type(2) | class(2) | originalTTL(4) | RDLENGTH(2) | canonical_RDATA
// Wildcard expansion (when rrsig.labels < owner label count) replaces the
// leading labels with "*".
export function buildSigningInput(
  rrsig: RRSIG_RD,
  rrsigRR: RR,
  rrset: PreparedRRset,
): Uint8Array {
  // RRSIG_RDATA without signature, signer name canonicalized
  const msg = rrsigRR._msg;
  const rdStart = rrsigRR._rdataOffset;
  const head = msg.slice(rdStart, rdStart + 18); // up through keyTag
  const canonSigner = encodeName(canonicalName(rrsig.signerName));
  const rrsigRdataMinusSig = concat(head, canonSigner);

  // Owner label count for wildcard handling
  const ownerLabels = rrset.ownerCanonical === "." ? [] : rrset.ownerCanonical.replace(/\.$/, "").split(".");
  let ownerWire: Uint8Array;
  if (rrsig.labels < ownerLabels.length) {
    // Wildcard: owner label count = rrsig.labels; prepend "*" label
    const kept = ownerLabels.slice(ownerLabels.length - rrsig.labels);
    ownerWire = encodeName("*." + kept.join("."));
  } else {
    ownerWire = encodeName(rrset.ownerCanonical);
  }

  const rrWires: Uint8Array[] = [];
  for (const { canonRdata } of rrset.records) {
    const hdr = new Uint8Array(10);
    const dv = new DataView(hdr.buffer);
    dv.setUint16(0, rrset.type);
    dv.setUint16(2, rrset.class);
    dv.setUint32(4, rrsig.originalTTL);
    dv.setUint16(8, canonRdata.length);
    rrWires.push(ownerWire, hdr, canonRdata);
  }
  return concat(rrsigRdataMinusSig, ...rrWires);
}
