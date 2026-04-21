import { concat } from "./util.ts";

export const TYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  OPT: 41,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  NSEC3PARAM: 51,
} as const;

export function typeName(t: number): string {
  for (const [k, v] of Object.entries(TYPE)) if (v === t) return k;
  return `TYPE${t}`;
}

export function typeFromName(s: string): number {
  const up = s.toUpperCase();
  const v = (TYPE as Record<string, number>)[up];
  if (v != null) return v;
  const m = /^TYPE(\d+)$/i.exec(s);
  if (m) return parseInt(m[1], 10);
  throw new Error(`unknown RR type: ${s}`);
}

export interface Question {
  name: string;
  type: number;
  class: number;
}

export interface RR {
  name: string;
  type: number;
  class: number;
  ttl: number;
  rdata: Uint8Array;
  // Reference to the full message + absolute offset of rdata within it, so
  // we can resolve compression pointers inside rdata when canonicalizing.
  _msg: Uint8Array;
  _rdataOffset: number;
}

export interface DNSMessage {
  id: number;
  flags: number;
  rcode: number;
  questions: Question[];
  answers: RR[];
  authorities: RR[];
  additionals: RR[];
  raw: Uint8Array;
}

// ------- name codec --------

export function encodeName(name: string): Uint8Array {
  if (name === "" || name === ".") return new Uint8Array([0]);
  const trimmed = name.replace(/\.$/, "");
  const labels = trimmed.split(".");
  const parts: number[] = [];
  const enc = new TextEncoder();
  for (const label of labels) {
    const b = enc.encode(label);
    if (b.length === 0) throw new Error(`empty label in "${name}"`);
    if (b.length > 63) throw new Error(`label too long: ${label}`);
    parts.push(b.length);
    for (const x of b) parts.push(x);
  }
  parts.push(0);
  return new Uint8Array(parts);
}

export function decodeName(buf: Uint8Array, offset: number): { name: string; next: number } {
  const labels: string[] = [];
  let o = offset;
  let jumped = false;
  let endOffset = offset;
  const dec = new TextDecoder();
  const seen = new Set<number>();
  while (true) {
    if (o >= buf.length) throw new Error("name truncated");
    const len = buf[o];
    if (len === 0) {
      o++;
      if (!jumped) endOffset = o;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (o + 1 >= buf.length) throw new Error("pointer truncated");
      const ptr = ((len & 0x3f) << 8) | buf[o + 1];
      if (!jumped) endOffset = o + 2;
      if (seen.has(ptr)) throw new Error("name pointer loop");
      seen.add(ptr);
      o = ptr;
      jumped = true;
      continue;
    }
    if ((len & 0xc0) !== 0) throw new Error("invalid label prefix");
    o++;
    if (o + len > buf.length) throw new Error("label truncated");
    labels.push(dec.decode(buf.slice(o, o + len)));
    o += len;
  }
  const name = labels.length === 0 ? "." : labels.join(".") + ".";
  return { name, next: endOffset };
}

// ------- message codec --------

export function encodeQuery(opts: {
  id?: number;
  qname: string;
  qtype: number;
  doBit?: boolean;
  cdBit?: boolean;
  rd?: boolean;
}): Uint8Array {
  const id = opts.id ?? Math.floor(Math.random() * 0x10000);
  const rd = opts.rd ?? true;
  const cd = opts.cdBit ?? true;
  const doBit = opts.doBit ?? true;
  const flags = (rd ? 0x0100 : 0) | (cd ? 0x0010 : 0);

  const header = new Uint8Array(12);
  const dv = new DataView(header.buffer);
  dv.setUint16(0, id);
  dv.setUint16(2, flags);
  dv.setUint16(4, 1); // QDCOUNT
  dv.setUint16(6, 0);
  dv.setUint16(8, 0);
  dv.setUint16(10, 1); // ARCOUNT (OPT)

  const qname = encodeName(opts.qname);
  const qtail = new Uint8Array(4);
  const qdv = new DataView(qtail.buffer);
  qdv.setUint16(0, opts.qtype);
  qdv.setUint16(2, 1); // class IN

  // OPT RR for EDNS0 with DO bit
  const opt = new Uint8Array(11);
  opt[0] = 0; // root
  const odv = new DataView(opt.buffer);
  odv.setUint16(1, 41); // TYPE=OPT
  odv.setUint16(3, 4096); // UDP payload size
  // TTL: extRCODE(1) | version(1) | DO-flag bit 15 of flags(2)
  opt[5] = 0;
  opt[6] = 0;
  opt[7] = doBit ? 0x80 : 0;
  opt[8] = 0;
  odv.setUint16(9, 0); // RDLEN

  return concat(header, qname, qtail, opt);
}

export function decodeMessage(buf: Uint8Array): DNSMessage {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const id = dv.getUint16(0);
  const flags = dv.getUint16(2);
  const rcode = flags & 0x000f;
  const qd = dv.getUint16(4);
  const an = dv.getUint16(6);
  const ns = dv.getUint16(8);
  const ar = dv.getUint16(10);
  let o = 12;
  const questions: Question[] = [];
  for (let i = 0; i < qd; i++) {
    const { name, next } = decodeName(buf, o);
    o = next;
    const type = dv.getUint16(o);
    o += 2;
    const cls = dv.getUint16(o);
    o += 2;
    questions.push({ name, type, class: cls });
  }
  const readRR = (): RR => {
    const { name, next } = decodeName(buf, o);
    o = next;
    const type = dv.getUint16(o);
    o += 2;
    const cls = dv.getUint16(o);
    o += 2;
    const ttl = dv.getUint32(o);
    o += 4;
    const rdlen = dv.getUint16(o);
    o += 2;
    const rdataOffset = o;
    const rdata = buf.slice(o, o + rdlen);
    o += rdlen;
    return { name, type, class: cls, ttl, rdata, _msg: buf, _rdataOffset: rdataOffset };
  };
  const answers = Array.from({ length: an }, readRR);
  const authorities = Array.from({ length: ns }, readRR);
  const additionals = Array.from({ length: ar }, readRR);
  return { id, flags, rcode, questions, answers, authorities, additionals, raw: buf };
}

// ------- RDATA parsers --------

export interface DNSKEY_RD {
  flags: number;
  protocol: number;
  algorithm: number;
  publicKey: Uint8Array;
  isKSK: boolean;
  isZSK: boolean;
}
export interface DS_RD {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: Uint8Array;
}
export interface RRSIG_RD {
  typeCovered: number;
  algorithm: number;
  labels: number;
  originalTTL: number;
  signatureExpiration: number;
  signatureInception: number;
  keyTag: number;
  signerName: string;
  signature: Uint8Array;
  // bytes from the start of rdata through the end of the signer name (canonicalized on demand)
  // stored here as absolute offsets so canonicalization can re-encode signer name
  signerNameRdataEndOffset: number; // offset within rdata where signer name ends
}
export interface NSEC_RD {
  nextName: string;
  typeBitmap: Uint8Array;
}
export interface NSEC3_RD {
  hashAlgorithm: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
  nextHashedOwner: Uint8Array;
  typeBitmap: Uint8Array;
  optOut: boolean;
}
export interface SOA_RD {
  mname: string;
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
}

export function parseDNSKEY(rr: RR): DNSKEY_RD {
  const r = rr.rdata;
  const dv = new DataView(r.buffer, r.byteOffset, r.byteLength);
  const flags = dv.getUint16(0);
  return {
    flags,
    protocol: r[2],
    algorithm: r[3],
    publicKey: r.slice(4),
    isKSK: (flags & 0x0001) === 1 && (flags & 0x0100) !== 0,
    isZSK: (flags & 0x0001) === 0 && (flags & 0x0100) !== 0,
  };
}

export function parseDS(rr: RR): DS_RD {
  const r = rr.rdata;
  const dv = new DataView(r.buffer, r.byteOffset, r.byteLength);
  return {
    keyTag: dv.getUint16(0),
    algorithm: r[2],
    digestType: r[3],
    digest: r.slice(4),
  };
}

export function parseRRSIG(rr: RR): RRSIG_RD {
  // Signer name may be compressed — use full message to decode
  const msg = rr._msg;
  const start = rr._rdataOffset;
  const dv = new DataView(msg.buffer, msg.byteOffset + start, 18);
  const typeCovered = dv.getUint16(0);
  const algorithm = msg[start + 2];
  const labels = msg[start + 3];
  const originalTTL = dv.getUint32(4);
  const signatureExpiration = dv.getUint32(8);
  const signatureInception = dv.getUint32(12);
  const keyTag = dv.getUint16(16);
  const { name: signerName, next } = decodeName(msg, start + 18);
  // The signature bytes are everything after the signer name, up to end of rdata.
  const rdataEnd = start + rr.rdata.length;
  const signature = msg.slice(next, rdataEnd);
  const signerNameRdataEndOffset = next - start;
  return {
    typeCovered,
    algorithm,
    labels,
    originalTTL,
    signatureExpiration,
    signatureInception,
    keyTag,
    signerName,
    signature,
    signerNameRdataEndOffset,
  };
}

export function parseNSEC(rr: RR): NSEC_RD {
  const { name, next } = decodeName(rr._msg, rr._rdataOffset);
  const rdataEnd = rr._rdataOffset + rr.rdata.length;
  const typeBitmap = rr._msg.slice(next, rdataEnd);
  return { nextName: name, typeBitmap };
}

export function parseNSEC3(rr: RR): NSEC3_RD {
  const r = rr.rdata;
  const dv = new DataView(r.buffer, r.byteOffset, r.byteLength);
  const hashAlgorithm = r[0];
  const flags = r[1];
  const iterations = dv.getUint16(2);
  const saltLength = r[4];
  const salt = r.slice(5, 5 + saltLength);
  const hashLength = r[5 + saltLength];
  const nextHashedOwner = r.slice(6 + saltLength, 6 + saltLength + hashLength);
  const typeBitmap = r.slice(6 + saltLength + hashLength);
  return {
    hashAlgorithm,
    flags,
    iterations,
    salt,
    nextHashedOwner,
    typeBitmap,
    optOut: (flags & 0x01) !== 0,
  };
}

export function parseSOA(rr: RR): SOA_RD {
  const msg = rr._msg;
  const start = rr._rdataOffset;
  const { name: mname, next: after1 } = decodeName(msg, start);
  const { name: rname, next: after2 } = decodeName(msg, after1);
  const dv = new DataView(msg.buffer, msg.byteOffset + after2, 20);
  return {
    mname,
    rname,
    serial: dv.getUint32(0),
    refresh: dv.getUint32(4),
    retry: dv.getUint32(8),
    expire: dv.getUint32(12),
    minimum: dv.getUint32(16),
  };
}

// ------- type bitmap --------

export function typeBitmapHas(bitmap: Uint8Array, type: number): boolean {
  let o = 0;
  const wantedWindow = (type >> 8) & 0xff;
  while (o < bitmap.length) {
    if (o + 2 > bitmap.length) return false;
    const window = bitmap[o];
    const len = bitmap[o + 1];
    if (o + 2 + len > bitmap.length) return false;
    if (window === wantedWindow) {
      const bitInWindow = type & 0xff;
      const byteIdx = bitInWindow >> 3;
      if (byteIdx < len) {
        const bit = 7 - (bitInWindow & 7);
        return (bitmap[o + 2 + byteIdx] & (1 << bit)) !== 0;
      }
      return false;
    }
    o += 2 + len;
  }
  return false;
}

export function typeBitmapList(bitmap: Uint8Array): number[] {
  const out: number[] = [];
  let o = 0;
  while (o < bitmap.length) {
    if (o + 2 > bitmap.length) break;
    const window = bitmap[o];
    const len = bitmap[o + 1];
    for (let i = 0; i < len; i++) {
      const byte = bitmap[o + 2 + i];
      for (let bit = 0; bit < 8; bit++) {
        if (byte & (1 << (7 - bit))) out.push((window << 8) | (i * 8 + bit));
      }
    }
    o += 2 + len;
  }
  return out;
}

// ------- key tag (RFC 4034 App. B) --------

export function computeKeyTag(dnskey: RR): number {
  const r = dnskey.rdata;
  // Algorithm 1 (RSAMD5) uses a different formula; we don't support it.
  let sum = 0;
  for (let i = 0; i < r.length; i++) {
    sum += i & 1 ? r[i] : r[i] << 8;
  }
  sum += (sum >> 16) & 0xffff;
  return sum & 0xffff;
}

// ------- name utilities --------

export function nameLabels(name: string): string[] {
  if (name === "." || name === "") return [];
  return name.replace(/\.$/, "").split(".");
}

export function canonicalName(name: string): string {
  if (name === "" || name === ".") return ".";
  return name.toLowerCase().replace(/\.?$/, ".");
}

export function nameEquals(a: string, b: string): boolean {
  return canonicalName(a) === canonicalName(b);
}

export function isSubdomainOrEqual(sub: string, parent: string): boolean {
  const s = canonicalName(sub);
  const p = canonicalName(parent);
  if (s === p) return true;
  return s.endsWith("." + p) || p === ".";
}
