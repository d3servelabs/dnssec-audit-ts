import { bytesToBase64Url } from "./util.ts";

// DNSSEC algorithm numbers (IANA)
export const ALGO = {
  RSASHA1: 5,
  RSASHA256: 8,
  RSASHA512: 10,
  ECDSAP256SHA256: 13,
  ECDSAP384SHA384: 14,
  ED25519: 15,
  ED448: 16,
} as const;

export function algoName(a: number): string {
  for (const [k, v] of Object.entries(ALGO)) if (v === a) return k;
  return `ALGO${a}`;
}

// Supported algos in this implementation
const SUPPORTED = new Set<number>([
  ALGO.RSASHA256,
  ALGO.RSASHA512,
  ALGO.ECDSAP256SHA256,
  ALGO.ECDSAP384SHA384,
  ALGO.ED25519,
]);

export function isAlgoSupported(a: number): boolean {
  return SUPPORTED.has(a);
}

// RFC 3110: RSA public key in DNSKEY rdata is:
//   exp_len(1)  if nonzero => exponent is exp_len bytes
//   if exp_len == 0: next 2 bytes (big-endian) are the exponent length
//   then exponent bytes
//   then modulus bytes (rest)
function parseRSAPubkey(pub: Uint8Array): { n: Uint8Array; e: Uint8Array } {
  let o = 0;
  let expLen = pub[o++];
  if (expLen === 0) {
    expLen = (pub[o] << 8) | pub[o + 1];
    o += 2;
  }
  const e = pub.slice(o, o + expLen);
  const n = pub.slice(o + expLen);
  return { n, e };
}

async function importRSAKey(pub: Uint8Array, hash: "SHA-256" | "SHA-512"): Promise<CryptoKey> {
  const { n, e } = parseRSAPubkey(pub);
  const jwk: JsonWebKey = {
    kty: "RSA",
    n: bytesToBase64Url(n),
    e: bytesToBase64Url(e),
    alg: hash === "SHA-256" ? "RS256" : "RS512",
    ext: true,
  };
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash },
    false,
    ["verify"],
  );
}

async function importECDSAKey(
  pub: Uint8Array,
  namedCurve: "P-256" | "P-384",
): Promise<CryptoKey> {
  const half = pub.length / 2;
  if (pub.length !== (namedCurve === "P-256" ? 64 : 96)) {
    throw new Error(`ECDSA ${namedCurve} key length ${pub.length} invalid`);
  }
  const x = pub.slice(0, half);
  const y = pub.slice(half);
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: namedCurve,
    x: bytesToBase64Url(x),
    y: bytesToBase64Url(y),
    ext: true,
  };
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve },
    false,
    ["verify"],
  );
}

async function importEd25519Key(pub: Uint8Array): Promise<CryptoKey> {
  if (pub.length !== 32) throw new Error(`Ed25519 key length ${pub.length} invalid`);
  return crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
}

export async function verifySignature(
  algorithm: number,
  publicKey: Uint8Array,
  signature: Uint8Array,
  signedData: Uint8Array,
): Promise<boolean> {
  switch (algorithm) {
    case ALGO.RSASHA256: {
      const key = await importRSAKey(publicKey, "SHA-256");
      return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signedData);
    }
    case ALGO.RSASHA512: {
      const key = await importRSAKey(publicKey, "SHA-512");
      return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signedData);
    }
    case ALGO.ECDSAP256SHA256: {
      const key = await importECDSAKey(publicKey, "P-256");
      return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, signedData);
    }
    case ALGO.ECDSAP384SHA384: {
      const key = await importECDSAKey(publicKey, "P-384");
      return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, signature, signedData);
    }
    case ALGO.ED25519: {
      const key = await importEd25519Key(publicKey);
      return crypto.subtle.verify({ name: "Ed25519" }, key, signature, signedData);
    }
    default:
      throw new Error(`unsupported DNSSEC algorithm ${algorithm}`);
  }
}

// DS digest algorithms
export const DIGEST = {
  SHA1: 1,
  SHA256: 2,
  SHA384: 4,
} as const;

export async function dsDigest(
  digestType: number,
  ownerWire: Uint8Array,
  dnskeyRdata: Uint8Array,
): Promise<Uint8Array> {
  const input = new Uint8Array(ownerWire.length + dnskeyRdata.length);
  input.set(ownerWire, 0);
  input.set(dnskeyRdata, ownerWire.length);
  let algo: string;
  switch (digestType) {
    case DIGEST.SHA1:
      algo = "SHA-1";
      break;
    case DIGEST.SHA256:
      algo = "SHA-256";
      break;
    case DIGEST.SHA384:
      algo = "SHA-384";
      break;
    default:
      throw new Error(`unsupported DS digest type ${digestType}`);
  }
  const buf = await crypto.subtle.digest(algo, input);
  return new Uint8Array(buf);
}

export async function sha1(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-1", data);
  return new Uint8Array(buf);
}
