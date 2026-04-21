import { hexToBytes } from "./util.ts";

// IANA root zone trust anchors (DS records for the root KSK).
// Source: https://data.iana.org/root-anchors/root-anchors.xml
// These are the DS records — we match a retrieved root DNSKEY against them to
// establish the trust base. Adding a future KSK = append to this array.
export interface TrustAnchorDS {
  keyTag: number;
  algorithm: number; // 8 = RSA/SHA-256
  digestType: number; // 2 = SHA-256
  digest: Uint8Array;
  notes: string;
}

export const ROOT_TRUST_ANCHORS: TrustAnchorDS[] = [
  {
    keyTag: 20326,
    algorithm: 8,
    digestType: 2,
    digest: hexToBytes("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
    notes: "IANA root KSK-2017",
  },
  {
    keyTag: 38696,
    algorithm: 8,
    digestType: 2,
    digest: hexToBytes("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
    notes: "IANA root KSK-2024",
  },
];
