import { encodeQuery, decodeMessage, type DNSMessage, canonicalName } from "./wire.ts";
import { bytesToBase64, base64ToBytes } from "./util.ts";

export interface ResolvedResponse {
  wire: Uint8Array;
  message: DNSMessage;
  source: "doh" | "cache";
  endpoint?: string;
  timestamp: string;
}

export interface Resolver {
  query(qname: string, qtype: number): Promise<ResolvedResponse>;
}

// ----- DoH (RFC 8484) -----

export class DoHResolver implements Resolver {
  readonly url: string;
  constructor(url: string) {
    this.url = url;
  }

  async query(qname: string, qtype: number): Promise<ResolvedResponse> {
    const id = Math.floor(Math.random() * 0x10000);
    const wireQ = encodeQuery({ id, qname, qtype, doBit: true, cdBit: true });
    const res = await fetch(this.url, {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
        accept: "application/dns-message",
      },
      body: wireQ,
    });
    if (!res.ok) throw new Error(`DoH HTTP ${res.status} for ${qname}/${qtype}`);
    const ab = await res.arrayBuffer();
    const wire = new Uint8Array(ab);
    const message = decodeMessage(wire);
    return {
      wire,
      message,
      source: "doh",
      endpoint: this.url,
      timestamp: new Date().toISOString(),
    };
  }
}

// ----- Recording wrapper: captures every query for export -----

export interface CapturedEntry {
  kind: "response";
  qname: string;
  qtype: number;
  endpoint: string;
  timestamp: string;
  wire_b64: string;
}

export class RecordingResolver implements Resolver {
  readonly entries: CapturedEntry[] = [];
  private readonly inner: Resolver;
  constructor(inner: Resolver) {
    this.inner = inner;
  }

  async query(qname: string, qtype: number): Promise<ResolvedResponse> {
    const r = await this.inner.query(qname, qtype);
    this.entries.push({
      kind: "response",
      qname: canonicalName(qname),
      qtype,
      endpoint: r.endpoint ?? "",
      timestamp: r.timestamp,
      wire_b64: bytesToBase64(r.wire),
    });
    return r;
  }
}

// ----- Offline resolver: serves from a JSONL-loaded map -----

export class JSONLResolver implements Resolver {
  private map = new Map<string, CapturedEntry>();

  constructor(entries: CapturedEntry[]) {
    for (const e of entries) {
      this.map.set(keyOf(e.qname, e.qtype), e);
    }
  }

  async query(qname: string, qtype: number): Promise<ResolvedResponse> {
    const k = keyOf(qname, qtype);
    const e = this.map.get(k);
    if (!e) throw new Error(`no captured response for ${qname}/${qtype}`);
    const wire = base64ToBytes(e.wire_b64);
    const message = decodeMessage(wire);
    return {
      wire,
      message,
      source: "cache",
      endpoint: e.endpoint,
      timestamp: e.timestamp,
    };
  }
}

function keyOf(qname: string, qtype: number): string {
  return `${canonicalName(qname)}\t${qtype}`;
}
