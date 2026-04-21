import { useState, useMemo, useCallback } from "preact/hooks";
import type { JSX } from "preact";
import {
  DOH_ENDPOINTS,
  DEFAULT_DOH,
  checkDomain,
  parseDomainInput,
  verdictLabel,
  verdictTone,
  type DomainCheckResult,
} from "./check.ts";

interface CheckerState {
  running: boolean;
  results: DomainCheckResult[];
  pending: string[];
}

export interface DnssecCheckerProps {
  /** Initial comma/space-separated domains. */
  initial?: string;
  /** Record type, defaults to A. */
  initialType?: string;
  /** Show the DoH endpoint picker. Defaults to true. */
  allowEndpointChange?: boolean;
  /** Show a link to the full web app (useful in the popup). */
  fullAppUrl?: string;
  /** Compact layout (Chrome extension popup). */
  compact?: boolean;
}

export function DnssecChecker({
  initial = "",
  initialType = "A",
  allowEndpointChange = true,
  fullAppUrl,
  compact = false,
}: DnssecCheckerProps): JSX.Element {
  const [raw, setRaw] = useState(initial);
  const [resolver, setResolver] = useState(DEFAULT_DOH);
  const [qtype, setQtype] = useState(initialType.toUpperCase());
  const [state, setState] = useState<CheckerState>({
    running: false,
    results: [],
    pending: [],
  });

  const domains = useMemo(() => parseDomainInput(raw), [raw]);

  const run = useCallback(async () => {
    if (domains.length === 0) return;
    setState({ running: true, results: [], pending: domains.slice() });
    const results: DomainCheckResult[] = [];
    for (const d of domains) {
      const res = await checkDomain(d, { resolver, qtype });
      results.push(res);
      setState({
        running: true,
        results: results.slice(),
        pending: domains.slice(results.length),
      });
    }
    setState({ running: false, results, pending: [] });
  }, [domains, resolver, qtype]);

  const onSubmit = (ev: Event) => {
    ev.preventDefault();
    void run();
  };

  return (
    <section class="dns-card">
      <h1 class="dns-h1">DNSSEC chain of trust</h1>
      <p class="dns-lede">
        Paste one or more domains, then verify the full DNSSEC chain entirely in
        your browser using DNS-over-HTTPS. The walker climbs from the IANA root
        through every signed delegation and checks each RRSIG against the key
        its parent vouches for.
      </p>

      <form class="dns-form" onSubmit={onSubmit}>
        {compact ? (
          <input
            class="dns-input"
            type="text"
            placeholder="example.com, cloudflare.com"
            value={raw}
            onInput={(e) => setRaw((e.currentTarget as HTMLInputElement).value)}
          />
        ) : (
          <textarea
            class="dns-textarea"
            placeholder="example.com&#10;cloudflare.com, prettysafe.xyz"
            value={raw}
            onInput={(e) =>
              setRaw((e.currentTarget as HTMLTextAreaElement).value)
            }
          />
        )}

        <div class="dns-controls">
          <div class="dns-controls-left">
            {allowEndpointChange && (
              <select
                class="dns-select"
                value={resolver}
                onChange={(e) =>
                  setResolver((e.currentTarget as HTMLSelectElement).value)
                }
              >
                {DOH_ENDPOINTS.map((ep) => (
                  <option key={ep.url} value={ep.url}>
                    DoH · {ep.label}
                  </option>
                ))}
              </select>
            )}
            <select
              class="dns-select"
              value={qtype}
              onChange={(e) =>
                setQtype((e.currentTarget as HTMLSelectElement).value)
              }
            >
              {["A", "AAAA", "MX", "TXT", "NS", "SOA"].map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div class="dns-controls-right">
            <span class="dns-muted">
              {domains.length === 0
                ? "no domains"
                : domains.length === 1
                  ? "1 domain"
                  : `${domains.length} domains`}
            </span>
            <button
              type="submit"
              class="dns-btn dns-btn-primary"
              disabled={state.running || domains.length === 0}
            >
              {state.running ? (
                <>
                  <span class="dns-spinner" /> Checking…
                </>
              ) : (
                "Check"
              )}
            </button>
          </div>
        </div>
      </form>

      <div style={{ marginTop: compact ? 14 : 22 }}>
        {state.results.length === 0 && state.pending.length === 0 && (
          <div class="dns-empty">
            Results will appear here. All DNS queries run in your browser — your
            domain list is never sent to any server.
          </div>
        )}
        {state.results.map((r) => (
          <ResultCard key={`${r.canonical}/${r.qtype}/${r.startedAt}`} result={r} compact={compact} />
        ))}
        {state.pending.length > 0 &&
          state.pending.map((d) => (
            <div key={`pending-${d}`} class="dns-subcard">
              <div class="dns-result-head">
                <div class="dns-domain">{d}</div>
                <div class="dns-verdict">
                  <span class="dns-spinner" />
                  Walking chain…
                </div>
              </div>
            </div>
          ))}
      </div>

      {fullAppUrl && (
        <p class="dns-footer">
          <span>Client-side DoH · no server round-trip</span>
          <a class="dns-link" href={fullAppUrl} target="_blank" rel="noreferrer">
            Open full web app ↗
          </a>
        </p>
      )}
    </section>
  );
}

function ResultCard({
  result,
  compact,
}: {
  result: DomainCheckResult;
  compact: boolean;
}): JSX.Element {
  const tone = verdictTone(result.verdict);
  return (
    <div class="dns-subcard">
      <div class="dns-result-head">
        <div class="dns-domain">{result.canonical}</div>
        <div class={`dns-verdict ${tone}`}>
          <span class="dot" />
          {verdictLabel(result.verdict)}
        </div>
      </div>
      <div class="dns-meta">
        <div>
          <b>Type</b>
          {result.qtypeName}
        </div>
        <div>
          <b>Resolver</b>
          {new URL(result.resolver).host}
        </div>
        <div>
          <b>Queries</b>
          {result.queryCount}
        </div>
        <div>
          <b>Took</b>
          {result.durationMs} ms
        </div>
      </div>
      {result.detail && (
        <div class="dns-detail">{result.detail}</div>
      )}
      {!compact && result.steps.length > 0 && (
        <details class="dns-toggle" style={{ marginTop: 12 }}>
          <summary>{result.steps.length} chain steps</summary>
          <div class="dns-steps">
            {result.steps.map((s, i) => (
              <div
                key={`${i}-${s.kind}`}
                class={`dns-step${s.ok ? "" : " err"}`}
              >
                <span class="dns-step-mark">{s.ok ? "OK" : "ERR"}</span>
                <span class="dns-step-kind">{s.kind}</span>
                <span class="dns-step-body">
                  {(s.zone || s.qname) && (
                    <span class="dns-step-scope">
                      {s.zone ?? s.qname}
                      {s.qtype ? ` / ${s.qtype}` : ""}
                      {" — "}
                    </span>
                  )}
                  {s.detail}
                </span>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

export function BrandHeader({
  tagline = "Client-side DNSSEC chain-of-trust checker",
}: {
  tagline?: string;
}): JSX.Element {
  return (
    <header class="dns-brand">
      <div class="dns-brand-mark" aria-hidden="true" />
      <div>
        <div class="dns-brand-title">dnssec.tools</div>
        <div class="dns-brand-sub">{tagline}</div>
      </div>
    </header>
  );
}
