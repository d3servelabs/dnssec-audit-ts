import { BrandHeader, DnssecChecker } from "@namefi/dnssec-ui-shared/components";

export function App() {
  // Seed from ?d=example.com,foo.com in the URL for linkable checks.
  const url = new URL(window.location.href);
  const seed = url.searchParams.get("d") ?? "";
  const type = url.searchParams.get("t") ?? "A";

  return (
    <main class="dns-shell">
      <BrandHeader tagline="DNSSEC chain-of-trust checker · dnssec.tools.namefi.io" />
      <DnssecChecker initial={seed} initialType={type} />
      <footer class="dns-footer">
        <span>
          Powered by{" "}
          <a
            class="dns-link"
            href="https://www.npmjs.com/package/@namefi/dnssec-audit"
            target="_blank"
            rel="noreferrer"
          >
            @namefi/dnssec-audit
          </a>{" "}
          · pure-TS, zero-dep
        </span>
        <span>
          <a
            class="dns-link"
            href="https://github.com/d3servelabs/dnssec-audit-ts"
            target="_blank"
            rel="noreferrer"
          >
            Source on GitHub ↗
          </a>
        </span>
      </footer>
    </main>
  );
}
