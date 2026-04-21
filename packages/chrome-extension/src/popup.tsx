import { render } from "preact";
import { BrandHeader, DnssecChecker } from "@namefi/dnssec-ui-shared/components";
import "@namefi/dnssec-ui-shared/styles.css";

const WEBAPP = "https://dnssec.tools.namefi.io/";

function hostFromActiveTabUrl(url: string | undefined): string {
  if (!url) return "";
  try {
    const u = new URL(url);
    if (u.protocol === "http:" || u.protocol === "https:") return u.hostname;
  } catch {
    /* ignore */
  }
  return "";
}

async function getInitialDomain(): Promise<string> {
  try {
    if (typeof chrome !== "undefined" && chrome.tabs?.query) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      return hostFromActiveTabUrl(tab?.url);
    }
  } catch {
    /* ignore */
  }
  return "";
}

function Popup({ initial }: { initial: string }) {
  return (
    <main class="dns-shell">
      <BrandHeader tagline="Quick check" />
      <DnssecChecker
        initial={initial}
        compact
        fullAppUrl={`${WEBAPP}?d=${encodeURIComponent(initial)}`}
      />
    </main>
  );
}

(async () => {
  const root = document.getElementById("app");
  if (!root) return;
  const initial = await getInitialDomain();
  render(<Popup initial={initial} />, root);
})();
