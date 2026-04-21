import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import { fileURLToPath, URL } from "node:url";

// Resolve @namefi/dnssec-audit directly to its TS source inside the monorepo
// so Vite's dev server and production build don't require the package's
// dist/ to exist. Vite/esbuild happily bundles .ts.
const dnssecAuditSrc = fileURLToPath(new URL("../dnssec-audit/src", import.meta.url));
const sharedSrc = fileURLToPath(new URL("../shared/src", import.meta.url));

export default defineConfig({
  plugins: [preact()],
  resolve: {
    alias: [
      { find: /^@namefi\/dnssec-audit$/, replacement: `${dnssecAuditSrc}/index.ts` },
      { find: /^@namefi\/dnssec-audit\/(.*)$/, replacement: `${dnssecAuditSrc}/$1.ts` },
      { find: /^@namefi\/dnssec-ui-shared\/styles\.css$/, replacement: `${sharedSrc}/styles.css` },
      { find: /^@namefi\/dnssec-ui-shared\/components$/, replacement: `${sharedSrc}/components.tsx` },
      { find: /^@namefi\/dnssec-ui-shared\/check$/, replacement: `${sharedSrc}/check.ts` },
      { find: /^@namefi\/dnssec-ui-shared\/styles$/, replacement: `${sharedSrc}/styles.ts` },
      { find: /^@namefi\/dnssec-ui-shared$/, replacement: `${sharedSrc}/index.ts` },
    ],
  },
  build: {
    target: "es2022",
    outDir: "dist",
    sourcemap: true,
  },
  server: {
    port: 5173,
  },
});
