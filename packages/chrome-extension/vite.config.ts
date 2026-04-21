import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import { resolve } from "node:path";
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";

const dnssecAuditSrc = fileURLToPath(new URL("../dnssec-audit/src", import.meta.url));
const sharedSrc = fileURLToPath(new URL("../shared/src", import.meta.url));

// Copy the extension static assets (manifest, icons) into dist/ on every build.
function copyExtensionAssets() {
  return {
    name: "copy-extension-assets",
    closeBundle() {
      const root = resolve(__dirname);
      const dist = resolve(root, "dist");
      mkdirSync(dist, { recursive: true });
      // manifest.json
      copyFileSync(resolve(root, "manifest.json"), resolve(dist, "manifest.json"));
      // icons (SVG, inlined at runtime as data-URI via manifest)
      mkdirSync(resolve(dist, "icons"), { recursive: true });
      for (const name of ["icon-16.png", "icon-48.png", "icon-128.png"]) {
        try {
          copyFileSync(resolve(root, "icons", name), resolve(dist, "icons", name));
        } catch {
          // icon missing — dev-time, swallow
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [preact(), copyExtensionAssets()],
  base: "./",
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
    rollupOptions: {
      input: {
        popup: resolve(__dirname, "popup.html"),
      },
      output: {
        entryFileNames: "assets/[name].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name][extname]",
      },
    },
  },
});
