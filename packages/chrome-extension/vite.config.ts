import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import { resolve } from "node:path";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

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
