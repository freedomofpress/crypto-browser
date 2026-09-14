/// <reference types="vitest" />
import { existsSync } from "fs";
import { createRequire } from "module";
import { defineConfig } from "vite";

// Chromium 136 is the last release without Ed25519 in WebCrypto, so the suite runs on it
// to exercise the @noble/curves fallback in a real browser. Playwright 1.52 pins that build.
// Install it with `npm run test:browser:install`.
function legacyChromium(): string | undefined {
  try {
    const require = createRequire(import.meta.url);
    const { registry } = require("playwright-legacy/lib/server/registry/index");
    const path: string = registry.findExecutable("chromium-headless-shell").executablePath();
    return existsSync(path) ? path : undefined;
  } catch {
    return undefined;
  }
}

const legacy = legacyChromium();
if (!legacy) {
  const message = "Chromium 136 (no Ed25519) is not installed. Run `npm run test:browser:install` to also test the fallback in a real browser.";
  if (process.env.CI) throw new Error(message);
  console.warn(message);
}

export default defineConfig({
  // Match the library build target so tests run the same syntax level that ships.
  esbuild: { target: "es2020" },
  build: {
    minify: false,
    outDir: "dist",
    target: "es2020",
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: "index",
    },
  },
  test: {
    globals: true,
    include: ["test/index.browser.test.ts"],
    browser: {
      provider: "playwright",
      enabled: true,
      headless: true,
      instances: [
        { browser: "chromium", name: "chromium" },
        { browser: "firefox", name: "firefox" },
        ...(legacy ? [{ browser: "chromium", name: "chromium-136-no-ed25519", launch: { executablePath: legacy } }] : []),
      ],
    },
  },
});
