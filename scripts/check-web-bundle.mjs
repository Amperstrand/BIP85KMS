#!/usr/bin/env node
// Guard: the web demo derives keys from user-entered seed material, so every
// crypto dependency must ship INSIDE the app bundle (versions pinned by
// package-lock.json). Any runtime import from an external origin (esm.sh or
// another CDN) exposes derivation logic — and the seed itself — to
// supply-chain compromise (Codex P1 on #2: "vendor browser crypto deps
// instead of loading from esm.sh"). Runs as part of `npm test`.
import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";

const fail = (msg) => {
  console.error(`web-bundle check FAILED: ${msg}`);
  process.exit(1);
};

const html = readFileSync("index.html", "utf8");
if (html.includes('<script type="importmap">')) {
  fail("index.html must not resolve modules via an import map");
}
const externalScripts = [...html.matchAll(/<script[^>]*\bsrc=["']([^"']+)["']/g)]
  .map((m) => m[1])
  .filter((src) => /^https?:\/\//.test(src));
if (externalScripts.length > 0) {
  fail(`external script sources in index.html: ${externalScripts}`);
}

const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const buildScript = pkg.scripts["build:web"];
if (!buildScript) fail("build:web script must exist");
if (buildScript.includes("--external:")) {
  fail(
    "build:web must bundle the crypto deps — remove --external flags " +
      "(they recreate the import-map/CDN path)"
  );
}

execSync("npm run build:web", { stdio: "pipe" });
const bundle = readFileSync("web/dist/app.js", "utf8");
if (bundle.length < 50_000) fail("bundle unexpectedly small — bundling broken?");
const externalImports = [
  ...bundle.matchAll(/from\s*"(@scure|@noble|bech32)[^"]*"/g),
].map((m) => m[0]);
if (externalImports.length > 0) {
  fail(`bundle must inline @scure/@noble/bech32, found imports: ${externalImports}`);
}
if (bundle.includes("esm.sh")) fail("CDN reference (esm.sh) inside the bundle");

console.log("web-bundle check OK: self-contained, no import map, no CDN");
