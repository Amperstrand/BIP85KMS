#!/usr/bin/env node
/**
 * BIP85KMS CLI
 *
 * Derives Age keys locally from a mnemonic, without any network calls. Reuses the
 * same derivation logic as the Worker API and browser demo (src/core.ts).
 *
 * Usage:
 *   MNEMONIC_SECRET="bacon bacon ... bacon" \
 *   npm run cli -- --filename example.txt --keyVersion 1 --appId myApp [--getPrivateKey] [--verbose]
 *
 *   # Semantic path mode:
 *   MNEMONIC_SECRET="..." npm run cli -- --semanticPath '[{"@type":"Organization","name":"Acme"}]'
 */

import {
  deriveFromMnemonic,
  deriveFromSemanticPath,
  deriveMasterNodeFromMnemonic,
  type DerivationResult,
  type SemanticDerivationResult,
  type SemanticSegment,
} from "./core";

declare const process: {
  argv: string[];
  env: { [key: string]: string | undefined };
  exit(code?: number): never;
};

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const result: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].substring(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        result[key] = argv[i + 1];
        i++;
      } else {
        result[key] = true;
      }
    }
  }
  return result;
}

function flagBool(value: string | boolean | undefined): boolean {
  return value === true || value === "true";
}

function printResult(result: DerivationResult | SemanticDerivationResult, getPrivateKey: boolean): void {
  if (getPrivateKey) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  const { age_private_key, raw_entropy, ...publicFields } = result as unknown as Record<string, unknown>;
  console.log(JSON.stringify(publicFields, null, 2));
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const getPrivateKey = flagBool(args.getPrivateKey);
  const verbose = flagBool(args.verbose);

  const mnemonic = process.env.MNEMONIC_SECRET;
  if (!mnemonic) {
    console.error("Error: MNEMONIC_SECRET environment variable is not set.");
    process.exit(1);
  }

  try {
    if (typeof args.semanticPath === "string") {
      const semanticPath = JSON.parse(args.semanticPath) as SemanticSegment[];
      if (verbose) console.error(`[cli] Deriving from semantic path: ${args.semanticPath}`);
      const masterNode = deriveMasterNodeFromMnemonic(mnemonic);
      const result = deriveFromSemanticPath(masterNode, semanticPath);
      printResult(result, getPrivateKey);
      return;
    }

    const { filename, keyVersion, appId } = args;
    if (!filename || !keyVersion || !appId) {
      console.error("Error: Missing required argument(s).");
      console.error(
        "Usage: cli --filename <filename> --keyVersion <number> --appId <appId> [--getPrivateKey] [--verbose]",
      );
      console.error('   or: cli --semanticPath \'[{"@type":"Organization","name":"Acme"}]\'');
      process.exit(1);
    }
    if (verbose) {
      console.error(`[cli] Deriving keyVersion=${keyVersion} appId=${appId} filename=${filename}`);
    }
    const result = deriveFromMnemonic(mnemonic, Number(keyVersion), String(appId), String(filename));
    printResult(result, getPrivateKey);
  } catch (err) {
    console.error("Error during key derivation:", (err as Error).message);
    process.exit(1);
  }
}

main();

