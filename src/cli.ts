/**
 * CLI Tool for BIP85KMS
 *
 * Usage Example:
 *
 *   export MNEMONIC_SECRET="bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon"
 *   node dist/cli.js --filename "example.txt" --keyVersion 1 --appId "myApp" --getPrivateKey
 *
 * This tool derives Age keys locally using the BIP85KMS library.
 * It expects the following command-line flags:
 *   --filename      (required): The filename string.
 *   --keyVersion    (required): The key version (number).
 *   --appId         (required): The app ID string.
 *   --getPrivateKey (optional): If present, includes the private key in the output.
 *
 * The environment variable MNEMONIC_SECRET must be set.
 */

// Minimal ambient declaration for process (to avoid installing @types/node)
declare const process: {
  argv: string[],
  env: { [key: string]: string | undefined },
  exit(code?: number): never
};

import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
// Note the explicit .js extension for Node ES module resolution:
import { deriveKeyAndIV } from "./bip85kms.js";

// Simple function to parse command-line arguments.
function parseArgs(): { [key: string]: string | boolean } {
  const args = process.argv.slice(2);
  const result: { [key: string]: string | boolean } = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].substring(2);
      // If the next value exists and is not another flag, use it as the value.
      if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        result[key] = args[i + 1];
        i++;
      } else {
        // If no value is given, treat it as a boolean flag.
        result[key] = true;
      }
    }
  }
  return result;
}

async function main() {
  const args = parseArgs();
  const filename = args["filename"];
  const keyVersion = args["keyVersion"];
  const appId = args["appId"];
  const getPrivateKey = args["getPrivateKey"] === true || args["getPrivateKey"] === "true";

  // Validate required arguments.
  if (!filename || !keyVersion || !appId) {
    console.error("Error: Missing required argument(s).");
    console.error("Usage: node dist/cli.js --filename <filename> --keyVersion <number> --appId <appId> [--getPrivateKey]");
    process.exit(1);
  }

  // Get the MNEMONIC_SECRET from the environment.
  const mnemonic = process.env.MNEMONIC_SECRET;
  if (!mnemonic) {
    console.error("Error: MNEMONIC_SECRET environment variable is not set.");
    process.exit(1);
  }

  // Derive the keys.
  try {
    const seed = mnemonicToSeedSync(mnemonic);
    const masterNode = HDKey.fromMasterSeed(seed);
    const result = await deriveKeyAndIV(masterNode, Number(keyVersion), String(appId), String(filename));
    if (getPrivateKey) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(JSON.stringify({
        age_public_key: result.age_public_key,
        iv: result.iv
      }, null, 2));
    }
  } catch (err) {
    console.error("Error during key derivation:", (err as Error).message);
    process.exit(1);
  }
}

main();
