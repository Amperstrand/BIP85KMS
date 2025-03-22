/**
 * Verbose CLI Tool for BIP85KMS (TypeScript Version)
 *
 * Usage Example:
 *   MNEMONIC_SECRET="bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon" \
 *   node dist/cli.js --filename "example.txt" --keyVersion 1 --appId "myApp" --getPrivateKey --verbose
 *
 * This tool derives Age keys locally and prints detailed logs at each step.
 */

declare const process: {
  argv: string[],
  env: { [key: string]: string | undefined },
  exit(code?: number): never
};

function parseArgs(): { [key: string]: string | boolean } {
  const args = process.argv.slice(2);
  const result: { [key: string]: string | boolean } = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].substring(2);
      if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        result[key] = args[i + 1];
        i++;
      } else {
        result[key] = true;
      }
    }
  }
  return result;
}

import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { bech32 } from "bech32";
import { x25519 } from "@noble/curves/ed25519";

function bufferToHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join("");
}

function intFromBytes(bytes: Uint8Array): number {
  return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

function deriveBIP85Entropy(index: number, masterNode: HDKey, verbose: boolean): Uint8Array {
  const path = `m/83696968'/${index}'`;
  if (verbose) console.log(`\n[Step 1] Deriving child node using path: ${path}`);
  const child = masterNode.derive(path);
  if (!child.privateKey) {
    throw new Error("Failed to derive privateKey from child node.");
  }
  if (verbose) console.log(`[Step 1] Child node private key: ${bufferToHex(child.privateKey)}`);
  const entropy = sha256(child.privateKey);
  if (verbose) console.log(`[Step 1] BIP85 entropy (SHA256 of child private key): ${bufferToHex(entropy)}`);
  return entropy;
}

function deriveDeterministicAgeKey(masterKey: Uint8Array, index: number, verbose: boolean): string {
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false);
  if (verbose) console.log(`\n[Step 2] Index bytes: ${bufferToHex(indexBytes)}`);
  const key = hmac(sha256, masterKey, indexBytes);
  if (verbose) console.log(`[Step 2] HMAC-SHA256 result: ${bufferToHex(key)}`);
  const keyU5 = bech32.toWords(key);
  const encoded = bech32.encode("AGE-SECRET-KEY-", keyU5, 1023);
  if (verbose) console.log(`[Step 2] Bech32 encoded Age private key: ${encoded}`);
  return encoded.toUpperCase();
}

async function deriveKeyAndIV(masterNode: HDKey, keyVersion: number, appId: string, filename: string, verbose: boolean) {
  if (verbose) console.log(`\n[Step 3] Deriving keys for keyVersion: ${keyVersion}, appId: ${appId}, filename: ${filename}`);
  const appIdHash = sha256(new TextEncoder().encode(appId));
  const filenameHash = sha256(new TextEncoder().encode(filename));
  if (verbose) {
    console.log(`[Step 3] SHA256(appId): ${bufferToHex(appIdHash)}`);
    console.log(`[Step 3] SHA256(filename): ${bufferToHex(filenameHash)}`);
  }

  const idx0 = keyVersion;
  const idx1 = intFromBytes(appIdHash.slice(0, 4));
  const idx2 = intFromBytes(filenameHash.slice(0, 4));
  if (verbose) {
    console.log(`[Step 3] Derived indexes: keyVersion: ${idx0}, appId index: ${idx1}, filename index: ${idx2}`);
  }
  const derivationPath = `m/83696968'/128169'/${idx0}'/${idx1}'/${idx2}'`;
  if (verbose) console.log(`[Step 3] Full derivation path: ${derivationPath}`);

  const entropy = deriveBIP85Entropy(idx0, masterNode, verbose);
  const agePrivateKey = deriveDeterministicAgeKey(entropy, idx0, verbose);
  const ivHex = bufferToHex(filenameHash.slice(0, 12));
  if (verbose) console.log(`[Step 3] Derived IV (first 12 bytes of filename hash): ${ivHex}`);

  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(idx0), false);
  const rawSecret = hmac(sha256, entropy, indexBytes);
  if (verbose) console.log(`[Step 4] Raw secret for X25519 derivation (HMAC result): ${bufferToHex(rawSecret)}`);

  const pubBytes = x25519.getPublicKey(rawSecret);
  if (verbose) console.log(`[Step 4] X25519 public key bytes: ${bufferToHex(pubBytes)}`);
  const pubU5 = bech32.toWords(pubBytes);
  const agePublicKey = bech32.encode("age", pubU5, 1023).toLowerCase();
  if (verbose) console.log(`[Step 4] Bech32 encoded Age public key: ${agePublicKey}`);

  return {
    derivationPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: bufferToHex(entropy),
    iv: ivHex
  };
}

async function main() {
  const args = parseArgs();
  const filename = args["filename"];
  const keyVersion = args["keyVersion"];
  const appId = args["appId"];
  const getPrivateKey = args["getPrivateKey"] === true || args["getPrivateKey"] === "true";
  const verbose = args["verbose"] === true || args["verbose"] === "true";

  if (!filename || !keyVersion || !appId) {
    console.error("Error: Missing required argument(s).");
    console.error("Usage: node dist/cli.js --filename <filename> --keyVersion <number> --appId <appId> [--getPrivateKey] [--verbose]");
    process.exit(1);
  }

  const mnemonic = process.env.MNEMONIC_SECRET;
  if (!mnemonic) {
    console.error("Error: MNEMONIC_SECRET environment variable is not set.");
    process.exit(1);
  }
  if (verbose) console.log(`\n[Step 0] Mnemonic: ${mnemonic}`);

  const seed = mnemonicToSeedSync(mnemonic);
  if (verbose) console.log(`[Step 0] Master seed: ${bufferToHex(seed)}`);

  const masterNode = HDKey.fromMasterSeed(seed);
  if (verbose) {
    console.log(`[Step 0] Master node derived.`);
    if (masterNode.publicKey) {
      console.log(`[Step 0] Master public key: ${bufferToHex(masterNode.publicKey)}`);
    }
  }

  try {
    const result = await deriveKeyAndIV(masterNode, Number(keyVersion), String(appId), String(filename), verbose);
    if (getPrivateKey) {
      console.log("\nFinal Result (full details):");
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log("\nFinal Result:");
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
