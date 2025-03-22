// src/bip85kms.ts
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { bech32 } from "bech32";
import { argon2id } from "@noble/hashes/argon2";
import { x25519 } from "@noble/curves/ed25519";

export interface Env {
  MNEMONIC_SECRET: string;
}

/**
 * Derive a 64-byte master key using Argon2id.
 */
export function deriveMasterKey(passphrase: string): Uint8Array {
  const salt = new TextEncoder().encode("age-keygen-deterministic-hardcoded-salt");
  return argon2id(passphrase, salt, {
    t: 10,      // time_cost
    m: 65536,   // mem_cost
    p: 2,       // lanes
    dkLen: 64   // hash_length
  });
}

/**
 * Derive 32-byte entropy by hashing a derived child private key,
 * effectively replicating BIP85 (m/83696968'/keyVersion').
 */
export function deriveBIP85Entropy(index: number, masterNode: HDKey): Uint8Array {
  const path = `m/83696968'/${index}'`;
  const child = masterNode.derive(path);
  if (!child.privateKey) {
    throw new Error("Failed to derive privateKey from child node.");
  }
  return sha256(child.privateKey);
}

/**
 * Generate a deterministic Age key using HMAC-SHA256 and Bech32 encoding.
 */
export function deriveDeterministicAgeKey(masterKey: Uint8Array, index: number): string {
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false);
  const key = hmac(sha256, masterKey, indexBytes);
  const keyU5 = bech32.toWords(key);
  const encoded = bech32.encode("AGE-SECRET-KEY-", keyU5, 1023);
  return encoded.toUpperCase();
}

/**
 * Derive an Age-compatible key and IV deterministically.
 */
export async function deriveKeyAndIV(
  masterNode: HDKey,
  keyVersion: number,
  appId: string,
  filename: string
) {
  const appIdHash = sha256(new TextEncoder().encode(appId));
  const filenameHash = sha256(new TextEncoder().encode(filename));

  const indexes = [
    keyVersion,
    intFromBytes(appIdHash.slice(0, 4)),
    intFromBytes(filenameHash.slice(0, 4))
  ].map((x) => x & 0x7fffffff);

  // This derivation path is for reference.
  const derivationPath = `m/83696968'/128169'/${indexes[0]}'/${indexes[1]}'/${indexes[2]}'`;

  const entropy = deriveBIP85Entropy(indexes[0], masterNode);
  const agePrivateKey = deriveDeterministicAgeKey(entropy, indexes[0]);
  const ivHex = bufferToHex(filenameHash.slice(0, 12));

  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(indexes[0]), false);
  const rawSecret = hmac(sha256, entropy, indexBytes);
  const pubBytes = x25519.getPublicKey(rawSecret);
  const pubU5 = bech32.toWords(pubBytes);
  const agePublicKey = bech32.encode("age", pubU5, 1023).toLowerCase();

  return {
    derivationPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: bufferToHex(entropy),
    iv: ivHex
  };
}

/**
 * Utility function to convert a buffer to hexadecimal string.
 */
export function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Utility function to convert bytes to integer.
 */
export function intFromBytes(bytes: Uint8Array): number {
  return (
    (bytes[0] << 24) |
    (bytes[1] << 16) |
    (bytes[2] << 8) |
    bytes[3]
  );
}
