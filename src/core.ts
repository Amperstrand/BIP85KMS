/**
 * BIP85KMS core derivation module.
 *
 * Single source of truth for all key-derivation logic (BIP39 -> BIP32 -> BIP85 -> Age).
 * Consumed by the Worker API (src/index.ts), the CLI (src/cli.ts), the browser demo
 * (web/app.ts) and the test suite. Do not duplicate this logic elsewhere.
 *
 * BIP85: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
 * Age:   https://age-encryption.org/
 */

import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { hmac } from "@noble/hashes/hmac";
import { argon2id } from "@noble/hashes/argon2";
import { x25519 } from "@noble/curves/ed25519";
import { bech32 } from "bech32";

export interface SemanticSegment {
  "@type": string;
  [key: string]: unknown;
}

export interface DerivationResult {
  derivationPath: string;
  age_private_key: string;
  age_public_key: string;
  raw_entropy: string;
  iv: string;
}

export interface SemanticDerivationResult {
  derivationPath: string;
  age_private_key: string;
  age_public_key: string;
  raw_entropy: string;
  semanticPath: SemanticSegment[];
}

export interface SemanticDerivationOptions {
  nonce?: Uint8Array;  // Optional versioning/rotation key
}

export interface DeriveIndexesResult {
  indexes: [number, number, number];
  appIdHash: Uint8Array;
  filenameHash: Uint8Array;
  derivationPath: string;
}

/** BIP85 purpose constant (ASCII "bip-85" derived, per spec 0x4FF4800). */
const BIP85_PURPOSE = 83696968;
/** BIP-Keychain application code within the BIP85 purpose namespace. */
const KEYCHAIN_APP_CODE = 67797668;
/** Legacy numeric-path application code (distinguishes from BIP-Keychain paths). */
const LEGACY_APP_CODE = 128169;

/**
 * Derives a master key from a passphrase using Argon2id.
 *
 * Not used by the Worker API (which uses BIP39 mnemonics instead); kept as an
 * alternative deterministic key-derivation entry point. The salt is fixed so the
 * same passphrase always yields the same output — passphrases must have high entropy.
 */
export function deriveMasterKey(passphrase: string): Uint8Array {
  const salt = new TextEncoder().encode("age-keygen-deterministic-hardcoded-salt");
  return argon2id(passphrase, salt, {
    t: 10,
    m: 65536,
    p: 2,
    dkLen: 64,
  });
}

export function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Converts a 4-byte big-endian buffer into an unsigned 32-bit integer. */
export function intFromBytes(bytes: Uint8Array): number {
  return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
}

function u64BE(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
  return bytes;
}

/**
 * Derives BIP85 entropy from a BIP32 master node at `m/83696968'/{index}'`.
 * 
 * Per BIP85 spec: entropy = HMAC-SHA512(key="bip-entropy-from-k", message=privateKey)
 * Output is always 64 bytes (full HMAC-SHA512 output), never truncated.
 * 
 * Entropy quality depends entirely on the master node's seed quality.
 */
export function deriveBIP85Entropy(index: number, masterNode: HDKey): Uint8Array {
  const child = masterNode.derive(`m/${BIP85_PURPOSE}'/${index}'`);
  if (!child.privateKey) {
    throw new Error("Failed to derive privateKey from child node.");
  }
  // BIP85 domain-separation string ensures entropy cannot be confused with other uses
  const domainSeparation = new TextEncoder().encode("bip-entropy-from-k");
  return hmac(sha512, domainSeparation, child.privateKey);
}

/**
 * Derives an Age-compatible bech32-encoded private key from master key material
 * and an index via HMAC-SHA256(masterKey, index).
 */
export function deriveDeterministicAgeKey(masterKey: Uint8Array, index: number): string {
  const key = hmac(sha256, masterKey, u64BE(index));
  const words = bech32.toWords(key);
  return bech32.encode("AGE-SECRET-KEY-", words, 1023).toUpperCase();
}

/** Derives a BIP32 master HD node from a BIP39 mnemonic phrase. */
export function deriveMasterNodeFromMnemonic(mnemonic: string): HDKey {
  const seed = mnemonicToSeedSync(mnemonic);
  return HDKey.fromMasterSeed(seed);
}

/**
 * Derives the three hardened indexes and BIP32 path used by the legacy
 * (keyVersion, appId, filename) derivation scheme.
 */
export function deriveIndexes(keyVersion: number, appId: string, filename: string): DeriveIndexesResult {
  const appIdHash = sha256(new TextEncoder().encode(appId));
  const filenameHash = sha256(new TextEncoder().encode(filename));

  const indexes = [
    keyVersion,
    intFromBytes(appIdHash.slice(0, 4)),
    intFromBytes(filenameHash.slice(0, 4)),
  ].map((x) => x & 0x7fffffff) as [number, number, number];

  return {
    indexes,
    appIdHash,
    filenameHash,
    derivationPath: `m/${BIP85_PURPOSE}'/${LEGACY_APP_CODE}'/${indexes[0]}'/${indexes[1]}'/${indexes[2]}'`,
  };
}

/** Derives an X25519 keypair from raw secret material and encodes it as an Age public key. */
function derivePublicKey(rawSecret: Uint8Array): string {
  const pubBytes = x25519.getPublicKey(rawSecret);
  return bech32.encode("age", bech32.toWords(pubBytes), 1023).toLowerCase();
}

/**
 * Derives an Age key pair and IV from a BIP32 master node and (keyVersion, appId, filename).
 *
 * The entropy is derived from `keyVersion` via BIP85, then mixed with the appId and
 * filename hashes (HMAC-SHA256) so that distinct apps/files always yield distinct keys.
 * Earlier versions of this function used only `keyVersion` for entropy, meaning
 * different appId/filename combinations under the same keyVersion collided to the
 * same key material — see docs/SECURITY.md. This is a breaking change from that
 * behavior; keys derived before this fix will differ.
 */
export function deriveKeyAndIV(
  masterNode: HDKey,
  keyVersion: number,
  appId: string,
  filename: string,
): DerivationResult {
  const { indexes, appIdHash, filenameHash, derivationPath } = deriveIndexes(keyVersion, appId, filename);

  const baseEntropy = deriveBIP85Entropy(indexes[0], masterNode);
  // Bind entropy to appId + filename so different files/apps never share key material.
  const context = new Uint8Array([...appIdHash.slice(0, 16), ...filenameHash.slice(0, 16)]);
  const entropy = hmac(sha256, baseEntropy, context);

  const agePrivateKey = deriveDeterministicAgeKey(entropy, indexes[0]);
  const rawSecret = hmac(sha256, entropy, u64BE(indexes[0]));
  const agePublicKey = derivePublicKey(rawSecret);

  return {
    derivationPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: bufferToHex(entropy),
    iv: bufferToHex(filenameHash.slice(0, 12)), // 96-bit IV from filename hash
  };
}

/**
 * Main legacy entry point: derives an Age key pair and IV from a mnemonic and
 * (keyVersion, appId, filename) parameters.
 *
 * Security warning: never log the mnemonic or derived private keys.
 */
export function deriveFromMnemonic(
  mnemonic: string,
  keyVersion: number,
  appId: string,
  filename: string,
): DerivationResult {
  return deriveKeyAndIV(deriveMasterNodeFromMnemonic(mnemonic), keyVersion, appId, filename);
}

/**
 * JSON Canonicalization Scheme (JCS) per RFC 8785: sorts object keys lexicographically
 * and produces a deterministic string so semantically identical JSON always hashes
 * the same way.
 */
export function jcs(obj: unknown): string {
  if (obj === null || obj === undefined) return "null";

  const type = typeof obj;

  if (type === "boolean") return (obj as boolean).toString();

  if (type === "number") {
    if (!isFinite(obj as number)) throw new Error("Cannot canonicalize non-finite number");
    return String(obj);
  }

  if (type === "string") return JSON.stringify(obj);

  if (Array.isArray(obj)) {
    return "[" + obj.map((item) => jcs(item)).join(",") + "]";
  }

  if (type === "object") {
    const record = obj as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const pairs = keys.map((key) => JSON.stringify(key) + ":" + jcs(record[key]));
    return "{" + pairs.join(",") + "}";
  }

  throw new Error(`Cannot canonicalize type: ${type}`);
}

/** Validates that a semantic path segment is a JSON-LD object with an `@type` property. */
export function validateSemanticSegment(segment: unknown): asserts segment is SemanticSegment {
  if (typeof segment !== "object" || segment === null || Array.isArray(segment)) {
    throw new Error("Semantic segment must be a JSON object");
  }
  if (!(segment as SemanticSegment)["@type"]) {
    throw new Error("Semantic segment must have @type property");
  }
}

/**
 * Converts a semantic segment to a BIP32 child index using chained entropy (the
 * "image function" `i()` from the BIP-Keychain proposal):
 * 1. Canonicalize the segment via JCS
 * 2. HMAC-SHA512(parentEntropy, canonicalJSON || nonce?) — per BIP-Keychain spec
 * 3. Take the top 31 bits as a valid BIP32 child index
 * 4. Optionally set the hardened bit
 * 
 * @param segment - JSON-LD semantic segment
 * @param parentEntropy - 64 bytes of entropy from parent path or BIP85
 * @param hardened - Whether to set the hardened bit (default: true)
 * @param nonce - Optional versioning/rotation nonce
 */
export function semanticToIndex(
  segment: SemanticSegment,
  parentEntropy: Uint8Array,
  hardened = true,
  nonce?: Uint8Array,
): number {
  const canonical = jcs(segment);
  const canonicalBytes = new TextEncoder().encode(canonical);
  
  // Construct message: canonical JSON + optional nonce
  const message = nonce
    ? new Uint8Array([...canonicalBytes, ...nonce])
    : canonicalBytes;
  
  // HMAC-SHA512 per BIP-Keychain spec
  const hmacResult = hmac(sha512, parentEntropy, message);

  // Extract top 31 bits from 512-bit output
  const bytes = hmacResult.slice(0, 4);
  const value32 = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  const index31bit = (value32 >>> 1) >>> 0;

  return hardened ? (index31bit | 0x80000000) >>> 0 : index31bit >>> 0;
}

/**
 * Derives Age keys from a BIP-Keychain semantic path: a sequence of JSON-LD segments
 * chained via entropy so that the same segment at different positions produces
 * different indexes, and path order matters (`[A, B] != [B, A]`).
 *
 * Base path: `m/83696968'/67797668'` (BIP85 purpose / BIP-Keychain application code).
 * 
 * Per Phase 2 design:
 * - Maintains full 64-byte BIP85 entropy throughout derivation chain
 * - Uses HMAC-SHA512 for semantic imaging (not SHA256)
 * - Supports optional nonce for key rotation/versioning
 * - Validates path depth (max 16 segments)
 */
export function deriveFromSemanticPath(
  masterNode: HDKey,
  semanticPath: SemanticSegment[],
  options?: SemanticDerivationOptions,
): SemanticDerivationResult {
  const MAX_DEPTH = 16;  // Security limit per Phase 2 spec
  
  if (!Array.isArray(semanticPath) || semanticPath.length === 0) {
    throw new Error("Semantic path must be a non-empty array");
  }
  
  if (semanticPath.length > MAX_DEPTH) {
    throw new Error(`Semantic path exceeds maximum depth of ${MAX_DEPTH}`);
  }

  semanticPath.forEach((segment, idx) => {
    try {
      validateSemanticSegment(segment);
      // Validate segment size
      const segmentJSON = JSON.stringify(segment);
      if (segmentJSON.length > 10000) {
        throw new Error("Segment exceeds maximum size of 10000 bytes");
      }
    } catch (err) {
      throw new Error(`Invalid segment at index ${idx}: ${(err as Error).message}`);
    }
  });

  let currentPath = `m/${BIP85_PURPOSE}'/${KEYCHAIN_APP_CODE}'`;
  // Initialize with BIP85 entropy for Keychain application
  let currentEntropy = deriveBIP85Entropy(KEYCHAIN_APP_CODE, masterNode);

  let finalIndex = 0;

  for (const segment of semanticPath) {
    // Pass nonce through all segments if provided
    const childIndex = semanticToIndex(segment, currentEntropy, true, options?.nonce);
    const unhardenedIndex = childIndex & 0x7fffffff;
    finalIndex = unhardenedIndex;

    currentPath = `${currentPath}/${unhardenedIndex}'`;

    const childNode = masterNode.derive(currentPath);
    if (!childNode.privateKey) {
      throw new Error(`Failed to derive child node at ${currentPath}`);
    }

    // Per Phase 2 spec: re-derive full BIP85 entropy for child to maintain 64-byte entropy throughout chain.
    // Must pass the unhardened index: deriveBIP85Entropy hardens it itself via the path string.
    currentEntropy = deriveBIP85Entropy(unhardenedIndex, childNode);
  }

  const finalEntropy = currentEntropy;
  const agePrivateKey = deriveDeterministicAgeKey(finalEntropy, finalIndex);
  const rawSecret = hmac(sha256, finalEntropy, u64BE(finalIndex));
  const agePublicKey = derivePublicKey(rawSecret);

  return {
    derivationPath: currentPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: bufferToHex(finalEntropy),
    semanticPath,
  };
}
