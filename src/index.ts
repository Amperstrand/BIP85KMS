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
 * effectively replicating BIP85 (m/83696968'/keyVersion'/appId'/filename_hash').
 */
function deriveBIP85Entropy(index: number, masterNode: HDKey): Uint8Array {
  const path = `m/83696968'/${index}'`;
  const child = masterNode.derive(path);
  if (!child.privateKey) {
    throw new Error("Failed to derive privateKey from child node.");
  }
  // 32-byte digest
  return sha256(child.privateKey);
}

/**
 * Generate a deterministic Age key using HMAC-SHA256 and Bech32 encoding.
 * Matches the Rust code:
 *   HMAC_SHA256(master_key, index) → 32 bytes → bech32("AGE-SECRET-KEY-", keyU5)
 * Then uppercase.
 */
export function deriveDeterministicAgeKey(masterKey: Uint8Array, index: number): string {
  // Convert index → big-endian 8 bytes
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false);

  // Full 32 bytes from HMAC
  const key = hmac(sha256, masterKey, indexBytes);

  // Convert to bech32 words
  const keyU5 = bech32.toWords(key);

  // Now encode with HRP = "AGE-SECRET-KEY-"
  const encoded = bech32.encode("AGE-SECRET-KEY-", keyU5, 1023);
  return encoded.toUpperCase();
}

/**
 * Derive an Age-compatible key and IV deterministically.
 * Adds a new field "age_public_key" by deriving from the same raw 32-byte secret.
 */
async function deriveKeyAndIV(masterNode: HDKey, keyVersion: number, appId: string, filename: string) {
  const appIdHash = sha256(new TextEncoder().encode(appId));
  const filenameHash = sha256(new TextEncoder().encode(filename));

  // We'll create indexes from:
  //   keyVersion (as given)
  //   first 4 bytes of appIdHash
  //   first 4 bytes of filenameHash
  // Then ensure each is masked to 0x7fffffff so they stay in the hardened path range.
  const indexes = [
    keyVersion,
    intFromBytes(appIdHash.slice(0, 4)),
    intFromBytes(filenameHash.slice(0, 4))
  ].map((x) => x & 0x7fffffff);

  const derivationPath = `m/83696968'/128169'/${indexes[0]}'/${indexes[1]}'/${indexes[2]}'`;

  // Derive a 32-byte subkey from BIP85-like logic
  const entropy = deriveBIP85Entropy(indexes[0], masterNode);

  // Then convert to Age key via HMAC → Bech32
  const agePrivateKey = deriveDeterministicAgeKey(entropy, indexes[0]);

  // Create a 12-byte IV from the beginning of filenameHash
  const ivHex = bufferToHex(filenameHash.slice(0, 12));

  // The raw secret used for generating the x25519 public key
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(indexes[0]), false);
  const rawSecret = hmac(sha256, entropy, indexBytes); // 32 bytes

  // X25519 public key from rawSecret
  const pubBytes = x25519.getPublicKey(rawSecret);
  const pubU5 = bech32.toWords(pubBytes);
  // produce "age1..."
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
 * Cloudflare Worker request handler:
 * Expects JSON: { filename, keyVersion, appId, getPrivateKey? }
 * If getPrivateKey is true, respond with full info; otherwise only { iv, age_public_key }.
 */
async function handleRequest(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  try {
    const { filename, keyVersion, appId, getPrivateKey } = await request.json() as {
      filename: string;
      keyVersion: number;
      appId: string;
      getPrivateKey?: boolean;
    };

    if (!filename || !appId || keyVersion === undefined) {
      return new Response(
        JSON.stringify({ error: "Missing filename, appId, or keyVersion" }),
        { status: 400 }
      );
    }

    // Fetch the secret from Cloudflare
    const mnemonic = env.MNEMONIC_SECRET;

    // Generate master seed from mnemonic
    const seed = mnemonicToSeedSync(mnemonic);
    const masterNode = HDKey.fromMasterSeed(seed);

    const result = await deriveKeyAndIV(masterNode, keyVersion, appId, filename);

    // If getPrivateKey is requested and true, return everything.
    if (getPrivateKey) {
      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" }
      });
    } else {
      return new Response(
        JSON.stringify({
          age_public_key: result.age_public_key,
          iv: result.iv
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), {
      status: 400
    });
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env);
  }
};

// Helpers
function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function intFromBytes(bytes: Uint8Array): number {
  return (
    (bytes[0] << 24) |
    (bytes[1] << 16) |
    (bytes[2] << 8) |
    bytes[3]
  );
}
