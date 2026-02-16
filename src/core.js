import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { argon2id } from "@noble/hashes/argon2";
import { x25519 } from "@noble/curves/ed25519";
import { bech32 } from "bech32";

/** @param {string} passphrase */
export function deriveMasterKey(passphrase) {
  const salt = new TextEncoder().encode("age-keygen-deterministic-hardcoded-salt");
  return argon2id(passphrase, salt, {
    t: 10,
    m: 65536,
    p: 2,
    dkLen: 64,
  });
}

/** @param {Uint8Array} buf */
export function bufferToHex(buf) {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** @param {Uint8Array} bytes */
export function intFromBytes(bytes) {
  return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

/**
 * @param {number} index
 * @param {HDKey} masterNode
 */
export function deriveBIP85Entropy(index, masterNode) {
  const path = `m/83696968'/${index}'`;
  const child = masterNode.derive(path);
  if (!child.privateKey) {
    throw new Error("Failed to derive privateKey from child node.");
  }
  return sha256(child.privateKey);
}

/**
 * @param {Uint8Array} masterKey
 * @param {number} index
 */
export function deriveDeterministicAgeKey(masterKey, index) {
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false);
  const key = hmac(sha256, masterKey, indexBytes);
  const keyU5 = bech32.toWords(key);
  return bech32.encode("AGE-SECRET-KEY-", keyU5, 1023).toUpperCase();
}

/** @param {string} mnemonic */
export function deriveMasterNodeFromMnemonic(mnemonic) {
  const seed = mnemonicToSeedSync(mnemonic);
  return HDKey.fromMasterSeed(seed);
}

/**
 * @param {number} keyVersion
 * @param {string} appId
 * @param {string} filename
 */
export function deriveIndexes(keyVersion, appId, filename) {
  const appIdHash = sha256(new TextEncoder().encode(appId));
  const filenameHash = sha256(new TextEncoder().encode(filename));

  const indexes = [
    keyVersion,
    intFromBytes(appIdHash.slice(0, 4)),
    intFromBytes(filenameHash.slice(0, 4)),
  ].map((x) => x & 0x7fffffff);

  return {
    indexes,
    appIdHash,
    filenameHash,
    derivationPath: `m/83696968'/128169'/${indexes[0]}'/${indexes[1]}'/${indexes[2]}'`,
  };
}

/**
 * @param {HDKey} masterNode
 * @param {number} keyVersion
 * @param {string} appId
 * @param {string} filename
 */
export function deriveKeyAndIV(masterNode, keyVersion, appId, filename) {
  const { indexes, filenameHash, derivationPath } = deriveIndexes(keyVersion, appId, filename);

  const entropy = deriveBIP85Entropy(indexes[0], masterNode);
  const agePrivateKey = deriveDeterministicAgeKey(entropy, indexes[0]);

  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(indexes[0]), false);
  const rawSecret = hmac(sha256, entropy, indexBytes);
  const pubBytes = x25519.getPublicKey(rawSecret);
  const agePublicKey = bech32.encode("age", bech32.toWords(pubBytes), 1023).toLowerCase();

  return {
    derivationPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: bufferToHex(entropy),
    iv: bufferToHex(filenameHash.slice(0, 12)),
  };
}

/**
 * @param {string} mnemonic
 * @param {number} keyVersion
 * @param {string} appId
 * @param {string} filename
 */
export function deriveFromMnemonic(mnemonic, keyVersion, appId, filename) {
  return deriveKeyAndIV(deriveMasterNodeFromMnemonic(mnemonic), keyVersion, appId, filename);
}
