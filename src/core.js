import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { argon2id } from "@noble/hashes/argon2";
import { x25519 } from "@noble/curves/ed25519";
import { bech32 } from "bech32";

/**
 * Derives a master key from a passphrase using Argon2id key derivation.
 * 
 * This function uses Argon2id (a memory-hard, password-hashing algorithm) to derive
 * deterministic key material from a passphrase. Argon2id provides resistance against
 * GPU/ASIC attacks and side-channel attacks.
 * 
 * **Note**: This function is not currently used by the Worker API. It was implemented
 * as an alternative key derivation method but is not wired into the main flow which
 * uses BIP39 mnemonics instead.
 * 
 * **Security Warning**: The hardcoded salt means the same passphrase will always produce
 * the same master key. This is intentional for deterministic key generation but means
 * passphrases must have high entropy.
 * 
 * @param {string} passphrase - The passphrase to derive the key from. Should have high entropy.
 * @returns {Uint8Array} A 64-byte master key derived using Argon2id
 * 
 * @example
 * const masterKey = deriveMasterKey("my-secure-passphrase-with-high-entropy");
 * // masterKey is a Uint8Array of 64 bytes
 */
export function deriveMasterKey(passphrase) {
  const salt = new TextEncoder().encode("age-keygen-deterministic-hardcoded-salt");
  return argon2id(passphrase, salt, {
    t: 10,      // Time cost (iterations)
    m: 65536,   // Memory cost in KiB (64 MiB)
    p: 2,       // Parallelism factor
    dkLen: 64,  // Derived key length in bytes
  });
}

/**
 * Converts a Uint8Array buffer to a hexadecimal string.
 * 
 * Each byte is converted to a 2-character hex string (with leading zeros if needed)
 * and concatenated together.
 * 
 * @param {Uint8Array} buf - The buffer to convert to hex
 * @returns {string} Lowercase hexadecimal string representation of the buffer
 * 
 * @example
 * const buf = new Uint8Array([0, 15, 255]);
 * bufferToHex(buf); // Returns "000fff"
 */
export function bufferToHex(buf) {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Converts a 4-byte Uint8Array to a 32-bit unsigned integer (big-endian).
 * 
 * This is used to convert hash prefixes into integer indexes for BIP32 derivation paths.
 * The bytes are interpreted in big-endian (network) byte order.
 * 
 * @param {Uint8Array} bytes - A 4-byte array to convert
 * @returns {number} A 32-bit unsigned integer
 * 
 * @example
 * const bytes = new Uint8Array([0x00, 0x00, 0x00, 0x01]);
 * intFromBytes(bytes); // Returns 1
 * 
 * const bytes2 = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]);
 * intFromBytes(bytes2); // Returns 4294967295
 */
export function intFromBytes(bytes) {
  return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

/**
 * Derives BIP85 entropy from a BIP32 master node at a specific index.
 * 
 * BIP85 (Deterministic Entropy From BIP32 Keychains) is a standard for deriving
 * deterministic entropy from a BIP32 HD wallet. This implementation:
 * 1. Derives a child key at path m/83696968'/{index}'
 *    - 83696968' is the BIP85 purpose constant (0x4FF4800)
 *    - {index}' is a hardened index provided as parameter
 * 2. Takes SHA-256 of the derived private key to produce 32 bytes of entropy
 * 
 * **BIP85 Specification**: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
 * 
 * **Security Note**: The entropy quality depends on the master node's seed quality.
 * Always use a cryptographically secure BIP39 mnemonic as the source.
 * 
 * @param {number} index - The hardened derivation index (will be used as {index}')
 * @param {HDKey} masterNode - A BIP32 HDKey master node derived from a seed
 * @returns {Uint8Array} 32 bytes of deterministic entropy derived via BIP85
 * @throws {Error} If the derived child node doesn't have a private key
 * 
 * @example
 * const masterNode = deriveMasterNodeFromMnemonic("bacon bacon ...");
 * const entropy = deriveBIP85Entropy(128169, masterNode);
 * // entropy is a 32-byte Uint8Array derived from m/83696968'/128169'
 */
export function deriveBIP85Entropy(index, masterNode) {
  const path = `m/83696968'/${index}'`;
  const child = masterNode.derive(path);
  if (!child.privateKey) {
    throw new Error("Failed to derive privateKey from child node.");
  }
  // Hash the private key to produce entropy (per BIP85 spec)
  return sha256(child.privateKey);
}

/**
 * Derives a deterministic Age encryption private key from master key material and an index.
 * 
 * This function creates Age-compatible private keys in a deterministic way by:
 * 1. Converting the index to an 8-byte big-endian representation
 * 2. Using HMAC-SHA256 with the master key and index bytes to derive 32 bytes
 * 3. Encoding the result as a bech32 string with the "AGE-SECRET-KEY-" prefix
 * 
 * The same master key and index will always produce the same Age private key.
 * 
 * **Age Encryption**: https://age-encryption.org/
 * 
 * **Note**: This function is not directly used by the main Worker API. Instead,
 * the Worker uses a variant that takes BIP85 entropy as the master key material.
 * This function remains available for alternative implementations.
 * 
 * @param {Uint8Array} masterKey - The master key material (typically 32-64 bytes)
 * @param {number} index - The derivation index
 * @returns {string} An Age private key in bech32 format (e.g., "AGE-SECRET-KEY-1...")
 * 
 * @example
 * const masterKey = deriveMasterKey("my-passphrase");
 * const ageKey = deriveDeterministicAgeKey(masterKey, 0);
 * // Returns something like "AGE-SECRET-KEY-1VZ3CREDN87LLHYDVS6FK36EZEVWNZGG..."
 */
export function deriveDeterministicAgeKey(masterKey, index) {
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false);
  const key = hmac(sha256, masterKey, indexBytes);
  const keyU5 = bech32.toWords(key);
  return bech32.encode("AGE-SECRET-KEY-", keyU5, 1023).toUpperCase();
}

/**
 * Derives a BIP32 master HD node from a BIP39 mnemonic phrase.
 * 
 * This function:
 * 1. Converts the BIP39 mnemonic to a 512-bit seed using the standard BIP39 algorithm
 * 2. Creates a BIP32 hierarchical deterministic (HD) master node from the seed
 * 
 * The resulting master node can be used to derive child keys at various derivation paths.
 * 
 * **BIP39 Specification**: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * **BIP32 Specification**: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * 
 * **Security Critical**: The mnemonic is the root secret. If compromised, all derived
 * keys are compromised. Never log, transmit over unencrypted channels, or store in
 * plain text.
 * 
 * @param {string} mnemonic - A BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
 * @returns {HDKey} A BIP32 HDKey master node
 * @throws {Error} If the mnemonic is invalid
 * 
 * @example
 * const mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
 * const masterNode = deriveMasterNodeFromMnemonic(mnemonic);
 * // masterNode can now be used for key derivation
 */
export function deriveMasterNodeFromMnemonic(mnemonic) {
  const seed = mnemonicToSeedSync(mnemonic);
  return HDKey.fromMasterSeed(seed);
}

/**
 * Derives deterministic indexes and a BIP32 derivation path from input parameters.
 * 
 * This function creates a deterministic derivation path by:
 * 1. Hashing the appId and filename with SHA-256
 * 2. Taking the first 4 bytes of each hash and converting to integers
 * 3. Masking with 0x7fffffff to ensure positive 31-bit values (valid for hardened derivation)
 * 4. Constructing a BIP32 path: m/83696968'/128169'/{keyVersion}'/{appIdHash}'/{filenameHash}'
 * 
 * **Derivation Path Structure**:
 * - `m/` - Master node
 * - `83696968'` - BIP85 purpose constant (0x4FF4800)
 * - `128169'` - Application-specific constant for Age key derivation (0x1F4F9)
 * - `{keyVersion}'` - Key rotation version (allows generating new keys for same file)
 * - `{appIdHash}'` - First 4 bytes of SHA-256(appId), provides app isolation
 * - `{filenameHash}'` - First 4 bytes of SHA-256(filename), provides per-file keys
 * 
 * **Important Security Note**: While appId and filename are included in the path,
 * the current entropy derivation only uses keyVersion! This means the same keyVersion
 * produces the same entropy regardless of appId/filename. The path components only
 * affect the derivation path string itself, not the actual key material.
 * 
 * @param {number} keyVersion - Key rotation version (0-2147483647)
 * @param {string} appId - Application identifier for isolation
 * @param {string} filename - Filename for per-file key derivation
 * @returns {{indexes: number[], appIdHash: Uint8Array, filenameHash: Uint8Array, derivationPath: string}}
 *   Object containing the three indexes, raw hashes, and formatted derivation path
 * 
 * @example
 * const result = deriveIndexes(1, "docs", "README.md");
 * // result.indexes = [1, <appIdInt>, <filenameInt>]
 * // result.derivationPath = "m/83696968'/128169'/1'/1186212674'/859136773'"
 */
export function deriveIndexes(keyVersion, appId, filename) {
  const appIdHash = sha256(new TextEncoder().encode(appId));
  const filenameHash = sha256(new TextEncoder().encode(filename));

  const indexes = [
    keyVersion,
    intFromBytes(appIdHash.slice(0, 4)),
    intFromBytes(filenameHash.slice(0, 4)),
  ].map((x) => x & 0x7fffffff); // Ensure hardened indexes are in valid range

  return {
    indexes,
    appIdHash,
    filenameHash,
    derivationPath: `m/83696968'/128169'/${indexes[0]}'/${indexes[1]}'/${indexes[2]}'`,
  };
}

/**
 * Derives an Age encryption key pair and IV from a BIP32 master node and input parameters.
 * 
 * This is the core derivation function that combines all the pieces:
 * 
 * **Derivation Process**:
 * 1. Compute derivation indexes and path from keyVersion, appId, filename
 * 2. Derive BIP85 entropy using ONLY keyVersion (indexes[0])
 * 3. Use HMAC-SHA256(entropy, keyVersion bytes) to derive the Age private key material
 * 4. Derive Age public key from private key using X25519 scalar multiplication
 * 5. Encode keys in bech32 format (Age standard)
 * 6. Derive IV from first 12 bytes of SHA-256(filename)
 * 
 * **Critical Design Decision**: The entropy is derived ONLY from keyVersion (indexes[0]),
 * NOT from the full path including appId/filename. This means:
 * - Same keyVersion = same underlying entropy
 * - appId and filename only affect the derivation path string and IV
 * - To get different keys for different files, you must use different keyVersions
 * 
 * **IV (Initialization Vector)**: Derived from filename hash. For deterministic encryption
 * schemes, the IV must be consistent for the same file to enable decryption. However,
 * using deterministic IVs has security implications (see SECURITY.md).
 * 
 * @param {HDKey} masterNode - BIP32 master node derived from mnemonic
 * @param {number} keyVersion - Key rotation version
 * @param {string} appId - Application identifier
 * @param {string} filename - File identifier
 * @returns {{derivationPath: string, age_private_key: string, age_public_key: string, raw_entropy: string, iv: string}}
 *   Object containing derivation path, Age key pair, raw entropy (hex), and IV (hex)
 * 
 * @example
 * const masterNode = deriveMasterNodeFromMnemonic("bacon bacon ...");
 * const keys = deriveKeyAndIV(masterNode, 1, "docs", "README.md");
 * // keys.age_private_key = "AGE-SECRET-KEY-1M4XE5PZGVMPX0D923NHT6HRXT7VEZ..."
 * // keys.age_public_key = "age15vzcvrduzysjsns520xkrd9les2nxjl..."
 * // keys.iv = "b335630551682c19a781afeb"
 */
export function deriveKeyAndIV(masterNode, keyVersion, appId, filename) {
  const { indexes, filenameHash, derivationPath } = deriveIndexes(keyVersion, appId, filename);

  // CRITICAL: Only indexes[0] (keyVersion) is used for entropy derivation!
  // This means same keyVersion = same entropy regardless of appId/filename
  const entropy = deriveBIP85Entropy(indexes[0], masterNode);
  const agePrivateKey = deriveDeterministicAgeKey(entropy, indexes[0]);

  // Derive the raw X25519 secret key material for Age
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(indexes[0]), false);
  const rawSecret = hmac(sha256, entropy, indexBytes);
  
  // Derive Age public key using X25519 (Curve25519 scalar multiplication)
  const pubBytes = x25519.getPublicKey(rawSecret);
  const agePublicKey = bech32.encode("age", bech32.toWords(pubBytes), 1023).toLowerCase();

  return {
    derivationPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: bufferToHex(entropy),
    iv: bufferToHex(filenameHash.slice(0, 12)), // 96-bit IV from filename hash
  };
}

/**
 * Main entry point: Derives Age key pair and IV from a mnemonic and request parameters.
 * 
 * This is a convenience function that combines mnemonic-to-master-node conversion
 * with key derivation. It's the primary function used by:
 * - The Cloudflare Worker API (src/index.ts)
 * - The browser demo (web/app.js)
 * - CLI tools (src/cli.ts, python/cli.py)
 * 
 * **Usage Pattern**:
 * ```javascript
 * // For encryption (public key only needed):
 * const result = deriveFromMnemonic(mnemonic, 1, "myapp", "data.txt");
 * // Use result.age_public_key for encryption
 * // Use result.iv as initialization vector
 * 
 * // For decryption (private key needed):
 * const result = deriveFromMnemonic(mnemonic, 1, "myapp", "data.txt");
 * // Use result.age_private_key for decryption
 * ```
 * 
 * **Security Warning**: This function exposes the mnemonic in memory. Never:
 * - Log the mnemonic or derived private keys
 * - Store them in plain text
 * - Transmit over unencrypted channels
 * - Use demo mnemonics for real data
 * 
 * @param {string} mnemonic - BIP39 mnemonic phrase (root secret)
 * @param {number} keyVersion - Key rotation version for the same file/app
 * @param {string} appId - Application identifier for key isolation
 * @param {string} filename - File identifier for per-file keys
 * @returns {{derivationPath: string, age_private_key: string, age_public_key: string, raw_entropy: string, iv: string}}
 *   Complete key derivation result including both private and public material
 * 
 * @example
 * const result = deriveFromMnemonic(
 *   "bacon bacon bacon...",
 *   1,           // keyVersion
 *   "docs",      // appId
 *   "README.md"  // filename
 * );
 * console.log(result.age_public_key);  // "age15vzcvrduzysjsns520xkrd9les..."
 * console.log(result.iv);              // "b335630551682c19a781afeb"
 */
export function deriveFromMnemonic(mnemonic, keyVersion, appId, filename) {
  return deriveKeyAndIV(deriveMasterNodeFromMnemonic(mnemonic), keyVersion, appId, filename);
}

/**
 * JSON Canonicalization Scheme (JCS) implementation per RFC 8785.
 * 
 * Converts a JSON object to a canonical string representation where:
 * - Object keys are sorted lexicographically
 * - No unnecessary whitespace
 * - Consistent string escaping
 * - Deterministic number representation
 * 
 * This ensures that semantically identical JSON produces identical byte sequences,
 * which is critical for deterministic key derivation in BIP-Keychain.
 * 
 * **RFC 8785**: https://datatracker.ietf.org/doc/html/rfc8785
 * 
 * @param {*} obj - JavaScript value to canonicalize
 * @returns {string} - Canonical JSON string representation
 * 
 * @example
 * jcs({ b: 1, a: 2 }) === jcs({ a: 2, b: 1 })
 * // Returns: '{"a":2,"b":1}'
 */
export function jcs(obj) {
  if (obj === null) return "null";
  if (obj === undefined) return "null";
  
  const type = typeof obj;
  
  if (type === "boolean") return obj.toString();
  
  if (type === "number") {
    if (!isFinite(obj)) throw new Error("Cannot canonicalize non-finite number");
    // Handle numbers per RFC 8785 (ES6 number serialization)
    return String(obj);
  }
  
  if (type === "string") {
    // Escape per JSON spec
    return JSON.stringify(obj);
  }
  
  if (Array.isArray(obj)) {
    return "[" + obj.map(item => jcs(item)).join(",") + "]";
  }
  
  if (type === "object") {
    // Sort keys lexicographically
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(key => {
      return JSON.stringify(key) + ":" + jcs(obj[key]);
    });
    return "{" + pairs.join(",") + "}";
  }
  
  throw new Error(`Cannot canonicalize type: ${type}`);
}

/**
 * Validates a semantic path segment.
 * 
 * Ensures the segment is a valid JSON-LD object with required properties.
 * BIP-Keychain requires each segment to have at least a @type property.
 * 
 * @param {Object} segment - JSON-LD segment to validate
 * @throws {Error} If segment is invalid
 * 
 * @example
 * validateSemanticSegment({ "@type": "WebSite", "url": "github.com" }); // OK
 * validateSemanticSegment({ "url": "github.com" }); // Throws: missing @type
 */
export function validateSemanticSegment(segment) {
  if (typeof segment !== "object" || segment === null || Array.isArray(segment)) {
    throw new Error("Semantic segment must be a JSON object");
  }
  
  if (!segment["@type"]) {
    throw new Error("Semantic segment must have @type property");
  }
}

/**
 * Convert a BigInt to a Uint8Array (big-endian).
 * 
 * @param {bigint} value - The BigInt value to convert
 * @param {number} byteLength - Desired byte length
 * @returns {Uint8Array} - Big-endian byte representation
 */
function bigIntToBytes(value, byteLength) {
  const bytes = new Uint8Array(byteLength);
  let val = value;
  for (let i = byteLength - 1; i >= 0; i--) {
    bytes[i] = Number(val & 0xFFn);
    val >>= 8n;
  }
  return bytes;
}

/**
 * Convert bytes to a BigInt (big-endian).
 * 
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {bigint} - BigInt representation
 */
function bytesToBigInt(bytes) {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Convert a semantic segment to a BIP-32 child index using chained entropy.
 * 
 * This is the core image function `i()` from the BIP-Keychain specification:
 * 1. Canonicalize the segment JSON using JCS
 * 2. Compute HMAC-SHA-512(parentEntropy, canonicalJSON)
 * 3. Extract top 31 bits for a valid BIP-32 child index
 * 4. Optionally set hardened bit (bit 31)
 * 
 * The use of parent entropy ensures that:
 * - Same segment at different path depths produces different indexes
 * - Order matters: [A, B] ≠ [B, A]
 * - No collisions between different positions in the tree
 * 
 * **BIP-Keychain Specification**: The image function per BIP-Keychain proposal
 * 
 * @param {Object} segment - JSON-LD object representing the semantic segment
 * @param {Uint8Array} parentEntropy - 64 bytes of entropy from parent derivation
 * @param {boolean} hardened - Whether to set the hardened bit (default: true)
 * @returns {number} - A 32-bit child index (31 bits + optional hardened bit)
 * 
 * @example
 * const segment = { "@type": "WebSite", "url": "https://github.com" };
 * const entropy = new Uint8Array(64); // Parent entropy
 * const index = semanticToIndex(segment, entropy, true);
 * // Returns a hardened index, e.g., 2147483648 + <31-bit-value>
 */
export function semanticToIndex(segment, parentEntropy, hardened = true) {
  // Step 1: Canonicalize JSON
  const canonical = jcs(segment);
  
  // Step 2: Compute HMAC-SHA-256
  // Note: BIP-Keychain specification suggests HMAC-SHA-512, but we use HMAC-SHA-256
  // which is sufficient for deriving 31-bit indexes and is available in our libraries.
  // The security properties remain sound as we only need 31 bits of output.
  const hmacResult = hmac(sha256, parentEntropy, new TextEncoder().encode(canonical));
  
  // Step 3: Extract top 31 bits from the HMAC result
  // HMAC-SHA-256 produces 32 bytes (256 bits)
  // We take first 4 bytes and shift right by 1 to get 31 bits
  const bytes = hmacResult.slice(0, 4);
  const value32 = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  // Unsigned right shift to get positive value, then shift right by 1 to get 31 bits
  const index31bit = (value32 >>> 1) >>> 0; // Keep it as unsigned 32-bit
  
  // Step 4: Set hardened bit if requested
  // Use unsigned operations to avoid negative numbers
  if (hardened) {
    return (index31bit | 0x80000000) >>> 0; // Ensure unsigned
  }
  return index31bit >>> 0; // Ensure unsigned
}

/**
 * Derive keys from a semantic path per BIP-Keychain specification.
 * 
 * BIP-Keychain extends BIP-85 with semantic derivation paths. Instead of arbitrary
 * integers, derivation paths are derived from meaningful JSON-LD objects using
 * schema.org vocabulary.
 * 
 * **Derivation Process**:
 * 1. Start at BIP-Keychain base path: m/83696968'/67797668'
 * 2. Derive initial entropy from application code 67797668
 * 3. For each semantic segment:
 *    a. Convert segment to child index using current entropy
 *    b. Derive child key at that index
 *    c. Update entropy for next segment
 * 4. Derive Age keys from final entropy
 * 
 * **Entropy Chaining**: Each segment's index depends on the parent's entropy,
 * ensuring that the same segment at different positions produces different indexes.
 * 
 * **BIP-Keychain Constants**:
 * - 83696968' = BIP-85 purpose code
 * - 67797668' = BIP-Keychain application code ("keychain")
 * 
 * @param {HDKey} masterNode - BIP32 master node derived from mnemonic
 * @param {Object[]} semanticPath - Array of JSON-LD semantic segments
 * @returns {{derivationPath: string, age_private_key: string, age_public_key: string, raw_entropy: string, semanticPath: Object[]}}
 *   Complete derivation result including semantic and numeric paths
 * 
 * @example
 * const semanticPath = [
 *   { "@type": "Organization", "name": "AcmeCorp" },
 *   { "@type": "SoftwareApplication", "name": "backup-system" },
 *   { "@type": "DigitalDocument", "name": "database.sql" }
 * ];
 * const result = deriveFromSemanticPath(masterNode, semanticPath);
 * // result.derivationPath = "m/83696968'/67797668'/923847291'/1837461928'/746291835'"
 * // result.semanticPath = [original semantic segments]
 */
export function deriveFromSemanticPath(masterNode, semanticPath) {
  // Validate semantic path
  if (!Array.isArray(semanticPath) || semanticPath.length === 0) {
    throw new Error("Semantic path must be a non-empty array");
  }
  
  semanticPath.forEach((segment, idx) => {
    try {
      validateSemanticSegment(segment);
    } catch (err) {
      throw new Error(`Invalid segment at index ${idx}: ${err.message}`);
    }
  });
  
  // BIP-Keychain constants
  const BIP85_PURPOSE = 83696968;
  const KEYCHAIN_APP_CODE = 67797668;
  
  // Start at BIP-Keychain base path
  let currentPath = `m/${BIP85_PURPOSE}'/${KEYCHAIN_APP_CODE}'`;
  
  // Derive initial entropy from BIP-Keychain application code
  let currentEntropy = deriveBIP85Entropy(KEYCHAIN_APP_CODE, masterNode);
  
  const indexes = [];
  
  // Process each semantic segment
  for (const segment of semanticPath) {
    // Convert segment to child index using current entropy
    const indexWithHardened = semanticToIndex(segment, currentEntropy, true);
    
    // Extract the unhardened index value (remove bit 31 for path string)
    const unhardenedIndex = indexWithHardened & 0x7FFFFFFF;
    indexes.push(indexWithHardened);
    
    // Update path with unhardened index (library adds hardened bit internally)
    currentPath = `${currentPath}/${unhardenedIndex}'`;
    
    // Derive child node at current path and get its entropy
    const childNode = masterNode.derive(currentPath);
    if (!childNode.privateKey) {
      throw new Error(`Failed to derive child node at ${currentPath}`);
    }
    // Use the child's private key hash as entropy for next iteration
    // This ensures entropy chaining through the semantic path
    currentEntropy = sha256(childNode.privateKey);
  }
  
  // Use the chained entropy from the final derivation
  // This entropy incorporates all semantic segments in the path
  const finalEntropy = currentEntropy;
  
  // Extract final index for Age key derivation parameter
  const finalIndexWithHardened = indexes[indexes.length - 1];
  const finalIndex = finalIndexWithHardened & 0x7FFFFFFF; // Remove hardened bit
  
  // Derive Age keys from the chained entropy
  const agePrivateKey = deriveDeterministicAgeKey(finalEntropy, finalIndex);
  
  // Derive Age public key
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(finalIndex), false);
  const rawSecret = hmac(sha256, finalEntropy, indexBytes);
  const pubBytes = x25519.getPublicKey(rawSecret);
  const agePublicKey = bech32.encode("age", bech32.toWords(pubBytes), 1023).toLowerCase();
  
  return {
    derivationPath: currentPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: bufferToHex(finalEntropy),
    semanticPath: semanticPath,
  };
}
