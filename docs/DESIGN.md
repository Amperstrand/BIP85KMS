# BIP85KMS Phase 2: Standards-Aligned Architecture & Design

**Phase 2 Deliverable:** Detailed architectural design for standards-compliant deterministic semantic key derivation library.

**Status:** Design specification (before implementation)  
**Target:** Interoperability with BIP32, BIP39, BIP85, RFC8785, BIP-Keychain (draft), Age encryption

**Date:** August 31, 2026

---

## Executive Summary

This document specifies the corrected architecture for BIP85KMS that:
1. ✅ Fixes all BIP85 entropy extraction to match spec
2. ✅ Implements BIP-Keychain semantic path imaging correctly
3. ✅ Maintains 64-byte entropy throughout derivation chain
4. ✅ Adds optional nonce/versioning for semantic paths
5. ✅ Separates core library from output adapters
6. ✅ Defines clear security boundaries
7. ✅ Enables test vector validation against official standards

---

## Part 1: Core Concepts & Hierarchy

### Derivation Conceptual Hierarchy

```
BIP39 Mnemonic (12-24 words)
    ↓ PBKDF2-HMAC-SHA512 (2048 iterations)
BIP32 Seed (64 bytes)
    ↓ HMAC-SHA512(key="Bitcoin seed", msg=seed)
BIP32 Master Node (private key + chain code)
    ↓ Derive fully-hardened path m/83696968'/{application_code}'
BIP85 Entropy (64 bytes per HMAC-SHA512-based function)
    ├─→ [Semantic Path] JSON-LD segments → HMAC-SHA512 imaging → BIP32 indexes → Entropy chain
            ↓ Final entropy (64 bytes)
    ├─→ [Age Adapter] X25519 → Bech32-encoded Age identity/recipient
    ├─→ [Raw Adapter] Hex-encoded 32/64-byte entropy
    └─→ [Other Adapters] AES key material, OpenPGP, etc. (per BIP85 apps)
```

### Key Design Principles

1. **BIP85 Entropy is Sacred:** 64-byte HMAC-SHA512 output is the canonical form; never truncate or hash it again
2. **Semantic Derivation is Path-Transparent:** Same semantic structure always produces identical BIP32 indexes and final entropy
3. **Nonce-Based Versioning:** Optional nonce enables key rotation without semantic restructuring
4. **Domain Separation:** Every cryptographic operation explicitly names its domain
5. **Adapter Pattern:** Core library exports raw entropy; adapters convert to specific key formats
6. **No Implicit Outputs:** Library never logs, serializes, or outputs secret key material without explicit caller request

---

## Part 2: BIP85 Entropy Extraction (Corrected)

### Algorithm: `bip85Entropy(index: number, masterNode: HDKey): Uint8Array`

**Purpose:** Derive 64 bytes of cryptographically strong entropy from a BIP32 master node, per BIP85 spec.

**Inputs:**
- `index` — Application code (e.g., 128169' for HEX, 67797668' for BIP-Keychain)
- `masterNode` — BIP32 master HD node

**Output:** 64 bytes (512 bits) of entropy

**Algorithm:**

```
FUNCTION bip85Entropy(index: uint32, masterNode: HDKey): Uint8Array
  
  // Step 1: Derive fully-hardened child at m/83696968'/{index}'
  // BIP85 spec: all path components must be hardened (have 0x80000000 bit set)
  path ← "m/83696968'/" + index + "'"
  child ← masterNode.derive(path)
  k ← child.privateKey  // 32-byte scalar
  
  if k is null or k has length ≠ 32:
    raise Error("Failed to derive 32-byte private key")
  
  // Step 2: Apply domain-separated HMAC-SHA512
  // BIP85 domain-separation string: "bip-entropy-from-k"
  // This ensures BIP85 entropy cannot be confused with other uses of child private keys
  domain_string ← UTF8("bip-entropy-from-k")
  entropy ← HMAC-SHA512(key=domain_string, message=k)
  
  // HMAC-SHA512 produces exactly 64 bytes (512 bits)
  assert entropy.length == 64
  
  RETURN entropy  // Full 64 bytes, never truncated
END FUNCTION
```

**Critical Points:**

1. **All path components are hardened** (have 0x80000000 bit set)
2. **HMAC-SHA512 with explicit domain-separation** (key="bip-entropy-from-k", message=32-byte private key)
3. **Output is always 64 bytes** (never truncated)
4. **Security property:** Each application code produces independent 64-byte entropy stream

### Pseudocode Example

```
MasterNode ← HDKey.fromMasterSeed(seed)
Entropy_HEX ← bip85Entropy(128169, MasterNode)  // 64 bytes for HEX entropy app
Entropy_Keychain ← bip85Entropy(67797668, MasterNode)  // 64 bytes for Keychain app
```

---

## Part 3: Semantic Path Derivation (BIP-Keychain Aligned)

### Overview

Semantic paths transform human-meaningful JSON-LD objects into BIP32 child indexes via HMAC-SHA512-based "imaging function." Each segment maps to a BIP32 index through:

1. **Canonicalization:** JSON-LD object → RFC8785 JSON Canonical Form
2. **Imaging:** HMAC-SHA512(parent_entropy, canonical_json ‖ nonce?) → 512 bits
3. **Index Extraction:** Top 31 bits from 512-bit output
4. **Hardening:** Set 0x80000000 bit (hardened child derivation)
5. **Chaining:** Update parent entropy from derived child node, repeat for next segment

### Algorithm: `semanticToIndex(segment, parentEntropy, hardened, nonce?): uint32`

**Purpose:** Convert a semantic segment to a BIP32 child index.

**Algorithm:**

```
FUNCTION semanticToIndex(
  segment: JSONLDObject,
  parentEntropy: Uint8Array[64],
  hardened: bool = true,
  nonce: Uint8Array? = null
): Uint32

  // Step 1: Validate JSON-LD format
  if segment is not JSONObject or segment["@type"] is null:
    raise Error("Semantic segment must have @type property")
  
  // Step 2: JSON Canonicalization (RFC8785)
  canonical ← jcs(segment)
  canonicalBytes ← UTF8(canonical)
  
  // Step 3: Construct message (canonical JSON + optional nonce)
  if nonce is provided:
    message ← concatenate(canonicalBytes, nonce)
  else:
    message ← canonicalBytes
  
  // Step 4: Domain-separated HMAC-SHA512
  domain ← UTF8("bip-keychain-semantic")
  hmacResult ← HMAC-SHA512(key=parentEntropy, message=message)
  
  // Step 5: Extract top 31 bits
  bytes4 ← hmacResult[0:4]
  value32 ← bytes4[0]<<24 | bytes4[1]<<16 | bytes4[2]<<8 | bytes4[3]
  index31bit ← value32 >> 1
  
  // Step 6: Conditionally set hardened bit (0x80000000)
  if hardened:
    childIndex ← index31bit | 0x80000000
  else:
    childIndex ← index31bit
  
  RETURN childIndex as Uint32

END FUNCTION
```

### Algorithm: `deriveFromSemanticPath(masterNode, semanticPath, nonce?): SemanticDerivationResult`

**Purpose:** Derive Age keys and entropy from a semantic path (sequence of JSON-LD segments).

**Algorithm:**

```
FUNCTION deriveFromSemanticPath(
  masterNode: HDKey,
  semanticPath: Array<JSONLDObject>,
  nonce: Uint8Array? = null
): SemanticDerivationResult

  // Validation
  if semanticPath is not array or semanticPath.length == 0:
    raise Error("Semantic path must be a non-empty array")
  
  if semanticPath.length > MAX_SEMANTIC_PATH_DEPTH (16):
    raise Error("Semantic path exceeds maximum depth")
  
  // Validate each segment
  for segment in semanticPath:
    validateJSONLD(segment)
  
  // Step 1: Initialize with BIP85 entropy for Keychain app
  applicationCode ← 67797668  // BIP-Keychain semantic paths
  currentPath ← "m/83696968'/" + applicationCode + "'"
  currentEntropy ← bip85Entropy(applicationCode, masterNode)
  
  // Step 2: Iterate through each semantic segment
  for i in range(semanticPath.length):
    segment ← semanticPath[i]
    
    // Convert segment to child index
    childIndex ← semanticToIndex(segment, currentEntropy, hardened=true, nonce=nonce)
    indexWithoutHardenedBit ← childIndex & 0x7FFFFFFF
    
    // Extend path
    currentPath ← currentPath + "/" + indexWithoutHardenedBit + "'"
    
    // Derive child node and update entropy
    childNode ← masterNode.derive(currentPath)
    if childNode.privateKey is null:
      raise Error("Failed to derive child node at path: " + currentPath)
    
    // Update entropy for next iteration
    currentEntropy ← bip85Entropy(childIndex, childNode)
  
  // Step 3: After all segments, derive final Age keys from entropy
  finalEntropy ← currentEntropy  // 64 bytes
  finalIndex ← childIndex  // Use last segment's index
  
  agePrivateKey ← deriveAgeSecretKey(finalEntropy, finalIndex)
  rawSecret ← HMAC-SHA256(key=finalEntropy, message=u64BE(finalIndex))
  agePublicKey ← deriveAgePublicKey(rawSecret)
  
  RETURN SemanticDerivationResult(
    derivationPath: currentPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: hexEncode(finalEntropy),
    semanticPath: semanticPath
  )

END FUNCTION
```

---

## Part 4: Age Key Adapter (Standards-Based Output)

### Algorithm: `deriveAgeSecretKey(entropy, index): string`

**Purpose:** Derive Age-compatible private key encoding from raw entropy.

**Algorithm:**

```
FUNCTION deriveAgeSecretKey(entropy: Uint8Array[64], index: Uint32): string

  // Step 1: Extract 32-byte identity from entropy via HMAC-SHA256
  domain ← UTF8("age-secret-key")
  identity ← HMAC-SHA256(key=entropy, message=domain + u64BE(index))
  
  // Step 2: Encode as Bech32 with HRP "AGE-SECRET-KEY-"
  words ← convertBits(identity, frombits=8, tobits=5)
  checksum ← bech32Checksum("age-secret-key-", words)
  encoded ← "AGE-SECRET-KEY-1" + base32(words + checksum)
  
  RETURN encoded.toUpperCase()

END FUNCTION
```

### Algorithm: `deriveAgePublicKey(rawSecret): string`

**Purpose:** Derive Age-compatible public key (recipient) from raw secret.

**Algorithm:**

```
FUNCTION deriveAgePublicKey(rawSecret: Uint8Array[32]): string

  // Step 1: Use X25519 to derive public key
  identity ← rawSecret
  recipient ← X25519.publicKey(identity)
  
  // Step 2: Encode as Bech32 with HRP "age"
  words ← convertBits(recipient, frombits=8, tobits=5)
  checksum ← bech32Checksum("age", words)
  encoded ← "age" + "1" + base32(words + checksum)
  
  RETURN encoded.toLowerCase()

END FUNCTION
```

---

## Part 5: Semantic Segment Schema & Validation

### JSON-LD Requirements

Each semantic segment **MUST** be a JSON object with:

1. **@type** (required, string): Schema.org entity type
2. **@context** (optional but recommended): JSON-LD context (default: "https://schema.org")
3. **Other properties** (optional): Valid schema.org properties for the declared @type

### Validation Function

```
FUNCTION validateJSONLD(segment: unknown): void

  if segment is not object or is null or is array:
    raise Error("Segment must be a JSON object")
  
  if segment["@type"] is null or not string:
    raise Error("Segment must have @type property (string)")
  
  if segment["@context"] is not provided:
    segment["@context"] ← "https://schema.org"

END FUNCTION
```

### Example Valid Semantic Segments

**Organization:**
```json
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "AcmeCorp",
  "url": "https://acme.example.com"
}
```

**DigitalDocument:**
```json
{
  "@type": "DigitalDocument",
  "name": "database.sql",
  "fileFormat": "text/plain"
}
```

---

## Part 6: Application Code Allocation

### Corrected BIP85 Application Codes

| Code | Name | Purpose | Standard |
|------|------|---------|----------|
| 2' | HD-Seed WIF | Bitcoin Core WIF seed | BIP85 |
| 39' | BIP39 | Mnemonic phrases | BIP85 |
| 32' | XPRV | Extended private keys | BIP85 |
| 128169' | HEX | Raw entropy (16-64 bytes) | **BIP85 Standard—DO NOT USE** |
| 67797668' | **BIP-Keychain** | Semantic paths (JSON-LD) | BIP-Keychain Draft |

**⚠️ IMPORTANT:** Never use 128169' for BIP85KMS purposes. It is assigned by BIP85 standard to HEX entropy derivation.

---

## Part 7: Path Structure & Validation (BIP88 Alignment)

### Semantic Path Template (BIP88 Format)

```
Semantic Path:  m/83696968'/67797668'/{*}/{*}/.../{*}

Where:
  83696968' = BIP85 purpose (constant)
  67797668' = BIP-Keychain application code (constant)
  {*}       = Derived child index (hardened, 0x80000000-0xFFFFFFFF)
```

### Path Constraints

```
CONSTANT MAX_SEMANTIC_PATH_DEPTH = 16
CONSTANT MAX_SEMANTIC_SEGMENT_SIZE = 10_000 bytes
CONSTANT MAX_ENTROPY_SIZE = 64 bytes
CONSTANT MAX_INDEX_VALUE = 2^32 - 1
```

---

## Part 8: Nonce/Versioning Scheme

### Use Case: Key Rotation Without Semantic Restructuring

**Problem:** If semantic path defines a role but a key needs rotation, allow new child without changing semantic structure.

**Solution:** Optional nonce parameter:

```
deriveFromSemanticPath(
  masterNode,
  semanticPath = [{"@type": "Organization", "name": "AcmeCorp"}],
  nonce = UTF8("v1")  // Version identifier
)

// Same semantic path with different nonce produces different final key
// Allows rotation: nonce "v1" → "v2" → "v3", etc.
```

### Recommended Nonce Format

```
UTF8("v" + version_number)

Examples:
  "v1" → UTF8([0x76, 0x31])
  "rotate-2026-09-01" → UTF8([...])
  
Empty string or null → no version (canonical semantic path only)
```

---

## Part 9: RFC8785 JSON Canonicalization

### Algorithm: `jcs(value): string`

```
FUNCTION jcs(value: any): string
  
  IF value == null:
    RETURN "null"
  ELSE IF value is boolean:
    RETURN "true" or "false"
  ELSE IF value is number:
    IF non-finite: raise Error
    RETURN decimal string (no exponent)
  ELSE IF value is string:
    RETURN JSON string literal (with escaping)
  ELSE IF value is array:
    RETURN "[" + join(",", [jcs(v) for v in value]) + "]"
  ELSE IF value is object:
    keys ← sorted(object.keys)
    pairs ← [JSON.stringify(key) + ":" + jcs(object[key]) for key in keys]
    RETURN "{" + join(",", pairs) + "}"
    
END FUNCTION
```

---

## Part 10: Derivation Path Examples (Concrete)

### Example 1: Single-Segment Semantic Path

**Input:**
```json
{
  "mnemonic": "bacon bacon bacon ... bacon",
  "semanticPath": [
    {"@type": "WebSite", "url": "https://example.com"}
  ]
}
```

**Processing:**
```
1. Seed = PBKDF2-HMAC-SHA512(mnemonic, salt, 2048 iterations)
2. MasterNode = BIP32.fromMasterSeed(seed)
3. Entropy_Keychain = bip85Entropy(67797668, MasterNode)  // 64 bytes
4. Index0 = semanticToIndex(segment, Entropy_Keychain, hardened=true)
5. Path = "m/83696968'/67797668'/{index0}'"
6. ChildNode = MasterNode.derive(Path)
7. FinalEntropy = bip85Entropy(Index0, ChildNode)
8. AgeSecret = deriveAgeSecretKey(FinalEntropy, Index0)
9. AgePublic = deriveAgePublicKey(HMAC-SHA256(FinalEntropy, Index0))
```

**Output:**
```json
{
  "derivationPath": "m/83696968'/67797668'/1234567890'",
  "age_private_key": "AGE-SECRET-KEY-1ABCDEFG...",
  "age_public_key": "age1xyzabc...",
  "raw_entropy": "a1b2c3d4e5f6..."
}
```

### Example 2: Multi-Segment Semantic Path

**Input:**
```json
{
  "semanticPath": [
    {"@type": "Organization", "name": "AcmeCorp"},
    {"@type": "SoftwareApplication", "name": "backup-system"},
    {"@type": "DigitalDocument", "name": "database.sql"}
  ]
}
```

**Output:**
```json
{
  "derivationPath": "m/83696968'/67797668'/123456789'/987654321'/555555555'",
  "age_private_key": "AGE-SECRET-KEY-1...",
  "age_public_key": "age1...",
  "raw_entropy": "..."
}
```

---

## Part 11: Test Vector Strategy

### Official Test Vectors (Must Pass)

1. **BIP32 Test Vectors** (4 from spec) — Validate master node derivation
2. **BIP39 Test Vectors** (Trezor repo) — Validate mnemonic-to-seed
3. **BIP85 Test Vectors** (BIP85 spec) — Validate `bip85Entropy()` for all app codes
4. **RFC8785 Vectors** (RFC spec) — Validate `jcs()` canonicalization
5. **Age Encryption Vectors** — Validate key encoding

### Golden Vectors (BIP-Keychain, Generate First Time)

Since BIP-Keychain has no official vectors yet:

1. Derive deterministic reference vectors from normative algorithm
2. Cross-check against Python implementation
3. Store in `test/fixtures/bip-keychain-golden-vectors.json`
4. Tag with algorithm version for future spec changes

---

## Part 12: Security Considerations

### Threats Protected

- ✅ Key storage breaches (deterministic derivation)
- ✅ Key synchronization issues (identical inputs → identical keys)
- ✅ Semantic path exposure (entropy never disclosed implicitly)

### Threats NOT Protected

- ❌ Mnemonic compromise (all keys compromised; no revocation)
- ❌ Side-channel attacks (no timing-attack mitigation)
- ❌ Unauthenticated API access (authentication layer responsibility)
- ❌ Nonce reuse attacks (caller responsibility)

### Implementation Security

1. **No Secret Logging:** Library never logs mnemonic, seed, private keys, entropy
2. **Explicit Caller Intent:** Require explicit `getPrivateKey: true` for secret output
3. **Input Validation:** All semantic segments validated before use
4. **Overflow Protection:** All numeric operations checked

---

## Part 13: Summary of Corrections

| Algorithm | Current (BROKEN) | Corrected (Phase 2) |
|-----------|------------------|-------------------|
| BIP85 Entropy | SHA256(k) → 32B | HMAC-SHA512("bip-entropy-from-k", k) → 64B |
| Semantic Imaging | HMAC-SHA256 | HMAC-SHA512 |
| Entropy Chaining | SHA256(child) | bip85Entropy(childIndex, childNode) |
| Nonce/Versioning | None | Optional nonce parameter |
| Path Validation | None | BIP88 constraints |
| Age Key Derivation | Direct HMAC | HMAC-SHA256(entropy, index) |

---

## References

- **BIP32:** https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- **BIP39:** https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- **BIP85:** https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki (v2.1.0)
- **BIP88:** https://github.com/bitcoin/bips/blob/master/bip-0088.mediawiki
- **RFC8785:** https://datatracker.ietf.org/doc/html/rfc8785
- **BIP-Keychain Draft:** https://github.com/akarve/bip-keychain
- **Age Encryption:** https://age-encryption.org/v1
- **bipsea:** https://github.com/akarve/bipsea

