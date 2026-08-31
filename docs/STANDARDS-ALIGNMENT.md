# BIP85KMS Standards Alignment Analysis

**Phase 1 Deliverable:** Comprehensive comparison of current BIP85KMS behavior against Bitcoin/BIP standards and related prior art.

**Status:** Current implementation is a proof-of-concept with **significant divergences from standards**. This document identifies necessary corrections.

**Date:** August 31, 2026

---

## Executive Summary

BIP85KMS is currently a **non-standard hybrid** that combines:
- ✅ **Standards-compliant:** BIP32 (HD derivation), BIP39 (mnemonics), Age encryption format
- ❌ **Non-standard:** Custom entropy extraction, semantic path imaging, application code allocations
- 🚫 **Unspecified:** Numerous design choices without normative guidance

**Critical Issues Requiring Changes:**

1. **BIP85 Application Code Collision:** Current use of application code `67797668'` (BIP-Keychain draft) but with incorrect semantic imaging algorithm
2. **Semantic Path Imaging:** Current implementation uses HMAC-SHA256 + 31-bit extraction, but BIP-Keychain draft specifies HMAC-SHA512 + extraction from 512 bits
3. **Legacy Application Code:** Application code `128169'` is already reserved by BIP85 for HEX entropy; current use for generic legacy paths is a namespace collision
4. **Age Key Derivation:** Current method (HMAC-SHA256 of entropy indexed by path component) is not standardized; no interoperability path
5. **JCS Implementation:** Current RFC8785 implementation appears correct but not validated against vectors
6. **Test Vector Gaps:** No cross-check against official BIP32, BIP39, or BIP85 vectors; Python implementation exists as independent check but needs official vectors

---

## Comparison Matrix

### BIP32 — Hierarchical Deterministic Wallets (Deployed, Assigned)

| Aspect | Standard | Current BIP85KMS | Status | Issue |
|--------|----------|------------------|--------|-------|
| **Master Key Generation** | HMAC-SHA512(Key="Bitcoin seed", Data=seed) | ✓ Uses @scure/bip32 (correct) | ✓ COMPLIANT | None |
| **Child Key Derivation (Private→Private)** | CKDpriv: HMAC-SHA512 for hardened/normal | ✓ Uses @scure/bip32 | ✓ COMPLIANT | None |
| **Child Key Derivation (Public→Public)** | CKDpub: Only non-hardened children | ✓ Supported by @scure/bip32 | ✓ COMPLIANT | None |
| **Extended Key Format** | 78 bytes: version (4B), depth (1B), parent FP (4B), index (4B), chain code (32B), key (33B) | ✓ Uses @scure/bip32 | ✓ COMPLIANT | None |
| **Extended Key Serialization** | Base58Check encoding (xprv/xpub) | ✓ @scure/bip32 handles serialization | ✓ COMPLIANT | None |
| **Extended Key Private Format** | 33 bytes: 0x00 || ser256(k) | ✓ Library handles correctly | ✓ COMPLIANT | None |
| **Hardened Child Index** | Index >= 2^31 (0x80000000 bit set) | ✓ Used correctly (e.g., 83696968') | ✓ COMPLIANT | None |

**Verdict:** ✅ BIP32 implementation is fully standards-compliant via @scure/bip32 library.

---

### BIP39 — Mnemonic Code (Deployed, Assigned)

| Aspect | Standard | Current BIP85KMS | Status | Issue |
|--------|----------|------------------|--------|-------|
| **Entropy Size** | 128-256 bits (12-24 words) | ✓ @scure/bip39 enforces | ✓ COMPLIANT | None |
| **Checksum** | First ENT/32 bits of SHA256(entropy) | ✓ Library handles | ✓ COMPLIANT | None |
| **Mnemonic to Seed** | PBKDF2-HMAC-SHA512, 2048 iterations, salt="mnemonic"+passphrase | ✓ @scure/bip39 uses standard | ✓ COMPLIANT | None |
| **Unicode Normalization** | NFKD on mnemonic and passphrase | ✓ Library handles | ✓ COMPLIANT | None |
| **Wordlist Language** | 12 official languages (English, Japanese, Korean, Spanish, etc.) | ✓ Supported by @scure/bip39 | ✓ COMPLIANT | Library provides all 12 |
| **Wordlist Validation** | No two words share same 4-letter prefix | ✓ Library enforces | ✓ COMPLIANT | None |

**Verdict:** ✅ BIP39 implementation is fully standards-compliant via @scure/bip39 library.

---

### BIP43 — Purpose Field (Deployed, Assigned)

| Aspect | Standard | Current BIP85KMS | Status | Issue |
|--------|----------|------------------|--------|-------|
| **Purpose Namespace** | m/purpose'/ where purpose = BIP number | ✓ Correct: 83696968' = BIP85 | ✓ COMPLIANT | BIP85 is correct purpose |
| **All Children Hardened** | All segments under purpose are hardened (apostrophe notation) | ✓ All paths use hardened (m/83696968'/...) | ✓ COMPLIANT | None |

**Verdict:** ✅ BIP43 purpose allocation is correct.

---

### BIP85 — Deterministic Entropy From BIP32 Keychains (Deployed, Assigned 2020-03-20)

#### BIP85 Core Algorithm

| Aspect | Standard | Current BIP85KMS | Status | Issue |
|--------|----------|------------------|--------|-------|
| **Purpose** | 0x83696968 ("bip-85") | ✓ BIP85_PURPOSE = 83696968 | ✓ COMPLIANT | Correct |
| **Application Hierarchy** | m/83696968'/{app_no}'{index}' (or longer per app) | ✓ Supports multiple apps | ✓ COMPLIANT | See app code issues below |
| **Entropy Function** | HMAC-SHA512(key="bip-entropy-from-k", msg=k) where k is fully hardened private key | ❌ Uses SHA256 in deriveBIP85Entropy | 🚫 INCORRECT | **Issue #1:** Currently hashes child private key with SHA256; should use HMAC-SHA512 with domain-separation string |
| **Fully Hardened Derivation** | All path components hardened (0x80000000 bit set) | ✓ All indexes hardened | ✓ COMPLIANT | None |
| **Output Size** | 64 bytes (512 bits) entropy | ❌ Returns 32 bytes (SHA256 output) | 🚫 WRONG | **Issue #2:** Only returns 32 bytes; should return full 64 bytes from HMAC-SHA512 |

**Current Code (Incorrect):**
```typescript
// src/core.ts, line ~89
export function deriveBIP85Entropy(index: number, masterNode: HDKey): Uint8Array {
  const child = masterNode.derive(`m/${BIP85_PURPOSE}'/${index}'`);
  if (!child.privateKey) {
    throw new Error("Failed to derive privateKey from child node.");
  }
  return sha256(child.privateKey);  // ❌ WRONG: Should be HMAC-SHA512 with domain-separation
}
```

**Should Be (Correct):**
```typescript
export function deriveBIP85Entropy(index: number, masterNode: HDKey): Uint8Array {
  const child = masterNode.derive(`m/${BIP85_PURPOSE}'/${index}'`);
  if (!child.privateKey) {
    throw new Error("Failed to derive privateKey from child node.");
  }
  // ✅ CORRECT per BIP85 spec:
  return hmac(sha512, new TextEncoder().encode("bip-entropy-from-k"), child.privateKey);
}
```

#### BIP85 Application Codes

| Code | Name (BIP85) | Current BIP85KMS Use | Status | Issue |
|------|--------------|---------------------|--------|-------|
| 2' | HD-Seed WIF | Not used | ✓ OK | Unneeded for this project |
| 39' | BIP39 (mnemonic) | Not used | ✓ OK | Could derive new mnemonics |
| 32' | XPRV (extended private keys) | Not used | ✓ OK | Could derive child xprv |
| **128169'** | HEX (raw entropy) | **Repurposed for LEGACY_APP_CODE** | 🚫 COLLISION | **Issue #3:** BIP85 already specifies this code for 16-64 byte HEX entropy. Current use for "legacy numeric paths" hijacks an assigned namespace |
| 707764' | PWD BASE64 (passwords) | Not used | ✓ OK | Unused |
| 707785' | PWD BASE85 (passwords) | Not used | ✓ OK | Unused |
| 828365' | RSA | Not used | ✓ OK | Unused |
| 89101' | DICE | Not used | ✓ OK | Unused |
| 128002' | Nostr | Not used | ✓ OK | Unused |
| **67797668'** | Not in BIP85; reserved by BIP-Keychain draft | **Used for semantic paths** | 🚫 SPEC MISMATCH | **Issue #4:** Using draft BIP-Keychain code with non-conformant imaging algorithm |

**Verdict:** ❌ BIP85 implementation is **fundamentally incorrect**:
1. Entropy extraction uses SHA256 instead of HMAC-SHA512
2. Returns 32 bytes instead of full 64 bytes
3. Application code 128169' collides with BIP85 HEX entropy allocation
4. Semantic path imaging diverges from BIP-Keychain draft specification

---

### BIP-Keychain — General Secrets Keychain (Draft, Not Assigned)

**Note:** As of August 2026, BIP-Keychain is a **draft proposal** by Aneesh Karve. It is **NOT an assigned BIP number**. Current status:
- GitHub: https://github.com/akarve/bip-keychain
- Application code: 67797668' (allocated as draft proposal, not official)
- Status: TODO section lists missing components (test vectors, formal specification)

#### Semantic Path Imaging Algorithm

| Aspect | BIP-Keychain Draft | Current BIP85KMS | Status | Issue |
|--------|-------------------|------------------|--------|-------|
| **Semantic Segment Format** | JSON-LD object with @context and @type | ✓ Requires @type property | ✓ PARTIAL | Missing @context validation |
| **Canonicalization** | RFC8785 JSON Canonicalization Scheme (JCS) | ✓ Implements jcs() function | ✓ COMPLIANT | Implementation looks correct |
| **Parent Entropy** | BIP85 entropy for parent semantic path or root | ❌ Uses SHA256(child.privateKey) | 🚫 WRONG | **Issue #5:** Uses child key hash; should use full 64-byte BIP85 entropy |
| **Imaging Function** | `i(segment) := HMAC-SHA512(key=parent_entropy, msg=jcs(segment) + nonce) >> (512-31)` | ✓ **BUT** uses HMAC-SHA256 | 🚫 WRONG | **Issue #6:** semanticToIndex() uses HMAC-SHA256 instead of HMAC-SHA512 |
| **Bit Extraction** | Extract 31 most significant bits from 512-bit output | ✓ Extracts top 31 bits correctly | ✓ CORRECT | Uses (value32 >>> 1) |
| **Hardened Bit** | Optionally add hardened bit (0x80000000) | ✓ Has hardened parameter | ✓ COMPLIANT | Default hardened=true |
| **Optional Nonce** | Nonce field for key rotation within same semantic path | ❌ Not implemented | 🚫 MISSING | **Issue #7:** No nonce parameter; BIP-Keychain specifies optional nonce for versioning |
| **Final Index** | Final numeric child index for additional versioning | ✓ Uses finalIndex | ✓ OK | Correct usage |
| **Path Structure** | `m/83696968'/67797668'/{i(s_0)}/{i(s_1)}/.../{i(s_n)}/{index}` | ✓ Correct structure | ✓ COMPLIANT | None |

**Current Code (Incorrect):**
```typescript
// src/core.ts, line ~300
export function semanticToIndex(segment: SemanticSegment, parentEntropy: Uint8Array, hardened = true): number {
  const canonical = jcs(segment);
  const hmacResult = hmac(sha256, parentEntropy, new TextEncoder().encode(canonical)); // ❌ WRONG: sha256 not sha512
  const bytes = hmacResult.slice(0, 4);
  const value32 = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  const index31bit = (value32 >>> 1) >>> 0;
  return hardened ? (index31bit | 0x80000000) >>> 0 : index31bit >>> 0;
}
```

**Should Be (Correct):**
```typescript
export function semanticToIndex(
  segment: SemanticSegment,
  parentEntropy: Uint8Array,
  hardened = true,
  nonce?: Uint8Array
): number {
  const canonical = jcs(segment);
  const message = nonce 
    ? new Uint8Array([...new TextEncoder().encode(canonical), ...nonce])
    : new TextEncoder().encode(canonical);
  // ✅ CORRECT: HMAC-SHA512 per BIP-Keychain
  const hmacResult = hmac(sha512, parentEntropy, message);
  // Extract top 31 bits from 512-bit output
  const bytes = hmacResult.slice(0, 4);
  const value32 = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  const index31bit = (value32 >>> 1) >>> 0;
  return hardened ? (index31bit | 0x80000000) >>> 0 : index31bit >>> 0;
}
```

#### Entropy Chaining in Semantic Derivation

| Aspect | BIP-Keychain Draft | Current BIP85KMS | Status | Issue |
|--------|-------------------|------------------|--------|-------|
| **Parent Entropy** | Obtain BIP85 entropy for parent semantic path | ❌ Uses SHA256(child.privateKey) | 🚫 WRONG | **Issue #8:** Should maintain 64-byte BIP85 entropy across entire chain |
| **Entropy Chain Update** | After deriving each child, update entropy from child key | ✓ Updates with sha256(childNode.privateKey) | 🟡 PARTIAL | Correct pattern but uses SHA256; should maintain full BIP85 entropy |
| **Final Entropy** | Use chained entropy for final key material | ✓ Uses currentEntropy | ✓ OK | Correct usage |

**Verdict:** ❌ BIP-Keychain implementation **fundamentally diverges**:
1. Uses HMAC-SHA256 instead of HMAC-SHA512
2. No nonce/versioning parameter
3. Entropy chaining uses SHA256 instead of maintaining proper BIP85 entropy
4. No validation of @context field
5. Missing test vectors entirely

---

### RFC8785 — JSON Canonicalization Scheme (RFC Standard)

| Aspect | Standard | Current BIP85KMS | Status | Issue |
|--------|----------|------------------|--------|-------|
| **Object Key Ordering** | Lexicographically sorted by UTF-16 code unit | ✓ Uses Object.keys(record).sort() | ✓ COMPLIANT | Correct |
| **Array Handling** | Elements in order, no sorting | ✓ Maps each item recursively | ✓ COMPLIANT | Correct |
| **Whitespace Removal** | No unnecessary whitespace | ✓ No spaces in separators | ✓ COMPLIANT | Correct |
| **String Escaping** | Minimal per JSON spec | ✓ Uses JSON.stringify() | ✓ COMPLIANT | Correct |
| **Number Formatting** | Decimal notation, no exponents | ✓ Uses String(obj) | 🟡 PARTIAL | Should validate no exponents; non-finite check present |
| **Primitive Types** | null, boolean, number, string | ✓ All handled | ✓ COMPLIANT | Correct |
| **Recursive Handling** | Nested objects/arrays | ✓ Recursive implementation | ✓ COMPLIANT | Correct |

**Verdict:** ✅ JCS implementation appears **standards-compliant** (though not validated against official test vectors).

---

### Age Encryption Format (Stable Standard)

| Aspect | Standard | Current BIP85KMS | Status | Issue |
|--------|----------|------------------|--------|-------|
| **Public Key Encoding** | Bech32 with HRP "age1" + 32-byte X25519 recipient | ✓ Uses bech32.encode("age", ...) | ✓ COMPLIANT | Correct |
| **Private Key Encoding** | Bech32 with HRP "AGE-SECRET-KEY-" + 32-byte identity | ✓ Uses bech32.encode("AGE-SECRET-KEY-", ...) | ✓ COMPLIANT | Correct |
| **X25519 Public Derivation** | `recipient = X25519(identity, basepoint)` | ✓ Uses @noble/curves/ed25519.x25519.getPublicKey() | ✓ COMPLIANT | Correct |
| **Bech32 Encoding** | Base32 + 6-char checksum | ✓ Uses bech32 library | ✓ COMPLIANT | Correct |
| **Case Handling** | HRP case-insensitive for checksum; output case flexible | ✓ Lowercases for public, uppercases for private | ✓ COMPLIANT | Correct |

**Verdict:** ✅ Age key encoding is **standards-compliant**.

---

### BIP88 — Hierarchical Deterministic Path Templates (Informational, Assigned 2020-06-23)

| Aspect | Standard | Current BIP85KMS | Status | Issue |
|--------|----------|------------------|--------|-------|
| **Path Validation** | Formal template specification (m/44'/0'/0'/{0-1}/{0-50000}) | ❌ No validation | 🚫 MISSING | **Issue #9:** No BIP88 path templates defined or validated |
| **Range Syntax** | {start-end} for ranges, {a,b,c} for multiple values | ❌ Not used | 🚫 MISSING | Could document valid path templates |
| **Hardened Notation** | Consistent use of ' or h marker | ✓ Consistent use of ' | ✓ COMPLIANT | Not formally templated |
| **Machine-Readable Paths** | Path templates for machine parsing | ❌ No templates | 🚫 MISSING | Could improve path documentation |

**Verdict:** 🟡 BIP88 **not utilized**. Current paths are hand-constructed strings with no machine-readable validation or documentation. Could benefit from BIP88 templates for documentation and validation.

---

### BIP44/49/84/86 Path Standards (Deployed, Assigned)

| Aspect | Standard | Current BIP85KMS | Status | Issue |
|--------|----------|------------------|--------|-------|
| **Purpose Allocation** | 44', 49', 84', 86' for different wallet types | ✓ Not used (BIP85 purpose instead) | ✓ COMPLIANT | Correctly avoids collision |
| **Account Discovery** | Gap limit algorithm for multi-account support | ❌ No account discovery | 🚫 MISSING | Not applicable to deterministic application key derivation |

**Verdict:** ✅ BIP85KMS correctly **avoids** using BIP44/49/84/86 purpose codes (which are for wallet address derivation, not application key management).

---

## Implementation-Specific Issues (Not Standards)

### Issue #1: Entropy Extraction Uses Wrong Hash Function

**Location:** `src/core.ts` line ~89, `python/cli.py` line ~58

**Current:** `SHA256(child.privateKey)`  
**Should Be:** `HMAC-SHA512(key="bip-entropy-from-k", msg=child.privateKey)`

**Impact:** All BIP85 entropy is wrong; incompatible with BIP85 reference implementations (bipsea, etc.)

**Fix Required:** Change to proper HMAC-SHA512 with domain-separation string.

---

### Issue #2: Entropy Size Is Truncated

**Location:** `src/core.ts` line ~89 (returns 32 bytes from SHA256)

**Current:** Returns 32 bytes  
**Should Be:** Returns 64 bytes (full HMAC-SHA512 output)

**Impact:** Only 32 bits of entropy used; BIP85 spec provides 64 bytes for application use

**Fix Required:** Return full 64-byte HMAC-SHA512 output; update downstream uses if they expect 32 bytes.

---

### Issue #3: Application Code 128169' Already Assigned

**Location:** `src/core.ts` line ~47, `LEGACY_APP_CODE = 128169`

**Current:** Used for generic "legacy numeric paths"  
**Should Be:** Reserved exclusively for BIP85 HEX entropy derivation (BIP85 spec)

**Impact:** If anyone implements BIP85 HEX entropy with code 128169', it will collide with BIP85KMS legacy paths

**Fix Required:** Choose a different application code for legacy numeric paths, or deprecate legacy path support entirely in standards-aligned version.

**Recommendation:** Deprecate LEGACY_APP_CODE and legacy path derivation (deriveFromMnemonic, deriveIndexes, etc.) in favor of semantic path derivation. The legacy paths serve no standards-aligned purpose.

---

### Issue #4: Semantic Path Imaging Uses Wrong HMAC

**Location:** `src/core.ts` line ~328, `python/cli.py` line ~200

**Current:** `HMAC-SHA256(parentEntropy, jcs(segment))`  
**Should Be:** `HMAC-SHA512(parentEntropy, jcs(segment) || nonce?)`

**Impact:** Semantic path indexes incompatible with BIP-Keychain reference implementation (once test vectors exist)

**Fix Required:** Update to HMAC-SHA512; add optional nonce parameter.

---

### Issue #5: Entropy Chaining Uses SHA256 Instead of BIP85

**Location:** `src/core.ts` line ~346, `python/cli.py` line ~220

**Current:** `currentEntropy = sha256(childNode.privateKey)`  
**Should Be:** Maintain full 64-byte BIP85 entropy throughout chain

**Impact:** Entropy degrades from 64 bytes to 32 bytes; violates BIP85 assumptions

**Fix Required:** After each semantic segment, derive new BIP85 entropy for the child path, not just hash the child private key.

---

### Issue #6: No Nonce/Versioning in Semantic Paths

**Location:** `src/core.ts` deriveFromSemanticPath()

**Current:** No parameter for optional nonce  
**Should Be:** Support optional nonce for key rotation/versioning

**Impact:** Cannot versioned-rotate keys under same semantic path without changing semantic structure

**Fix Required:** Add optional `nonce?: Uint8Array` parameter to semanticToIndex() and deriveFromSemanticPath().

---

### Issue #7: No BIP88 Path Templates

**Location:** Entire project

**Current:** Paths are hand-constructed strings (e.g., `m/83696968'/67797668'/{i}/{i}'/...`)  
**Should Be:** Document path constraints and validation using BIP88 templates

**Impact:** No machine-readable path validation; documentation is prose-only

**Fix Required:** Define BIP88 templates for:
- Semantic paths: `m/83696968'/67797668'/{*}/{*}/.../{0-2^31-1}`
- Legacy paths (if kept): `m/83696968'/128169'/{*}/{*}/{*}`

---

### Issue #8: Semantic Path Segment Validation Missing

**Location:** `src/core.ts` line ~280

**Current:** Only checks for @type property  
**Should Be:** Also validate @context per JSON-LD spec

**Impact:** Non-JSON-LD objects might be accepted; reduces standardization

**Fix Required:** Add @context validation (or document why it's optional).

---

### Issue #9: No Path Size/Depth Limits

**Location:** `src/core.ts` deriveFromSemanticPath()

**Current:** Accepts arbitrary semantic path depth  
**Should Be:** Define maximum depth (per BIP-Keychain security considerations)

**Impact:** Unbounded paths could be used for denial-of-service; no documented limit

**Fix Required:** Define and enforce maximum semantic path depth (e.g., 16 segments) and size limits.

---

## Test Vector Status

### BIP32 Vectors
- **Status:** ✅ Available (official test vectors in BIP32 spec)
- **Current Testing:** Not explicitly tested against BIP32 vectors
- **Needed:** Add BIP32 test vectors to validate @scure/bip32 usage

### BIP39 Vectors
- **Status:** ✅ Available (https://github.com/trezor/python-mnemonic/blob/master/vectors.json)
- **Current Testing:** Not explicitly tested
- **Needed:** Validate mnemonic-to-seed with official vectors

### BIP85 Vectors
- **Status:** ✅ Available (official vectors in BIP85 spec and bipsea)
- **Current Testing:** ❌ **WILL FAIL** due to Issues #1 and #2
- **Needed:** Fix entropy extraction to pass official vectors

### RFC8785 Vectors
- **Status:** ✅ Available (https://datatracker.ietf.org/doc/html/rfc8785)
- **Current Testing:** Not explicitly tested
- **Needed:** Validate jcs() against RFC8785 test vectors

### BIP-Keychain Vectors
- **Status:** 🚫 **Does not exist yet** (draft phase, marked TODO)
- **Current Testing:** N/A
- **Needed:** Develop deterministic golden vectors from specification; cross-check against independent implementation once one exists

### Age Encryption Vectors
- **Status:** ✅ Available (age-encryption.org/testkit)
- **Current Testing:** Not explicitly tested
- **Needed:** Validate key encoding and X25519 derivation

---

## Cross-Language Cross-Check Status

### Python Implementation (`python/cli.py`)

**Status:** Independent implementation mirrors TypeScript logic  
**Purpose:** Intended as correctness cross-check (per project memory)

**Current Issues:**
- Also uses wrong entropy extraction (SHA256 instead of HMAC-SHA512)
- Also uses HMAC-SHA256 for semantic imaging
- Both must be fixed in parallel to maintain cross-check validity

**Observation:** Having two independent implementations is valuable (catches bugs invisible in single implementation), but both must be corrected together.

---

## Decision Matrix: Standards vs. Non-Standard Behavior

| Component | Classification | Status | Normative Source |
|-----------|----------------|--------|------------------|
| BIP32 derivation | Standard | ✅ Compliant | BIP32 |
| BIP39 mnemonic | Standard | ✅ Compliant | BIP39 |
| BIP85 entropy (core) | Standard | ❌ Non-compliant | BIP85 |
| Age key encoding | Standard | ✅ Compliant | Age spec |
| JCS canonicalization | Standard | ✅ Compliant | RFC8785 |
| Semantic path imaging | Draft standard | ❌ Non-compliant | BIP-Keychain draft |
| Legacy numeric paths | Non-standard | ⚠️ Collides with BIP85 | (None—should remove) |
| Entropy chaining | Non-standard | 🟡 Partially compliant | (Custom implementation) |
| Nonce/versioning | Draft standard | ❌ Missing | BIP-Keychain draft |
| Path templates | Standard | ❌ Missing | BIP88 |
| Semantic segment format | Draft standard | 🟡 Partial | BIP-Keychain draft (@context) |

---

## Required Corrections (Priority Order)

### 🔴 Critical — Breaks Interoperability

1. **Fix BIP85 entropy extraction:** HMAC-SHA512 with domain-separation string
2. **Fix semantic path imaging:** HMAC-SHA512 instead of HMAC-SHA256
3. **Remove application code collision:** Don't use 128169' for legacy paths
4. **Fix entropy chaining:** Use proper BIP85 entropy, not SHA256 hash

### 🟠 High — Standards Conformance

5. Add nonce parameter for semantic path versioning
6. Add @context validation for semantic segments
7. Define and enforce path depth/size limits
8. Document semantic segment schema more rigorously

### 🟡 Medium — Documentation & Validation

9. Add BIP32/BIP39/BIP85/RFC8785/Age test vector validation
10. Develop BIP-Keychain golden vectors (cross-check with reference implementation once available)
11. Define BIP88 path templates for path documentation
12. Update documentation to distinguish standard vs. non-standard behavior

### 🟢 Low — Enhancement

13. Deprecate/remove legacy numeric path support (Issue #3)
14. Add deterministic golden vector generation and test harness

---

## Recommended Phase 2 Architecture

Based on this standards analysis, Phase 2 design should establish:

1. **Correct BIP85 entropy:** Full 64-byte HMAC-SHA512 output with "bip-entropy-from-k" domain separation
2. **Standards-aligned semantic imaging:** HMAC-SHA512 with optional nonce, extracting top 31 bits
3. **Proper application code allocation:**
   - Keep 67797668' for semantic paths (BIP-Keychain draft)
   - Allocate new code for legacy paths (or deprecate)
   - Never use 128169' (reserved for BIP85 HEX entropy)
4. **Strict JSON-LD validation:** @context and @type both required
5. **Security boundaries:** Path depth, segment size, entropy size all bounded
6. **Test vector infrastructure:** Framework for validating against BIP32, BIP39, BIP85, RFC8785, Age specs

---

## Sources

- **BIP32:** https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- **BIP39:** https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- **BIP43:** https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
- **BIP44:** https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
- **BIP48:** https://github.com/bitcoin/bips/blob/master/bip-0048.mediawiki
- **BIP49:** https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
- **BIP84:** https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
- **BIP86:** https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
- **BIP85:** https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki (Version 2.1.0)
- **BIP88:** https://github.com/bitcoin/bips/blob/master/bip-0088.mediawiki
- **BIP-Keychain (Draft):** https://github.com/akarve/bip-keychain
- **bipsea:** https://github.com/akarve/bipsea
- **RFC8785 (JCS):** https://datatracker.ietf.org/doc/html/rfc8785
- **Age Encryption Spec:** https://age-encryption.org/v1
- **SLIP-0044 (Coin Types):** https://github.com/satoshilabs/slips/blob/master/slip-0044.md
- **SLIP-0132 (Extended Key Versions):** https://github.com/satoshilabs/slips/blob/master/slip-0132.md

