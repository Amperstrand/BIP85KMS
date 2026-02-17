# BIP85KMS Architecture Documentation

## Table of Contents

1. [Overview](#overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Component Architecture](#component-architecture)
4. [Key Derivation Flow](#key-derivation-flow)
5. [Data Flow Diagrams](#data-flow-diagrams)
6. [Derivation Path Construction](#derivation-path-construction)
7. [Technology Stack](#technology-stack)
8. [Architecture Decisions](#architecture-decisions)
9. [Design Trade-offs](#design-trade-offs)
10. [Scalability Considerations](#scalability-considerations)
11. [Future Architecture Evolution](#future-architecture-evolution)

---

## Overview

BIP85KMS (BIP85 Key Management Service) is a deterministic key derivation system that generates cryptographic keys on-demand from a master mnemonic. Instead of storing per-file encryption keys, it recreates the same key material whenever given the same input parameters.

### Core Principle

```
Same Inputs (mnemonic + keyVersion + appId + filename) → Same Outputs (keys + IV)
```

This deterministic property eliminates the need for key storage while maintaining the ability to encrypt and decrypt data consistently.

### Design Philosophy

1. **Determinism Over State**: No database, no key storage, pure computation
2. **Simplicity Over Features**: Minimal API surface, easy to audit
3. **Transparency Over Obscurity**: Clear derivation process, no hidden steps
4. **Standards-Based**: Built on BIP39, BIP32, BIP85, Age specifications

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Layer                              │
├─────────────────────────────────────────────────────────────────┤
│  • CLI Tools (Node.js, Python)                                  │
│  • Shell Scripts (bin/*.sh)                                      │
│  • Browser Demo (index.html + web/app.js)                       │
│  • HTTP Clients (curl, fetch, etc.)                             │
└────────────────────┬────────────────────────────────────────────┘
                     │ HTTP POST / TLS
                     │ JSON: {filename, keyVersion, appId, getPrivateKey?}
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Cloudflare Worker API                          │
│                     (src/index.ts)                               │
├─────────────────────────────────────────────────────────────────┤
│  1. Validate request (POST, required fields)                    │
│  2. Call deriveFromMnemonic(MNEMONIC_SECRET, ...)               │
│  3. Filter response based on getPrivateKey flag                 │
│  4. Return JSON response                                        │
└────────────────────┬────────────────────────────────────────────┘
                     │ Function call
                     │ Parameters: mnemonic, keyVersion, appId, filename
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│               Core Derivation Module                             │
│                  (src/core.js)                                   │
├─────────────────────────────────────────────────────────────────┤
│  Step 1: Mnemonic → BIP32 Master Node                           │
│  Step 2: Hash appId and filename                                │
│  Step 3: Construct derivation path indexes                      │
│  Step 4: Derive BIP85 entropy (from keyVersion only)            │
│  Step 5: Generate Age key pair from entropy                     │
│  Step 6: Derive IV from filename hash                           │
│  Step 7: Return {derivationPath, keys, entropy, iv}             │
└────────────────────┬────────────────────────────────────────────┘
                     │ Return value
                     │ {derivationPath, age_private_key, age_public_key, raw_entropy, iv}
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Cryptographic Primitives                      │
├─────────────────────────────────────────────────────────────────┤
│  • @scure/bip39: BIP39 mnemonic → seed conversion               │
│  • @scure/bip32: BIP32 HD key derivation                        │
│  • @noble/hashes: SHA-256, HMAC-SHA256, Argon2id                │
│  • @noble/curves: X25519 (Curve25519 ECDH)                      │
│  • bech32: Age key encoding                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. Core Derivation Module (`src/core.js`)

**Purpose**: Pure JavaScript implementation of key derivation logic

**Why Vanilla JS?**
- Works in Node.js, browsers, and Cloudflare Workers without transpilation
- Easier to audit (no build step obscuration)
- Compatible with import maps for browser usage

**Key Functions**:

```javascript
// High-level API
deriveFromMnemonic(mnemonic, keyVersion, appId, filename)
  → {derivationPath, age_private_key, age_public_key, raw_entropy, iv}

// Mnemonic handling
deriveMasterNodeFromMnemonic(mnemonic) → HDKey

// Index derivation
deriveIndexes(keyVersion, appId, filename)
  → {indexes: number[], appIdHash, filenameHash, derivationPath: string}

// Entropy derivation (BIP85)
deriveBIP85Entropy(index, masterNode) → Uint8Array (32 bytes)

// Key generation
deriveKeyAndIV(masterNode, keyVersion, appId, filename)
  → {derivationPath, age_private_key, age_public_key, raw_entropy, iv}

// Utility functions
deriveDeterministicAgeKey(masterKey, index) → string
deriveMasterKey(passphrase) → Uint8Array  // Not currently used
bufferToHex(buf) → string
intFromBytes(bytes) → number
```

**Dependencies**:
- Reads: None (pure function, stateless)
- Writes: None (no side effects)
- External calls: Uses crypto libraries only

---

### 2. TypeScript Re-export Module (`src/bip85kms.ts`)

**Purpose**: Provides typed exports for TypeScript consumers

```typescript
export { deriveFromMnemonic, deriveDeterministicAgeKey, deriveMasterKey } from "./core.js";

export interface Env {
  MNEMONIC_SECRET: string;
}
```

**Why Separate from core.js?**
- Core stays vanilla JS (browser-compatible, no build needed)
- TypeScript types available for Worker and tests
- Best of both worlds: runtime simplicity + development ergonomics

---

### 3. Cloudflare Worker API (`src/index.ts`)

**Purpose**: HTTP API endpoint for key derivation requests

**Request Flow**:
```typescript
1. Validate HTTP method (must be POST)
2. Parse JSON body
3. Validate required fields (filename, keyVersion, appId)
4. Call deriveFromMnemonic(env.MNEMONIC_SECRET, ...)
5. Filter response:
   - If getPrivateKey === true: Return full result
   - Else: Return {age_public_key, iv} only
6. Return JSON response
```

**Error Handling**:
- 405: Non-POST requests
- 400: Missing required fields
- 400: Derivation errors (caught from core)

**Configuration**:
- `MNEMONIC_SECRET`: Environment variable (Cloudflare Workers secret)
- Routes: Configured in `wrangler.jsonc`

---

### 4. Browser Demo (`index.html` + `web/app.js`)

**Purpose**: Client-side demonstration of deterministic derivation

**Architecture**:
```
index.html
  ├─ Import maps (ESM dependencies from esm.sh)
  ├─ HTML form (mnemonic, filename, keyVersion, appId, getPrivateKey)
  └─ <script type="module" src="./web/app.js">

web/app.js
  ├─ import { deriveFromMnemonic } from "../src/core.js"
  ├─ Form submission handler
  ├─ Client-side key derivation (no server call)
  └─ Display results as JSON
```

**Security Model**:
- Runs entirely in browser (offline-capable)
- No server communication for derivation
- Uses import maps to load dependencies from CDN (esm.sh)
- Mnemonic never leaves the browser

**Use Case**:
- Educational demonstration
- Offline key derivation
- Verifying Worker behavior
- Learning how deterministic derivation works

---

### 5. CLI Tools

#### Node.js CLI (`src/cli.ts`)

```typescript
// Usage: node dist/cli.js --filename X --keyVersion N --appId Y --getPrivateKey
import { deriveFromMnemonic } from './bip85kms';

const mnemonic = process.env.MNEMONIC_SECRET;
const result = deriveFromMnemonic(mnemonic, keyVersion, appId, filename);
console.log(JSON.stringify(result, null, 2));
```

**Build Required**: `npm run build` (compiles TypeScript to `dist/`)

#### Python CLI (`python/cli.py`)

```python
# Usage: python python/cli.py --filename X --keyVersion N --appId Y --getPrivateKey
# Uses bipsea library for BIP39/BIP32
# Reimplements derivation logic in Python
```

**Dependencies**: `bipsea`, `cryptography`

#### Shell Scripts (`bin/*.sh`)

**`deterministic_age.sh`**:
- Wrapper for Age encryption/decryption
- Fetches keys from Worker API via curl
- Automatically encrypts or decrypts based on file extension

**`deterministic_openssl_encrypt.sh`**:
- Wrapper for OpenSSL symmetric encryption
- Fetches raw entropy from Worker API
- Uses content-based IV derivation (different from Worker)

**`age_demo.sh`** and **`openssl_demo.sh`**:
- Demonstration scripts
- Create test files and show encrypt/decrypt cycle

---

## Key Derivation Flow

### Step-by-Step Process

```
Input: mnemonic, keyVersion, appId, filename

┌─────────────────────────────────────────────────────────────┐
│ Step 1: Derive BIP32 Master Node                            │
├─────────────────────────────────────────────────────────────┤
│ seed = BIP39.mnemonicToSeed(mnemonic)                       │
│ masterNode = BIP32.fromMasterSeed(seed)                     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Hash Input Parameters                               │
├─────────────────────────────────────────────────────────────┤
│ appIdHash = SHA-256(appId)                                  │
│ filenameHash = SHA-256(filename)                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Derive Indexes                                      │
├─────────────────────────────────────────────────────────────┤
│ indexes[0] = keyVersion & 0x7fffffff                        │
│ indexes[1] = intFromBytes(appIdHash[0:4]) & 0x7fffffff     │
│ indexes[2] = intFromBytes(filenameHash[0:4]) & 0x7fffffff  │
│                                                             │
│ derivationPath = m/83696968'/128169'/{idx0}'/{idx1}'/{idx2}'│
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 4: Derive BIP85 Entropy (⚠️ ONLY uses indexes[0])     │
├─────────────────────────────────────────────────────────────┤
│ childPath = m/83696968'/{indexes[0]}'                       │
│ childNode = masterNode.derive(childPath)                    │
│ entropy = SHA-256(childNode.privateKey)  // 32 bytes        │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 5: Derive Age Private Key                              │
├─────────────────────────────────────────────────────────────┤
│ indexBytes = BigEndian(indexes[0])  // 8 bytes              │
│ rawSecret = HMAC-SHA256(entropy, indexBytes)  // 32 bytes   │
│ age_private_key = bech32("AGE-SECRET-KEY-", rawSecret)      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 6: Derive Age Public Key                               │
├─────────────────────────────────────────────────────────────┤
│ pubBytes = X25519.getPublicKey(rawSecret)  // Curve25519    │
│ age_public_key = bech32("age", pubBytes)                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 7: Derive IV                                           │
├─────────────────────────────────────────────────────────────┤
│ iv = hex(filenameHash[0:12])  // 96 bits                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
Output: {derivationPath, age_private_key, age_public_key, raw_entropy, iv}
```

### Critical Architecture Note

**⚠️ Key Entropy Depends ONLY on keyVersion**

The current implementation has a significant architectural characteristic:

```javascript
// In deriveKeyAndIV():
const entropy = deriveBIP85Entropy(indexes[0], masterNode);  // ← ONLY indexes[0]!
```

This means:
- **Same `keyVersion`** → **Same entropy** → **Same keys**
- `appId` and `filename` only affect the derivation path STRING
- They do NOT affect the actual cryptographic key material

**Implications**:
```javascript
// These produce THE SAME entropy and keys:
deriveFromMnemonic(mnemonic, 1, "app1", "file1.txt")
deriveFromMnemonic(mnemonic, 1, "app2", "file2.txt")
// Only the derivationPath string differs!

// To get DIFFERENT keys, change keyVersion:
deriveFromMnemonic(mnemonic, 1, "app1", "file1.txt")  // Key A
deriveFromMnemonic(mnemonic, 2, "app1", "file1.txt")  // Key B (different)
```

**Is This a Bug or Feature?**

This appears to be a **design limitation** rather than an intentional feature:

**Arguments for "Bug"**:
- Users expect different files to have different keys
- The derivation path suggests per-file keys, but entropy doesn't match
- Potential security issue: limited key diversity

**Arguments for "Feature"**:
- Simplified key rotation via keyVersion
- Explicit version control over key changes
- Reduced complexity in entropy derivation

**Recommendation**: See "Architecture Decisions" below for detailed analysis and proposed fix.

---

## Data Flow Diagrams

### Public Key Request (Encryption)

```
Client                    Worker API              Core Module
  │                          │                        │
  ├─ POST /                  │                        │
  │  {filename: "data.txt",  │                        │
  │   keyVersion: 1,         │                        │
  │   appId: "myapp"}        │                        │
  │ ────────────────────────>│                        │
  │                          │                        │
  │                          ├─ Validate request      │
  │                          ├─ Extract MNEMONIC      │
  │                          │                        │
  │                          ├─ deriveFromMnemonic()  │
  │                          │ ──────────────────────>│
  │                          │                        │
  │                          │                        ├─ Derive master node
  │                          │                        ├─ Derive indexes
  │                          │                        ├─ Derive entropy
  │                          │                        ├─ Generate keys
  │                          │                        ├─ Derive IV
  │                          │                        │
  │                          │<──────────────────────┤
  │                          │  {derivationPath,      │
  │                          │   age_private_key,     │
  │                          │   age_public_key,      │
  │                          │   raw_entropy, iv}     │
  │                          │                        │
  │                          ├─ Filter response       │
  │                          │  (public mode)         │
  │<────────────────────────┤                        │
  │  {age_public_key,        │                        │
  │   iv}                    │                        │
  │                          │                        │
```

### Private Key Request (Decryption)

```
Client                    Worker API              Core Module
  │                          │                        │
  ├─ POST /                  │                        │
  │  {filename: "data.txt",  │                        │
  │   keyVersion: 1,         │                        │
  │   appId: "myapp",        │                        │
  │   getPrivateKey: true}   │                        │
  │ ────────────────────────>│                        │
  │                          │                        │
  │                          ├─ Validate request      │
  │                          ├─ Extract MNEMONIC      │
  │                          │                        │
  │                          ├─ deriveFromMnemonic()  │
  │                          │ ──────────────────────>│
  │                          │                        │
  │                          │      [Same flow]       │
  │                          │                        │
  │                          │<──────────────────────┤
  │                          │  {derivationPath,      │
  │                          │   age_private_key,     │
  │                          │   age_public_key,      │
  │                          │   raw_entropy, iv}     │
  │                          │                        │
  │                          ├─ Return full response  │
  │<────────────────────────┤  (private mode)        │
  │  {derivationPath,        │                        │
  │   age_private_key,       │                        │
  │   age_public_key,        │                        │
  │   raw_entropy, iv}       │                        │
  │                          │                        │
```

### Browser Demo Flow (Offline)

```
User                     Browser                  core.js
  │                          │                        │
  ├─ Enter mnemonic,         │                        │
  │  filename, keyVersion,   │                        │
  │  appId                   │                        │
  │ ───────────────────────> │                        │
  │                          │                        │
  │ ├─ Click "Derive"        │                        │
  │ ───────────────────────> │                        │
  │                          │                        │
  │                          ├─ Form submit event     │
  │                          ├─ Extract values        │
  │                          │                        │
  │                          ├─ deriveFromMnemonic()  │
  │                          │ ──────────────────────>│
  │                          │                        │
  │                          │      [Local execution] │
  │                          │      [No network call] │
  │                          │                        │
  │                          │<──────────────────────┤
  │                          │  {keys, entropy, iv}   │
  │                          │                        │
  │                          ├─ Display as JSON       │
  │<───────────────────────┤                        │
  │  [Results shown         │                        │
  │   in <pre> element]     │                        │
  │                          │                        │
```

---

## Derivation Path Construction

### BIP32 Path Format

```
m/purpose'/coin_type'/index0'/index1'/index2'/...
```

### BIP85KMS Path Structure

```
m/83696968'/128169'/{keyVersion}'/{appIdHash}'/{filenameHash}'
```

**Component Breakdown**:

| Level | Value | Meaning | Derivation |
|-------|-------|---------|------------|
| Purpose | `83696968'` | BIP85 purpose constant | Hardcoded (0x4FF4800 in decimal) |
| Application | `128169'` | Age key derivation constant | Hardcoded (0x1F4F9 in decimal) |
| Index 0 | `{keyVersion}'` | Key rotation version | User-provided keyVersion parameter |
| Index 1 | `{appIdHash}'` | Application identifier hash | First 4 bytes of SHA-256(appId) |
| Index 2 | `{filenameHash}'` | File identifier hash | First 4 bytes of SHA-256(filename) |

**All indexes use hardened derivation** (indicated by `'`)

### Example Derivation Paths

```javascript
// Example 1
deriveFromMnemonic(mnemonic, 1, "docs", "README.md")
// Path: m/83696968'/128169'/1'/1186212674'/859136773'
//                            └─┬─┘ └────┬────┘ └────┬────┘
//                         keyVersion  appIdHash  filenameHash

// Example 2  
deriveFromMnemonic(mnemonic, 42, "backup", "database.db")
// Path: m/83696968'/128169'/42'/987654321'/123456789'

// Example 3 - Same keyVersion produces same entropy!
deriveFromMnemonic(mnemonic, 1, "app1", "file1.txt")
// Path: m/83696968'/128169'/1'/1234567890'/2345678901'
// Entropy derived from: m/83696968'/1' only!

deriveFromMnemonic(mnemonic, 1, "app2", "file2.txt")
// Path: m/83696968'/128169'/1'/9876543210'/8765432109' (different path)
// Entropy derived from: m/83696968'/1' only! (SAME as above)
```

### Why Hardened Derivation?

**Hardened** (`'`) vs **Non-hardened** derivation:

**Non-hardened**: Parent public key can derive child public keys
- Useful for watch-only wallets
- Child public key exposure can reveal parent

**Hardened**: Parent public key CANNOT derive child keys
- Requires parent private key
- More secure when exposing derived keys

**BIP85KMS uses hardened** because:
1. We expose public keys in responses
2. Parent key (mnemonic) must remain secret
3. Child key compromise shouldn't reveal parent or siblings

---

## Technology Stack

### Runtime Environments

| Environment | Purpose | Entry Point |
|-------------|---------|-------------|
| **Cloudflare Workers** | Production API | `src/index.ts` |
| **Node.js** | CLI tools, testing | `src/cli.ts`, `test/*.ts` |
| **Browser** | Demo, offline derivation | `index.html`, `web/app.js` |
| **Python** | Alternative CLI | `python/cli.py` |
| **Bash** | Script integration | `bin/*.sh` |

### Core Dependencies

```json
{
  "@scure/bip39": "^1.5.4",     // BIP39 mnemonic handling
  "@scure/bip32": "^1.6.2",     // BIP32 HD key derivation
  "@noble/hashes": "^1.7.1",    // SHA-256, HMAC, Argon2id
  "@noble/curves": "^1.8.2",    // X25519 (Curve25519)
  "bech32": "^2.0.0"            // Age key encoding
}
```

**Why these libraries?**

- **@scure/*** and **@noble/***: Paul Miller's audited crypto libraries
  - Pure JavaScript/TypeScript
  - No native dependencies
  - Works in all environments
  - Well-maintained and audited
  - Used by major projects (ethers.js, viem, etc.)

- **bech32**: Standard implementation of bech32/bech32m encoding
  - Used by Bitcoin, Lightning, Age
  - Battle-tested

### Development Dependencies

```json
{
  "typescript": "^5.5.2",                        // Type checking
  "vitest": "~3.0.7",                            // Testing framework
  "@cloudflare/vitest-pool-workers": "^0.7.5",  // Worker testing
  "wrangler": "^4.2.0"                           // Cloudflare CLI
}
```

### Why Vitest?

- Fast (powered by Vite)
- Worker-compatible (via `@cloudflare/vitest-pool-workers`)
- Jest-compatible API
- Great TypeScript support

---

## Architecture Decisions

### ADR-001: Vanilla JavaScript Core

**Decision**: Implement `src/core.js` as vanilla JavaScript with JSDoc comments instead of TypeScript.

**Context**:
- Need to support Node.js, Cloudflare Workers, and browsers
- Browsers can import ES modules directly without build step
- TypeScript adds build complexity for browser usage

**Consequences**:
- ✅ Browser demo works without build step
- ✅ Easier to audit (no compiled/minified code)
- ✅ Direct execution in all environments
- ✅ Import maps work seamlessly
- ⚠️ No compile-time type checking in core module
- ⚠️ JSDoc can become verbose

**Mitigation**: TypeScript re-export layer (`bip85kms.ts`) provides types for Workers/tests.

---

### ADR-002: Single Endpoint Design

**Decision**: Single POST endpoint handles both public and private key requests, controlled by `getPrivateKey` flag.

**Context**:
- Could have separate `/public` and `/private` endpoints
- Could use different HTTP methods (GET vs POST)
- Could use query parameters vs body

**Chosen Design**:
```typescript
POST /
Body: {filename, keyVersion, appId, getPrivateKey?: boolean}
```

**Alternatives Considered**:

**Option A: Separate Endpoints**
```
GET /public?filename=X&keyVersion=1&appId=Y
POST /private (same params)
```
- ❌ More complex routing
- ✅ Easier to apply different auth policies
- ✅ Clear semantic separation

**Option B: Different Methods**
```
GET / → public key (params in query string)
POST / → private key (params in body)
```
- ❌ Inconsistent parameter location
- ❌ GET requests with sensitive params logged
- ✅ RESTful

**Consequences**:
- ✅ Simple implementation
- ✅ Single URL to remember
- ✅ All sensitive data in POST body
- ⚠️ Must implement auth at request body level
- ⚠️ Cannot apply different rate limits easily

**Recommendation for Production**: Consider separate endpoints for better security policy granularity.

---

### ADR-003: Deterministic IV from Filename

**Decision**: Derive IV from `SHA-256(filename)[0:12]` instead of random or content-based.

**Context**:
- Deterministic system needs reproducible IVs
- Age handles nonces internally, this IV is for auxiliary encryption

**Alternatives**:

**Option A: Random IV**
- ❌ Breaks determinism
- ❌ Need to store IV somewhere
- ✅ Best security for most encryption schemes

**Option B: Content Hash IV** (like OpenSSL script)
- ✅ Ties IV to content
- ⚠️ Need plaintext access to derive IV
- ⚠️ Different IV for same file if content changes

**Option C: Filename Hash IV** (chosen)
- ✅ Deterministic
- ✅ No need for plaintext access
- ✅ Consistent for same filename
- ⚠️ Reveals when same filename is encrypted
- ⚠️ Not suitable for AES-GCM (IV reuse fatal)

**Consequences**:
- ✅ Works for Age (which manages nonces separately)
- ✅ Simple implementation
- ⚠️ Security implications documented in SECURITY.md
- ⚠️ Users must understand limitations

---

### ADR-004: Entropy Derived Only from keyVersion

**Decision**: Current implementation derives BIP85 entropy using only `keyVersion` (indexes[0]).

**Status**: ⚠️ **ARCHITECTURAL ISSUE** - Likely unintentional, needs review

**Current Behavior**:
```javascript
const { indexes } = deriveIndexes(keyVersion, appId, filename);
// indexes = [keyVersion, appIdHash, filenameHash]

const entropy = deriveBIP85Entropy(indexes[0], masterNode);
// ↑ Only uses indexes[0]! appId and filename don't affect entropy!
```

**Impact**:
- Same keyVersion = same entropy for all apps/files
- appId and filename only affect derivation path string
- Limited key diversity

**Was This Intentional?**

**Arguments for Intentional**:
- Simplified key versioning
- Explicit control over key changes via keyVersion
- Clear semantic: version number determines the key

**Arguments for Bug**:
- Derivation path includes appId/filename, suggesting they should matter
- User expectation: different files get different keys
- Documentation suggests per-file keys
- Security concern: all keyVersion=1 keys are identical

**Proposed Fix**:

```javascript
// Option 1: Derive entropy from full path
export function deriveBIP85EntropyMultiIndex(indexes, masterNode) {
  // Combine all indexes into entropy derivation
  const indexBytes = new Uint8Array(indexes.length * 4);
  indexes.forEach((idx, i) => {
    new DataView(indexBytes.buffer).setUint32(i * 4, idx, false);
  });
  
  // First derive from indexes[0] as per BIP85
  const baseEntropy = deriveBIP85Entropy(indexes[0], masterNode);
  
  // Then mix in other indexes via HMAC
  return hmac(sha256, baseEntropy, indexBytes);
}

// Use in deriveKeyAndIV:
const entropy = deriveBIP85EntropyMultiIndex(indexes, masterNode);
```

**Option 2: Concatenate hashes**
```javascript
// Combine appIdHash and filenameHash into derivation
const combinedInput = new Uint8Array([
  ...appIdHash,
  ...filenameHash
]);
const keyMaterial = hmac(sha256, baseEntropy, combinedInput);
```

**Breaking Change**: Yes - existing keys would be different

**Migration Path**:
1. Add optional `derivationMode` parameter (v1, v2)
2. Default to v1 (current behavior) for backward compatibility
3. Document v2 as recommended for new deployments
4. Provide migration guide

**Recommendation**: 
- Document current behavior clearly
- Add to issue tracker as enhancement
- Provide migration path when fixing
- Consider this in "Future Evolution" section

---

### ADR-005: No Authentication in PoC

**Decision**: Ship without authentication for educational/PoC purposes.

**Context**:
- Authentication adds complexity
- Many possible auth methods (mTLS, JWT, HMAC, Access)
- Different users have different requirements
- Want to keep core simple and auditable

**Consequences**:
- ✅ Simple implementation
- ✅ Easy to understand and demo
- ✅ Users can add their own auth
- ⚠️ **NOT PRODUCTION SAFE**
- ⚠️ Must be clearly documented

**Mitigation**:
- Prominent warnings in README and SECURITY.md
- Detailed auth implementation examples in docs
- Clear "Production Hardening Checklist"

---

## Design Trade-offs

### Determinism vs Security

**Trade-off**: Deterministic systems can't use randomness for security (nonces, salts, IVs).

**Decision**: Prioritize determinism, document security implications.

**Consequences**:
- ✅ Reproducible keys enable stateless KMS
- ✅ No synchronization or storage needed
- ⚠️ Deterministic IVs have security implications
- ⚠️ No forward secrecy (past keys always recoverable)
- ⚠️ Single point of failure (mnemonic)

---

### Simplicity vs Features

**Trade-off**: Simple codebase vs feature-rich KMS.

**Decision**: Minimal feature set, clear and auditable code.

**What's Included**:
- ✅ Key derivation (Age-compatible)
- ✅ Multiple client interfaces (HTTP, CLI, browser)
- ✅ Deterministic IV generation

**What's Excluded**:
- ❌ Authentication/authorization
- ❌ Rate limiting
- ❌ Audit logging
- ❌ Key rotation mechanisms
- ❌ Multi-tenancy
- ❌ Key revocation

**Rationale**: Educational focus, clear implementation, users add security layers as needed.

---

### Performance vs Security

**Trade-off**: Fast key derivation vs expensive key derivation (slowing brute-force).

**Decision**: Moderate cost (BIP32 + SHA-256 + X25519).

**Current Performance**:
- ~1-5ms per derivation (depends on environment)
- No intentional slowdown (like Argon2id with high cost)

**Considerations**:
- ✅ Fast enough for interactive use
- ✅ Not so slow to impact UX
- ⚠️ Fast enough to brute-force enumerate if mnemonic length is low
- ⚠️ No protection against offline attacks if mnemonic is weak

**Argon2id Not Used**: `deriveMasterKey()` function exists but isn't wired in. If used, would slow derivation significantly.

---

## Scalability Considerations

### Cloudflare Workers Scale Characteristics

**Strengths**:
- Automatic global distribution (edge computing)
- Scales to millions of requests
- Sub-millisecond cold start
- No infrastructure management

**Limitations**:
- CPU time limits (10ms-50ms depending on plan)
- Memory limits (128MB)
- No persistent state (stateless)

**BIP85KMS Fit**:
- ✅ Stateless design perfect for Workers
- ✅ Fast derivation fits within CPU limits
- ✅ Small memory footprint
- ✅ Benefits from edge distribution

### Bottlenecks

**None identified** for the core use case:
- Pure computation (CPU-bound)
- No database queries
- No external API calls
- Minimal memory allocation

**Potential Issues at Extreme Scale**:
- Worker CPU time limits if using Argon2id
- Rate limiting needed to prevent abuse
- Mnemonic access could be bottleneck if stored in KV (not an issue with secrets)

### Horizontal Scaling

**Current**: Scales automatically with Cloudflare's infrastructure

**Multi-Region**: Deployed to all Cloudflare edge locations by default

**No Coordination Needed**: Stateless design means no cross-region coordination

---

## Future Architecture Evolution

### Phase 1: Security Hardening (High Priority)

**Goals**: Make production-ready

**Changes**:
1. **Add Authentication**
   - Implement JWT or HMAC authentication
   - Separate public/private endpoints
   - Role-based access control

2. **Add Rate Limiting**
   - Durable Objects for rate limiting state
   - Per-IP and per-appId limits
   - Progressive delays for failed auth

3. **Add Audit Logging**
   - Log all requests (without sensitive data)
   - Integration with external logging service
   - Alerting for anomalous patterns

4. **Input Validation**
   - Stronger validation of all inputs
   - Sanitization to prevent injection
   - Size limits

**Architecture Impact**: Minimal - additive changes

---

### Phase 2: Fix Key Entropy Issue (Medium Priority)

**Goals**: Incorporate appId and filename into entropy

**Changes**:
1. **Modify `deriveBIP85Entropy` or `deriveKeyAndIV`**
   ```javascript
   // New function
   function deriveBIP85EntropyV2(indexes, masterNode, appIdHash, filenameHash) {
     const baseEntropy = deriveBIP85Entropy(indexes[0], masterNode);
     const additionalInput = new Uint8Array([...appIdHash, ...filenameHash]);
     return hmac(sha256, baseEntropy, additionalInput);
   }
   ```

2. **Add Versioning**
   ```javascript
   // Request parameter
   { derivationVersion: 1 | 2, ... }
   
   // V1: Current behavior (backward compat)
   // V2: New behavior (includes appId/filename in entropy)
   ```

3. **Migration Path**
   - Document breaking change
   - Provide migration guide
   - Keep v1 for existing users
   - Recommend v2 for new deployments

**Architecture Impact**: Breaking change, requires versioning strategy

---

### Phase 3: Extensibility (Low Priority)

**Goals**: Support multiple key types and algorithms

**Changes**:
1. **Abstract Key Derivation**
   ```typescript
   interface KeyDerivationStrategy {
     name: string;
     derive(entropy: Uint8Array, index: number): KeyMaterial;
   }
   
   class AgeKeyStrategy implements KeyDerivationStrategy {
     derive(entropy, index) { /* current impl */ }
   }
   
   class PGPKeyStrategy implements KeyDerivationStrategy {
     derive(entropy, index) { /* PGP key generation */ }
   }
   ```

2. **Pluggable Strategies**
   ```typescript
   // Request parameter
   { keyType: "age" | "pgp" | "ssh" | "x509", ... }
   ```

3. **Multiple Output Formats**
   - Age keys (current)
   - SSH keys
   - PGP keys
   - Raw entropy (for custom schemes)

**Architecture Impact**: Significant refactoring, backward compatible with feature flags

---

### Phase 4: Multi-Tenancy (Future)

**Goals**: Support multiple applications/tenants with isolation

**Changes**:
1. **Tenant-Specific Mnemonics**
   ```typescript
   // Store per-tenant mnemonics in KV or Durable Objects
   const mnemonic = await env.TENANT_MNEMONICS.get(tenantId);
   ```

2. **Tenant Authentication**
   - API keys per tenant
   - Separate rate limits per tenant
   - Isolated audit logs

3. **Tenant Management API**
   - Create/delete tenants
   - Rotate tenant mnemonics
   - Usage reporting

**Architecture Impact**: Major change, new storage layer, management interface

---

### Phase 5: Offline/Local Modes (Future)

**Goals**: Enable fully offline operation

**Current State**: Browser demo works offline, but most use cases hit Worker API

**Enhancements**:
1. **CLI Improvements**
   - Full offline mode (no API calls)
   - Mnemonic from environment or secure storage
   - Integration with system keychains

2. **Library Distribution**
   ```typescript
   // npm package for direct integration
   import { deriveFromMnemonic } from '@amperstrand/bip85kms';
   ```

3. **Mobile Apps**
   - iOS/Android SDK
   - Secure enclave integration
   - Biometric authentication

**Architecture Impact**: Packaging and distribution, no core changes needed

---

## Deployment Patterns

### Pattern 1: Single Worker (Current)

```
User → Cloudflare Worker (with MNEMONIC_SECRET) → Response
```

**Pros**: Simple, single deployment  
**Cons**: Single mnemonic, no isolation

---

### Pattern 2: Worker per Application

```
App A Users → Worker A (Mnemonic A)
App B Users → Worker B (Mnemonic B)
```

**Pros**: Application isolation, separate secrets  
**Cons**: Management overhead

---

### Pattern 3: Gateway + Multiple Workers

```
Users → API Gateway (Auth/Rate Limit) → Routing → Worker A/B/C
```

**Pros**: Centralized security, flexible routing  
**Cons**: More complex, another component

---

### Pattern 4: Hybrid (API + Local)

```
Encryption (Public Key):  User → Worker API → Public Key
Decryption (Private Key): User → Local CLI → Private Key (offline)
```

**Pros**: Private keys never transit network  
**Cons**: Need to distribute mnemonic to clients

---

## Appendix: Glossary

**BIP32**: Hierarchical Deterministic Wallets - standard for deriving keys from a seed  
**BIP39**: Mnemonic code for generating deterministic keys - 12/24 word phrases  
**BIP85**: Deterministic Entropy From BIP32 Keychains - derive entropy for other purposes  
**Age**: Modern encryption tool (https://age-encryption.org/)  
**X25519**: Elliptic curve Diffie-Hellman function using Curve25519  
**HMAC**: Hash-based Message Authentication Code  
**IV**: Initialization Vector - starting state for block cipher modes  
**Bech32**: Bitcoin address encoding format, also used by Age  
**Hardened Derivation**: BIP32 child key derivation requiring parent private key  

---

**Document Version**: 1.0  
**Last Updated**: 2026-02-16  
**Authors**: Architecture review team  
**Status**: Initial Release
