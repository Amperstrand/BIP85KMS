# BIP85KMS

## Deterministic Key Management with Semantic Paths

BIP85KMS is a stateless, deterministic key derivation service that generates cryptographic keys on-demand from a single BIP39 mnemonic. Using **BIP-Keychain semantic paths**, it transforms abstract derivation paths into self-documenting, meaningful structures using JSON-LD and schema.org vocabulary.

**Core Concept**: Semantic paths like `[{"@type":"Organization","name":"AcmeCorp"}, {"@type":"DigitalDocument","name":"report.pdf"}]` are cryptographically transformed into deterministic derivation paths, eliminating key storage entirely while maintaining human-readable context.

---

## 🎯 Project Overview

### What is BIP85KMS?

BIP85KMS is a **proof-of-concept** key management service that demonstrates deterministic key derivation using:
- **BIP39** for mnemonic-to-seed conversion
- **BIP32** for hierarchical deterministic key derivation  
- **BIP85** for extracting deterministic entropy
- **BIP-Keychain** for semantic path derivation using JSON-LD
- **Age encryption** for modern, secure file encryption

It runs as a Cloudflare Worker and provides Age-compatible encryption keys through a simple HTTP API.

### What are Semantic Paths?

Instead of opaque numbers like `m/83696968'/128169'/1'/1837461928'/746291835'`, semantic paths use meaningful JSON-LD objects:

```json
[
  {"@type": "Organization", "name": "AcmeCorp"},
  {"@type": "SoftwareApplication", "name": "backup-system"},
  {"@type": "DigitalDocument", "name": "database.sql"}
]
```

**Benefits:**
- 🔍 **Self-documenting**: Know what each key is for without a database
- 🔒 **Collision-resistant**: Same segment at different positions = different keys
- 📊 **Order-sensitive**: Path order matters for security
- 🔄 **Deterministic**: Same input always produces same keys

### Use Cases

**Who would use this?**

1. **Backup Systems**: Derive keys with semantic context (org/app/file) for easy key management
2. **Multi-tenant Systems**: Isolate keys by organization and application using semantic namespaces
3. **Stateless Microservices**: Eliminate key storage by deriving from request metadata
4. **API Authentication**: Derive consistent keys for services using semantic identifiers
5. **Educational Tool**: Learn about BIP39/BIP32/BIP85 and semantic key derivation

**Example Workflow**:
```bash
# Encrypt a file (only need public key from API)
$ curl -X POST https://your-worker.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "AcmeCorp"},
      {"@type": "DigitalDocument", "name": "report.pdf"}
    ]
  }' | jq -r '.age_public_key' > pubkey.txt
$ age -R pubkey.txt -o report.pdf.age report.pdf

# Decrypt later (same semantic path retrieves same key)
$ curl -X POST https://your-worker.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "AcmeCorp"},
      {"@type": "DigitalDocument", "name": "report.pdf"}
    ],
    "getPrivateKey": true
  }' | jq -r '.age_private_key' > privkey.txt
$ age -d -i privkey.txt report.pdf.age > report.pdf
```

### Security Model Summary

**What BIP85KMS Protects Against:**
- ✅ Database breaches (no keys stored)
- ✅ Key synchronization issues (deterministic = always in sync)
- ✅ Backup complexity (one mnemonic backs up all keys)
- ✅ Key confusion (semantic paths are self-documenting)

**What BIP85KMS Does NOT Protect Against:**
- ❌ Mnemonic compromise (all keys lost forever)
- ❌ Unauthorized API access (no authentication in PoC)
- ❌ Replay attacks (no request signing)
- ❌ Side-channel attacks (no timing attack mitigation)

**⚠️ CRITICAL**: This is a **proof-of-concept** for educational purposes. Do not use in production without implementing authentication, rate limiting, audit logging, and other security controls detailed in [`docs/SECURITY.md`](docs/SECURITY.md).

---

## 📐 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Layer                             │
│  • HTTP Clients (curl, fetch)                                │
│  • CLI Tools (Node.js, Python)                               │
│  • Shell Scripts (bin/*.sh)                                  │
│  • Browser Demo (offline-capable)                            │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS POST
                     │ {filename, keyVersion, appId, getPrivateKey?}
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Cloudflare Worker API                           │
│              (src/index.ts)                                  │
│  1. Validate request (method, required fields)               │
│  2. Derive keys from MNEMONIC_SECRET                         │
│  3. Return public or full key material                       │
└────────────────────┬────────────────────────────────────────┘
                     │ deriveFromMnemonic()
                     ▼
┌─────────────────────────────────────────────────────────────┐
│           Core Derivation Engine                             │
│           (src/core.js - vanilla JS)                         │
│                                                              │
│  mnemonic ──→ BIP32 master node ──→ BIP85 entropy ──→       │
│  ──→ Age private key ──→ X25519 public key                  │
│                                                              │
│  filename ──→ SHA-256 ──→ IV (96-bit)                       │
│                                                              │
│  appId + filename ──→ derivation path components            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
                 {age_public_key, age_private_key, iv, 
                  derivationPath, raw_entropy}
```

### Key Derivation Flow

```
1. Mnemonic → BIP39 → Seed (512 bits)
2. Seed → BIP32 → Master Node
3. appId → SHA-256 → appIdHash
4. filename → SHA-256 → filenameHash  
5. Construct indexes: [keyVersion, appIdHash[:4], filenameHash[:4]]
6. Derivation path: m/83696968'/128169'/{keyVersion}'/{appIdHash}'/{filenameHash}'
7. ⚠️ BIP85 entropy: Derived ONLY from keyVersion (not appId/filename)
8. Age private key: HMAC-SHA256(entropy, keyVersion) → bech32
9. Age public key: X25519(private_key) → bech32
10. IV: filenameHash[:12] (96-bit hex)
```

**Important Architecture Note**: The current implementation derives entropy **only from `keyVersion`**, not from the full path including `appId` and `filename`. This means the same `keyVersion` produces the same underlying key material regardless of app or file. See [`docs/ARCHITECTURE.md#ADR-004`](docs/ARCHITECTURE.md) for detailed analysis and proposed fix.

### Project Structure

```
BIP85KMS/
├── src/
│   ├── core.js          # ⭐ Core derivation logic (vanilla JS + JSDoc)
│   ├── bip85kms.ts      # TypeScript exports for Worker/tests
│   ├── index.ts         # Cloudflare Worker HTTP API
│   └── cli.ts           # Node.js CLI tool
│
├── web/
│   └── app.js           # Browser demo (imports core.js)
│
├── bin/
│   ├── deterministic_age.sh              # Age encrypt/decrypt wrapper
│   ├── deterministic_openssl_encrypt.sh  # OpenSSL wrapper
│   ├── age_demo.sh                       # Demonstration script
│   └── openssl_demo.sh                   # Demonstration script
│
├── python/
│   └── cli.py           # Python implementation
│
├── test/
│   ├── index.spec.ts              # Worker API tests (5 tests)
│   └── deterministic_age.test.ts  # Key derivation tests (4 tests)
│
├── docs/
│   ├── API.md           # Complete HTTP API documentation
│   ├── ARCHITECTURE.md  # Architecture decisions and diagrams
│   └── SECURITY.md      # Threat model and security analysis
│
├── index.html           # GitHub Pages browser demo
├── wrangler.jsonc       # Cloudflare Worker config
├── package.json         # Dependencies
└── readme.md            # This file
```

For detailed architecture documentation, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

---

## 🔌 HTTP API Reference

### Endpoint

**POST /** (single endpoint for all operations)

### Request Format

The API uses **BIP-Keychain semantic paths** - JSON-LD objects with schema.org vocabulary:

```json
{
  "semanticPath": [
    {"@type": "Organization", "name": "AcmeCorp"},
    {"@type": "DigitalDocument", "name": "report.pdf"}
  ],
  "getPrivateKey": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `semanticPath` | array | Yes | Array of JSON-LD objects. Each must have `@type`. |
| `getPrivateKey` | boolean | No | Return private key? Default: `false` |

### Response Format

**Public Mode** (`getPrivateKey: false` or omitted):
```json
{
  "age_public_key": "age15vzcvrduzysjsns520xkrd9les2nxjl...",
  "derivationPath": "m/83696968'/67797668'/923847291'/1837461928'",
  "semanticPath": [{"@type": "Organization", "name": "AcmeCorp"}, {"@type": "DigitalDocument", "name": "report.pdf"}]
}
```

**Private Mode** (`getPrivateKey: true`):
```json
{
  "derivationPath": "m/83696968'/67797668'/923847291'/1837461928'",
  "age_private_key": "AGE-SECRET-KEY-1M4XE5PZGVMPX0D923NHT6HRXT7VEZ...",
  "age_public_key": "age15vzcvrduzysjsns520xkrd9les2nxjl...",
  "raw_entropy": "d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81",
  "semanticPath": [{"@type": "Organization", "name": "AcmeCorp"}, {"@type": "DigitalDocument", "name": "report.pdf"}]
}
```

### Quick Examples

**Get public key for encryption**:
```bash
curl -X POST https://your-worker.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "AcmeCorp"},
      {"@type": "DigitalDocument", "name": "report.pdf"}
    ]
  }'
```

**Get private key for decryption** (⚠️ use carefully):
```bash
curl -X POST https://your-worker.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "AcmeCorp"},
      {"@type": "DigitalDocument", "name": "report.pdf"}
    ],
    "getPrivateKey": true
  }'
```

For complete API documentation including error responses, authentication recommendations, and integration examples, see [`docs/API.md`](docs/API.md).

---

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ (for development)
- Cloudflare account (for deployment)
- Wrangler CLI: `npm install -g wrangler`

### 1. Clone and Install

```bash
git clone https://github.com/Amperstrand/BIP85KMS.git
cd BIP85KMS
npm install
```

### 2. Run Tests

```bash
npm test
```

You should see all 44 tests pass:
```
✓ test/index.spec.ts (8 tests)
✓ test/semantic_paths.test.ts (25 tests)
✓ test/deterministic_age.test.ts (11 tests)
```

### 3. Local Development
```bash
# Start local dev server
npm run dev

# In another terminal, test the endpoint
curl -X POST http://localhost:8787 \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "dev"},
      {"@type": "DigitalDocument", "name": "test.txt"}
    ]
  }'
```

### 4. Deploy to Cloudflare Workers

```bash
# Set your mnemonic as a secret (⚠️ NEVER commit this to git!)
# For testing only - use a unique, secure mnemonic for production
echo "your twenty four word mnemonic phrase goes here..." | wrangler secret put MNEMONIC_SECRET

# Deploy the Worker
npx wrangler deploy

# Test your deployed worker
curl -X POST https://your-worker.workers.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "test"},
      {"@type": "DigitalDocument", "name": "test.txt"}
    ]
  }'

# Optional: Configure custom routes
# npx wrangler deploy --routes https://keys.example.com/*
```

**⚠️ Security Reminders:**
- Never use the demo mnemonic for real data
- Always host your own instance
- Implement authentication before production use
- See [docs/SECURITY.md](docs/SECURITY.md) for full security guidelines

### 5. Try the Browser Demo

The repository includes a client-side demo that runs entirely in your browser:

**Option A: GitHub Pages** (if repo is public)
1. Go to repository Settings → Pages
2. Set Source to "GitHub Actions"
3. Push to main branch (workflow auto-deploys)
4. Visit `https://yourusername.github.io/BIP85KMS/`

**Option B: Local preview**
```bash
python3 -m http.server 4173 --directory .
# Open http://localhost:4173 in your browser
```

The demo:
- Runs 100% offline (no server calls)
- Uses the same `core.js` as the Worker
- Shows deterministic key derivation in action
- **Uses demo mnemonic by default** (safe for learning, not for real data)

---

---

## 📚 Usage Examples

### Using with Age Encryption

Age (https://age-encryption.org/) is a modern, simple file encryption tool. BIP85KMS generates Age-compatible keys.

**Encrypt a file**:
```bash
# 1. Get public key from API
PUBLIC_KEY=$(curl -s -X POST https://your-worker.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "myorg"},
      {"@type": "DigitalDocument", "name": "secret.txt"}
    ]
  }' \
  | jq -r '.age_public_key')

# 2. Encrypt with Age
echo "$PUBLIC_KEY" > recipient.txt
age -R recipient.txt -o secret.txt.age secret.txt
rm recipient.txt
```

**Decrypt the file**:
```bash
# 1. Get private key from API (same semantic path!)
PRIVATE_KEY=$(curl -s -X POST https://your-worker.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "myorg"},
      {"@type": "DigitalDocument", "name": "secret.txt"}
    ],
    "getPrivateKey": true
  }' \
  | jq -r '.age_private_key')

# 2. Decrypt with Age
echo "$PRIVATE_KEY" > identity.txt
age -d -i identity.txt -o secret.txt secret.txt.age
rm identity.txt  # Clean up private key file
```

### Using the Shell Scripts

The `bin/` directory includes convenient wrapper scripts:

**Age encryption/decryption**:
```bash
cd bin

# Encrypt a file (automatically fetches public key)
./deterministic_age.sh encrypt hello.txt

# Creates hello.txt.age

# Decrypt a file (automatically fetches private key)
./deterministic_age.sh decrypt hello.txt.age

# Extracts hello.txt
```

**Full demonstration**:
```bash
cd bin
./age_demo.sh
# Shows complete encrypt → decrypt cycle with debug output
```

### Using the Node.js CLI (Legacy)

> ⚠️ **Note**: The CLI uses the legacy `filename/keyVersion/appId` API. For new projects, prefer using the HTTP API with semantic paths or the browser demo.

```bash
# Build the CLI
npm run build

# Set your mnemonic
export MNEMONIC_SECRET="your mnemonic phrase here..."

# Derive keys (legacy format)
node dist/cli.js \
  --filename "data.json" \
  --keyVersion 1 \
  --appId "myapp" \
  --getPrivateKey

# Output:
# {
#   "derivationPath": "m/83696968'/128169'/1'/...",
#   "age_private_key": "AGE-SECRET-KEY-...",
#   "age_public_key": "age1...",
#   "raw_entropy": "...",
#   "iv": "..."
# }
```

### Using the Python CLI (Legacy)

> ⚠️ **Note**: The Python CLI uses the legacy `filename/keyVersion/appId` API. For new projects, prefer using the HTTP API with semantic paths.

```bash
# Install dependencies
pip install bipsea cryptography

# Set your mnemonic
export MNEMONIC_SECRET="your mnemonic phrase here..."

# Derive keys (legacy format)
python3 python/cli.py \
  --filename "data.json" \
  --keyVersion 1 \
  --appId "myapp" \
  --getPrivateKey
```

### Using the Python CLI

```bash
# Install dependencies
pip install bipsea cryptography

# Set your mnemonic
export MNEMONIC_SECRET="your mnemonic phrase here..."

# Derive keys
python3 python/cli.py \
  --filename "data.json" \
  --keyVersion 1 \
  --appId "myapp" \
  --getPrivateKey
```

### Key Rotation Example

To rotate keys, modify the semantic path. Add a version property or change any segment:

```bash
# Original encryption
PUBLIC_KEY_V1=$(curl -s -X POST https://your-worker.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "myorg"},
      {"@type": "DigitalDocument", "name": "data.db", "version": "1"}
    ]
  }' \
  | jq -r '.age_public_key')

echo "$PUBLIC_KEY_V1" | age -R - -o data.db.v1.age data.db

# Rotate by changing version (different keys)
PUBLIC_KEY_V2=$(curl -s -X POST https://your-worker.dev \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "myorg"},
      {"@type": "DigitalDocument", "name": "data.db", "version": "2"}
    ]
  }' \
  | jq -r '.age_public_key')

echo "$PUBLIC_KEY_V2" | age -R - -o data.db.v2.age data.db

# Both encrypted files exist with different keys
# Decrypt each with its respective semantic path
```

### Integration Example: Backup Script

```bash
#!/bin/bash
# backup.sh - Encrypt backups with deterministic keys using semantic paths

WORKER_URL="https://your-worker.dev"
ORG_NAME="myorg"
APP_NAME="backup-system"

for file in /data/*.db; do
  filename=$(basename "$file")
  
  # Get encryption key from BIP85KMS with semantic path
  pubkey=$(curl -s -X POST "$WORKER_URL" \
    -H "Content-Type: application/json" \
    -d '{
      "semanticPath": [
        {"@type": "Organization", "name": "'"$ORG_NAME'"},
        {"@type": "SoftwareApplication", "name": "'"$APP_NAME'"},
        {"@type": "DigitalDocument", "name": "'"$filename'"}
      ]
    }' \
    | jq -r '.age_public_key')
  
  # Encrypt and upload
  echo "$pubkey" | age -R - -o "$file.age" "$file"
  aws s3 cp "$file.age" "s3://my-backup-bucket/$filename.age"
  
  rm "$file.age"
done
```

---

## 🔐 Security Considerations

### ⚠️ Critical Security Warnings

1. **This is a PROOF-OF-CONCEPT** - Not production-ready without significant hardening
2. **NO AUTHENTICATION** - Anyone with your endpoint URL can request keys
3. **NO RATE LIMITING** - Vulnerable to brute-force and DoS attacks  
4. **NO AUDIT LOGGING** - No record of who requested which keys
5. **SINGLE POINT OF FAILURE** - Mnemonic compromise = all keys compromised forever

### Threat Model

**What This Protects:**
- ✅ Database breaches (no keys stored)
- ✅ Key sync issues (deterministic = always consistent)
- ✅ Backup complexity (single mnemonic backs up all keys)

**What This Does NOT Protect:**
- ❌ Mnemonic compromise (catastrophic failure)
- ❌ Unauthorized API access (no auth implemented)
- ❌ Side-channel attacks (no timing-safe operations)
- ❌ Replay attacks (no request signing)
- ❌ Key enumeration (no rate limiting)

### Known Vulnerabilities

| Severity | Issue | Impact | Mitigation |
|----------|-------|--------|------------|
| 🔴 CRITICAL | No authentication on private key endpoint | Anyone can request private keys | Implement mTLS, JWT, or HMAC auth |
| 🔴 CRITICAL | Single mnemonic controls all keys | Mnemonic leak = total compromise | Secure storage (HSM), rotation plan |
| 🟠 HIGH | No rate limiting | Brute-force enumeration possible | Add Cloudflare rate limits + app-level throttling |
| 🟠 HIGH | No audit logging | No forensic evidence | Implement comprehensive logging |
| 🟡 MEDIUM | Deterministic IVs | Information leakage in some scenarios | Use Age (handles nonces), document trade-offs |
| 🟡 MEDIUM | Entropy only from keyVersion | Same version = same key across files | See ARCHITECTURE.md ADR-004 for proposed fix |

For detailed security analysis, threat scenarios, and mitigation strategies, see [`docs/SECURITY.md`](docs/SECURITY.md).

### Production Hardening Checklist

Before production use, implement:

- [ ] **Authentication** (mTLS, JWT, HMAC, or Cloudflare Access)
- [ ] **Authorization** (restrict `getPrivateKey` to trusted clients)
- [ ] **Rate Limiting** (per-IP and per-appId)
- [ ] **Audit Logging** (comprehensive, secure, no sensitive data)
- [ ] **Input Validation** (strict validation of all parameters)
- [ ] **Mnemonic Security** (HSM or secure key management service)
- [ ] **Monitoring & Alerting** (anomaly detection, security events)
- [ ] **Incident Response Plan** (document procedures)
- [ ] **Security Audit** (professional review of implementation)
- [ ] **Penetration Testing** (validate security controls)

See [`docs/SECURITY.md#production-hardening-checklist`](docs/SECURITY.md) for the complete checklist.

### Recommended Authentication Implementation

**Option 1: JWT Authentication** (recommended for API clients)
```typescript
import { verify } from '@tsndr/cloudflare-worker-jwt';

async function handleRequest(request: Request, env: Env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }
  
  const token = authHeader.substring(7);
  const isValid = await verify(token, env.JWT_SECRET);
  if (!isValid) {
    return new Response('Invalid token', { status: 403 });
  }
  
  // Continue with request handling...
}
```

**Option 2: Cloudflare Access** (recommended for web apps)
- Configure in Cloudflare Dashboard
- Supports OAuth providers (Google, GitHub, Okta, etc.)
- Automatic authentication and session management

See [`docs/API.md#authentication`](docs/API.md) for more authentication options.

---

## 🛠️ Development Guide

### Local Development Setup

```bash
# Clone repository
git clone https://github.com/Amperstrand/BIP85KMS.git
cd BIP85KMS

# Install dependencies
npm install

# Run tests
npm test

# Start local development server
npm run dev
# Server runs at http://localhost:8787

# In another terminal, test locally
curl -X POST http://localhost:8787 \
  -H "Content-Type: application/json" \
  -d '{"filename":"test.txt", "keyVersion":1, "appId":"dev"}'
```

### Project Structure

**Core Files:**
- `src/core.js` - Pure JS derivation logic (browser + Node.js + Worker compatible)
- `src/bip85kms.ts` - TypeScript exports for type safety
- `src/index.ts` - Cloudflare Worker HTTP handler
- `src/cli.ts` - Node.js CLI tool

**Why Vanilla JS for core?**
- Works in browsers without build step
- Import maps for CDN dependencies (esm.sh)
- Easier to audit (no transpilation)
- TypeScript layer on top for development

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run specific test file
npm test test/index.spec.ts

# Run with coverage
npm test -- --coverage
```

**Test suites:**
- `test/index.spec.ts` - Worker API tests (5 tests)
- `test/deterministic_age.test.ts` - Key derivation tests (4 tests)

### Building

```bash
# Build TypeScript (for CLI)
npm run build
# Output in dist/

# Run built CLI
node dist/cli.js --filename test --keyVersion 1 --appId dev
```

### Deployment

**Deploy to Cloudflare Workers:**
```bash
# Login to Cloudflare
wrangler login

# Set mnemonic secret (NEVER commit to git!)
echo "your secure mnemonic here" | wrangler secret put MNEMONIC_SECRET

# Deploy
npm run deploy

# Deploy with custom route
wrangler deploy --routes https://keys.example.com/*
```

**Configuration** (`wrangler.jsonc`):
```jsonc
{
  "name": "bip85kms",
  "main": "src/index.ts",
  "compatibility_date": "2025-03-19",
  "compatibility_flags": ["nodejs_compat"]
}
```

### Code Style

This project uses:
- **Prettier** for code formatting (`.prettierrc`)
- **EditorConfig** for editor consistency (`.editorconfig`)
- **TypeScript** for type checking (tsconfig.json)

```bash
# Format code
npx prettier --write .

# Type check
npx tsc --noEmit
```

### Dependencies

**Core Crypto Libraries:**
```json
{
  "@scure/bip39": "^1.5.4",    // BIP39 mnemonic handling
  "@scure/bip32": "^1.6.2",    // BIP32 HD derivation
  "@noble/hashes": "^1.7.1",   // SHA-256, HMAC, Argon2id
  "@noble/curves": "^1.8.2",   // X25519 (Curve25519)
  "bech32": "^2.0.0"           // Age key encoding
}
```

**Why @scure and @noble?**
- Pure JavaScript/TypeScript (no native binaries)
- Works in all environments (Node.js, browsers, Workers)
- Well-audited by security researchers
- Used by major projects (ethers.js, viem, MetaMask)
- Maintained by Paul Miller (paulmillr)

**Development Dependencies:**
```json
{
  "typescript": "^5.5.2",
  "vitest": "~3.0.7",
  "@cloudflare/vitest-pool-workers": "^0.7.5",
  "wrangler": "^4.2.0"
}
```

### Browser Demo Development

The browser demo at `index.html` uses import maps to load dependencies from CDN:

```html
<script type="importmap">
{
  "imports": {
    "@scure/bip32": "https://esm.sh/@scure/bip32@1.6.2",
    "@scure/bip39": "https://esm.sh/@scure/bip39@1.5.4",
    "@noble/hashes/sha256": "https://esm.sh/@noble/hashes@1.7.1/sha256",
    "@noble/hashes/hmac": "https://esm.sh/@noble/hashes@1.7.1/hmac",
    "@noble/curves/ed25519": "https://esm.sh/@noble/curves@1.8.2/ed25519",
    "bech32": "https://esm.sh/bech32@2.0.0"
  }
}
</script>
```

This allows `web/app.js` to import from `src/core.js` which uses these dependencies.

**Test browser demo locally:**
```bash
python3 -m http.server 4173
# Open http://localhost:4173
```

---

## 📖 Documentation

### Available Documentation

- **[README.md](readme.md)** (this file) - Getting started, overview, quick start
- **[docs/API.md](docs/API.md)** - Complete HTTP API reference with examples
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System architecture, design decisions (ADRs), data flow
- **[docs/SECURITY.md](docs/SECURITY.md)** - Threat model, vulnerabilities, mitigation strategies

### Code Documentation

All functions in `src/core.js` have comprehensive JSDoc comments including:
- Purpose and description
- Parameter types and descriptions  
- Return value documentation
- Usage examples
- Security implications
- References to specifications (BIP39, BIP32, BIP85, Age)

**Example:**
```javascript
/**
 * Derives BIP85 entropy from a BIP32 master node at a specific index.
 * 
 * BIP85 (Deterministic Entropy From BIP32 Keychains) is a standard for deriving
 * deterministic entropy from a BIP32 HD wallet. This implementation:
 * 1. Derives a child key at path m/83696968'/{index}'
 * 2. Takes SHA-256 of the derived private key to produce 32 bytes of entropy
 * 
 * @param {number} index - The hardened derivation index
 * @param {HDKey} masterNode - A BIP32 HDKey master node
 * @returns {Uint8Array} 32 bytes of deterministic entropy
 */
export function deriveBIP85Entropy(index, masterNode) { ... }
```

---

## �� Frequently Asked Questions

### Q: Is this production-ready?

**A:** No. This is a proof-of-concept for educational purposes. It lacks authentication, rate limiting, audit logging, and other critical security features. See the [Production Hardening Checklist](#production-hardening-checklist) for what needs to be implemented.

### Q: How secure is the mnemonic storage?

**A:** Cloudflare Workers secrets are encrypted at rest and only accessible to your Worker at runtime. However, for high-security applications, consider using a Hardware Security Module (HSM) or secure key management service.

### Q: What happens if my mnemonic is compromised?

**A:** All past, present, and future keys are compromised. There is no way to revoke individual derived keys. You must:
1. Generate a new mnemonic immediately
2. Deploy a new Worker with the new mnemonic
3. Re-encrypt all data with new keys
4. Audit logs to determine scope of exposure

### Q: Can I use this for Bitcoin or cryptocurrency wallets?

**A:** BIP85KMS is designed for Age encryption keys, not cryptocurrency wallets. While it uses BIP standards (BIP39/BIP32/BIP85), it derives Age keys (X25519) rather than Bitcoin keys (secp256k1). Do not use this for managing cryptocurrency.

### Q: Why does the same keyVersion produce the same key for different files?

**A:** This is a current architectural limitation (see [`docs/ARCHITECTURE.md#ADR-004`](docs/ARCHITECTURE.md#adr-004)). The entropy is derived only from `keyVersion`, not from the full path including `appId` and `filename`. To get different keys, use different `keyVersion` values. A fix is proposed in the architecture documentation.

### Q: Can I use this offline?

**A:** Yes! The browser demo works completely offline. You can also use the Node.js or Python CLI tools locally without hitting the API. The core derivation logic (`src/core.js`) has no external dependencies at runtime.

### Q: What's the difference between the Worker API and the browser demo?

**A:** Both use the same `core.js` derivation logic. The Worker API stores the mnemonic securely and serves keys via HTTP. The browser demo runs entirely client-side—you provide the mnemonic in the browser (never send it anywhere). Use the Worker for production encryption workflows; use the browser demo for learning and verification.

### Q: How do I rotate keys?

**A:** Increment the `keyVersion` parameter. Same file, same app, different version = different key:

```bash
# Original key (version 1)
curl ... -d '{"filename":"data.db", "keyVersion":1, "appId":"backup"}'

# Rotated key (version 2) 
curl ... -d '{"filename":"data.db", "keyVersion":2, "appId":"backup"}'
```

Re-encrypt your data with the new key. Both encrypted versions can coexist.

### Q: Can I derive keys for different encryption algorithms?

**A:** Currently, BIP85KMS only generates Age-compatible keys. The raw entropy (`raw_entropy` field) can be used as key material for other algorithms, but you'll need to handle the key formatting yourself. See [`docs/ARCHITECTURE.md#phase-3-extensibility`](docs/ARCHITECTURE.md#phase-3-extensibility) for planned support for multiple key types.

### Q: What's the performance like?

**A:** Fast! Each derivation takes 1-5ms depending on the environment:
- Cloudflare Worker: ~2-3ms
- Node.js: ~1-2ms  
- Browser: ~3-5ms

No expensive operations like Argon2id are used (it's implemented but not wired in).

### Q: Is there a rate limit?

**A:** No rate limiting is implemented in the PoC. Cloudflare Workers have built-in DDoS protection, but application-level rate limiting should be added for production. See [`docs/SECURITY.md#scenario-3-key-enumeration-attack`](docs/SECURITY.md#scenario-3-key-enumeration-attack).

---

## 🗺️ Roadmap

### Current Status: Proof-of-Concept

The project currently demonstrates deterministic key derivation with:
- ✅ Core derivation engine (BIP39/BIP32/BIP85)
- ✅ Age-compatible key generation
- ✅ Cloudflare Worker API
- ✅ Multiple client implementations (HTTP, CLI, browser)
- ✅ Comprehensive documentation

### Phase 1: Security Hardening (High Priority)

**Goal:** Make production-ready

- [ ] Authentication (JWT, mTLS, HMAC, or Cloudflare Access)
- [ ] Authorization (RBAC for private key access)
- [ ] Rate limiting (per-IP, per-appId)
- [ ] Audit logging (comprehensive, secure)
- [ ] Input validation (strict checks)
- [ ] Monitoring & alerting

### Phase 2: Entropy Fix (Medium Priority)

**Goal:** Incorporate appId/filename into entropy derivation

- [ ] Implement enhanced entropy derivation (uses full path)
- [ ] Add derivation version parameter (v1 = current, v2 = fixed)
- [ ] Provide migration guide
- [ ] Maintain backward compatibility

See [`docs/ARCHITECTURE.md#ADR-004`](docs/ARCHITECTURE.md#adr-004) for technical details.

### Phase 3: Extensibility (Low Priority)

**Goal:** Support multiple key types

- [ ] Pluggable key derivation strategies
- [ ] SSH keys
- [ ] PGP keys  
- [ ] X.509 certificates
- [ ] Raw entropy export

### Phase 4: Multi-Tenancy (Future)

**Goal:** Support multiple applications/tenants

- [ ] Per-tenant mnemonics (stored in KV/Durable Objects)
- [ ] Tenant management API
- [ ] Isolated rate limits and audit logs
- [ ] Usage reporting

### Phase 5: Offline/Local Modes (Future)

**Goal:** Better offline support

- [ ] npm package for direct integration
- [ ] CLI with system keychain integration
- [ ] Mobile SDKs (iOS/Android)
- [ ] Secure enclave/TPM support

See [`docs/ARCHITECTURE.md#future-architecture-evolution`](docs/ARCHITECTURE.md#future-architecture-evolution) for detailed roadmap.

---

## 🤝 Contributing

Contributions are welcome! This is an educational/PoC project, so the focus is on:
- Clear, auditable code
- Comprehensive documentation  
- Security best practices
- Educational value

**Before contributing:**
1. Read the documentation (especially SECURITY.md and ARCHITECTURE.md)
2. Open an issue to discuss major changes
3. Follow existing code style (Prettier, EditorConfig)
4. Add tests for new functionality
5. Update documentation

**Areas that need help:**
- Security review and hardening
- Authentication implementation examples
- Additional client libraries (Go, Rust, Java, etc.)
- Performance benchmarking
- Additional test coverage

---

## 📜 License

MIT License - See LICENSE file for details

---

## ⚖️ Disclaimer

**USE AT YOUR OWN RISK**

This project is provided "as is" without warranty of any kind, express or implied. It is a proof-of-concept for educational purposes and is NOT recommended for production use without significant security hardening.

- ⚠️ **Never use demo mnemonics for real data**
- ⚠️ **Always host your own instance**  
- ⚠️ **Implement authentication before production**
- ⚠️ **Conduct security audit before production use**
- ⚠️ **Understand the threat model and limitations**

The authors and contributors are not responsible for:
- Loss of data due to incorrect usage
- Security breaches or compromised keys
- Financial losses from key management failures
- Any damages resulting from use of this software

**For production use, conduct thorough security review and implement all recommended hardening measures outlined in [`docs/SECURITY.md`](docs/SECURITY.md).**

---

## 🔗 Related Resources

### Specifications
- [BIP39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP85: Deterministic Entropy From BIP32 Keychains](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
- [Age Encryption Specification](https://age-encryption.org/v1)

### Tools
- [Age - Modern encryption tool](https://age-encryption.org/)
- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Libraries Used
- [@scure/bip39](https://github.com/paulmillr/scure-bip39) - BIP39 implementation
- [@scure/bip32](https://github.com/paulmillr/scure-bip32) - BIP32 HD derivation
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) - Cryptographic hash functions
- [@noble/curves](https://github.com/paulmillr/noble-curves) - Elliptic curve cryptography

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Amperstrand/BIP85KMS/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Amperstrand/BIP85KMS/discussions)
- **Documentation**: [`docs/`](docs/) directory

---

**Last Updated**: 2026-02-16  
**Version**: 1.0  
**Status**: Proof-of-Concept / Educational

---

**Made with 🔐 by [Amperstrand](https://github.com/Amperstrand)**
