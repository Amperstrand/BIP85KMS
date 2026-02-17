# BIP85KMS API Documentation

## Overview

BIP85KMS provides a RESTful HTTP API for deterministic key derivation using **BIP-Keychain semantic paths**. Instead of arbitrary numeric indexes, derivation paths are built from meaningful JSON-LD objects using schema.org vocabulary. The service derives Age-compatible encryption keys from a master mnemonic and semantic metadata without storing any per-file keys.

## What are Semantic Paths?

Semantic paths use JSON-LD (JSON Linked Data) objects with schema.org vocabulary to create human-readable, self-documenting derivation paths. Each segment in the path represents a meaningful context:

```json
[
  {"@type": "Organization", "name": "AcmeCorp"},
  {"@type": "SoftwareApplication", "name": "backup-system"},
  {"@type": "DigitalDocument", "name": "database.sql"}
]
```

This produces a BIP-32 path like `m/83696968'/67797668'/923847291'/1837461928'/746291835'` where each number is cryptographically derived from the semantic context.

**Benefits:**
- **Self-documenting**: Paths contain meaningful information
- **Collision-resistant**: Same segment at different positions = different indexes
- **Order-sensitive**: `[A, B] ≠ [B, A]`
- **Deterministic**: Same input always produces same output

## Base URL

The API is deployed as a Cloudflare Worker. You must deploy your own instance:

```
https://your-worker-domain.workers.dev
```

Or configure a custom route:

```
https://keys.example.com/*
```

## Authentication

**⚠️ WARNING**: The current implementation has NO authentication mechanism. Anyone with access to your endpoint can:
- Retrieve public keys
- Request private key material if `getPrivateKey: true` is set

**Production Recommendation**: Implement one of the following authentication mechanisms:
- mTLS (mutual TLS) for client certificate validation
- JWT (JSON Web Tokens) with signature verification
- HMAC request signing
- IP allowlisting at the Cloudflare Worker level
- Cloudflare Access for identity-based authentication

## Endpoints

### POST / (Root)

The single endpoint for all key derivation operations.

**HTTP Method**: `POST`

**Content-Type**: `application/json`

**Request Body Schema**:

```typescript
{
  semanticPath: Array<{
    "@type": string;
    [key: string]: any;
  }>;
  getPrivateKey?: boolean;
}
```

**Field Descriptions**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `semanticPath` | array | Yes | Array of JSON-LD objects with schema.org types. Each object must have an `@type` property. Minimum 1 segment. |
| `getPrivateKey` | boolean | No | If `true`, response includes private key material. Default `false` returns only public key. **Use with extreme caution**. |

**Common schema.org Types**:

| @type | Use Case | Example Properties |
|-------|----------|-------------------|
| `Organization` | Company/team namespace | `name`, `identifier` |
| `SoftwareApplication` | Application context | `name`, `applicationCategory` |
| `DigitalDocument` | File/document identifier | `name`, `encodingFormat` |
| `WebSite` | Web service keys | `url`, `name` |
| `Person` | Personal keys | `name`, `email` |
| `CreateAction` | Key derivation operation | `name`, `object` |

---

## Response Formats

### Public Mode Response (getPrivateKey: false or omitted)

Returns only the public key needed for encryption.

**HTTP Status**: `200 OK`

**Response Body**:

```json
{
  "age_public_key": "age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33",
  "derivationPath": "m/83696968'/67797668'/923847291'/1837461928'/746291835'",
  "semanticPath": [
    {"@type": "Organization", "name": "AcmeCorp"},
    {"@type": "SoftwareApplication", "name": "backup-system"},
    {"@type": "DigitalDocument", "name": "database.sql"}
  ]
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `age_public_key` | string | Age-format public key (bech32 encoding with "age" prefix). Used as the recipient for Age encryption. |
| `derivationPath` | string | BIP-32 derivation path showing the numeric indexes derived from semantic segments. |
| `semanticPath` | array | Echo of the input semantic path for verification. |

---

### Private Mode Response (getPrivateKey: true)

Returns full key material including private key, entropy, and derivation path.

**HTTP Status**: `200 OK`

**Response Body**:

```json
{
  "derivationPath": "m/83696968'/67797668'/923847291'/1837461928'/746291835'",
  "age_private_key": "AGE-SECRET-KEY-1M4XE5PZGVMPX0D923NHT6HRXT7VEZRMCYHJZYTD8UR6WX0A29WGSR6KPEW",
  "age_public_key": "age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33",
  "raw_entropy": "d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81",
  "semanticPath": [
    {"@type": "Organization", "name": "AcmeCorp"},
    {"@type": "SoftwareApplication", "name": "backup-system"},
    {"@type": "DigitalDocument", "name": "database.sql"}
  ]
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `derivationPath` | string | BIP-32 derivation path using BIP-Keychain format: `m/83696968'/67797668'/{index1}'/{index2}'/{index3}'` where indexes are cryptographically derived from semantic segments. |
| `age_private_key` | string | Age-format private key (bech32 encoding with "AGE-SECRET-KEY-" prefix). Used for Age decryption. **Highly sensitive**. |
| `age_public_key` | string | Age-format public key corresponding to the private key. |
| `raw_entropy` | string | 32 bytes (64 hex chars) of BIP85-derived entropy. The seed material from which keys are derived. **Highly sensitive**. |
| `semanticPath` | array | Echo of the input semantic path for verification. |

---

## Error Responses

### 405 Method Not Allowed

Returned when using HTTP methods other than POST.

**HTTP Status**: `405 Method Not Allowed`

**Response Body**:

```
Method Not Allowed
```

---

### 400 Bad Request - Missing or Invalid semanticPath

Returned when semanticPath is missing, empty, or not an array.

**HTTP Status**: `400 Bad Request`

**Response Body**:

```json
{
  "error": "semanticPath must be a non-empty array of JSON-LD objects"
}
```

---

### 400 Bad Request - Invalid Segment

Returned when a segment is missing required properties (e.g., @type).

**HTTP Status**: `400 Bad Request`

**Response Body**:

```json
{
  "error": "Invalid segment at index 0: Semantic segment must have @type property"
}
```

---

## BIP-Keychain Specification Details

### Derivation Path Structure

BIP-Keychain paths follow this format:

```
m/83696968'/67797668'/{semantic_index_1}'/{semantic_index_2}'/...
```

- `83696968'` = BIP-85 purpose code
- `67797668'` = BIP-Keychain application code
- Subsequent indexes are derived from semantic segments using HMAC-SHA-256

### Index Derivation Algorithm

For each semantic segment:

1. **Canonicalize**: Convert JSON object to canonical form (JCS/RFC 8785)
2. **HMAC**: Compute `HMAC-SHA-256(parent_entropy, canonical_json)`
3. **Extract**: Take first 31 bits of HMAC output
4. **Harden**: Set bit 31 to create hardened index

### Entropy Chaining

Each segment's index is derived using entropy from the parent path:
- Segment at depth 0 uses base BIP-Keychain entropy
- Segment at depth N uses entropy from path at depth N-1
- This ensures: Same segment at different depths = different indexes

### Properties

- **Deterministic**: Same input always produces same output
- **Order-sensitive**: `[A, B] ≠ [B, A]`
- **Context-dependent**: Same segment in different positions = different indexes
- **Collision-resistant**: Different segments produce different indexes

---

## Security Considerations

## Usage Examples

### Example 1: Basic Semantic Path - Organization and Document

Request public key for encrypting a document:

```bash
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {
        "@type": "Organization",
        "name": "AcmeCorp"
      },
      {
        "@type": "DigitalDocument",
        "name": "quarterly-report-2025.pdf"
      }
    ]
  }'
```

**Response**:

```json
{
  "age_public_key": "age1qyv7kkr...",
  "derivationPath": "m/83696968'/67797668'/923847291'/1837461928'",
  "semanticPath": [
    {"@type": "Organization", "name": "AcmeCorp"},
    {"@type": "DigitalDocument", "name": "quarterly-report-2025.pdf"}
  ]
}
```

**Use Case**: You have the public key to encrypt `quarterly-report-2025.pdf` for AcmeCorp using Age encryption.

---

### Example 2: Full Path with Application Context

Request private key with application context:

```bash
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {
        "@type": "Organization",
        "name": "AcmeCorp"
      },
      {
        "@type": "SoftwareApplication",
        "name": "backup-system",
        "applicationCategory": "Utilities"
      },
      {
        "@type": "DigitalDocument",
        "name": "database-backup.sql",
        "encodingFormat": "application/sql"
      }
    ],
    "getPrivateKey": true
  }'
```

**Response**:

```json
{
  "derivationPath": "m/83696968'/67797668'/923847291'/1234567890'/2147483647'",
  "age_private_key": "AGE-SECRET-KEY-1...",
  "age_public_key": "age1qyv7kkr...",
  "raw_entropy": "d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81",
  "semanticPath": [
    {"@type": "Organization", "name": "AcmeCorp"},
    {"@type": "SoftwareApplication", "name": "backup-system", "applicationCategory": "Utilities"},
    {"@type": "DigitalDocument", "name": "database-backup.sql", "encodingFormat": "application/sql"}
  ]
}
```

**Use Case**: Full application context for backup system with private key for decryption.

---

### Example 3: Web Service Keys

Derive keys for web service authentication:

```bash
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {
        "@type": "Organization",
        "name": "MyCompany"
      },
      {
        "@type": "WebSite",
        "url": "https://api.github.com",
        "name": "GitHub API"
      }
    ],
    "getPrivateKey": true
  }'
```

**Use Case**: Derive consistent keys for API authentication across services.

---

### Example 4: Personal Key Management

Derive keys for personal use:

```bash
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {
        "@type": "Person",
        "name": "John Doe",
        "email": "john@example.com"
      },
      {
        "@type": "DigitalDocument",
        "name": "personal-notes.txt"
      }
    ]
  }'
```

**Use Case**: Personal file encryption with semantic context.

---

### Example 5: Key Rotation with Version Context

When you need to rotate keys, add version information to the semantic path:

```bash
# Version 1
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "AcmeCorp"},
      {"@type": "SoftwareApplication", "name": "backup", "version": "1.0"},
      {"@type": "DigitalDocument", "name": "data.db"}
    ]
  }'

# Version 2 (different keys due to version property)
curl -X POST https://keys.example.com \
  -H "Content-Type": application/json" \
  -d '{
    "semanticPath": [
      {"@type": "Organization", "name": "AcmeCorp"},
      {"@type": "SoftwareApplication", "name": "backup", "version": "2.0"},
      {"@type": "DigitalDocument", "name": "data.db"}
    ]
  }'
```

Different semantic paths (even with small changes like version numbers) produce different keys.

---

### Example 4: Application Isolation

Different applications should use different `appId` values:

```bash
# App 1
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{"filename": "config.json", "keyVersion": 1, "appId": "webapp"}'

# App 2
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{"filename": "config.json", "keyVersion": 1, "appId": "mobile"}'
```

The keys will be different even though `filename` and `keyVersion` are the same.

---

## Integration with Age Encryption

The API returns Age-compatible keys that work with the [age encryption tool](https://age-encryption.org/).

### Encryption Example

```bash
# 1. Get public key from API
PUBLIC_KEY=$(curl -s -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{"filename":"secret.txt","keyVersion":1,"appId":"docs"}' \
  | jq -r '.age_public_key')

# 2. Encrypt file with age
echo "$PUBLIC_KEY" > /tmp/pubkey.txt
age -R /tmp/pubkey.txt -o secret.txt.age secret.txt
```

### Decryption Example

```bash
# 1. Get private key from API
PRIVATE_KEY=$(curl -s -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{"filename":"secret.txt","keyVersion":1,"appId":"docs","getPrivateKey":true}' \
  | jq -r '.age_private_key')

# 2. Decrypt file with age
echo "$PRIVATE_KEY" > /tmp/privkey.txt
age -d -i /tmp/privkey.txt -o secret.txt secret.txt.age
rm /tmp/privkey.txt  # Clean up sensitive material
```

---

## Rate Limiting

**Current Status**: No rate limiting implemented.

**Recommendation**: Implement rate limiting at:
- Cloudflare Worker level (using Durable Objects or KV)
- Cloudflare rate limiting rules
- External API gateway

Without rate limiting, the service is vulnerable to:
- Brute-force enumeration attacks
- Denial of service
- Excessive API costs

---

## CORS

**Current Status**: No CORS headers configured.

If you need to call this API from a browser, add CORS headers to the Worker response:

```typescript
return new Response(JSON.stringify(result), {
  headers: {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "https://your-app.com",
    "Access-Control-Allow-Methods": "POST",
    "Access-Control-Allow-Headers": "Content-Type"
  }
});
```

---

## Security Best Practices

1. **Never expose `getPrivateKey: true` endpoints publicly**
   - Use authentication and authorization
   - Restrict to trusted clients only
   - Consider IP allowlisting

2. **Use TLS/HTTPS exclusively**
   - Cloudflare Workers provide TLS by default
   - Never use HTTP for key material transmission

3. **Implement request logging (without logging keys)**
   - Log request metadata (timestamp, IP, appId, filename)
   - NEVER log the mnemonic, private keys, or entropy
   - Use Cloudflare Workers logging or external logging services

4. **Rotate the master mnemonic periodically**
   - Plan for mnemonic rotation
   - Maintain key derivation history for decryption

5. **Monitor for anomalous access patterns**
   - Unusual request volumes
   - Requests for many different keyVersions
   - Geographic anomalies

---

## Limitations

### Current Limitations

1. **No authentication**: Anyone with the URL can request keys
2. **No rate limiting**: Vulnerable to abuse
3. **No audit logging**: No record of who requested which keys
4. **Single mnemonic**: All keys derived from one secret
5. **No key revocation**: Derived keys cannot be revoked individually

### Architectural Limitations

1. **Deterministic IVs**: The IV is derived from the filename hash. While deterministic encryption is intentional for this use case, it has security implications (see `docs/SECURITY.md`).

2. **Key entropy depends only on keyVersion**: The current implementation derives entropy from `keyVersion` alone. While `appId` and `filename` are included in the derivation path, they don't contribute to the entropy itself. This means you need to use different `keyVersion` values to get different keys for different files within the same app.

---

## Troubleshooting

### Issue: "Missing filename, appId, or keyVersion"

**Cause**: One or more required fields are missing or undefined.

**Solution**: Ensure all three required fields are present:
```json
{
  "filename": "file.txt",
  "keyVersion": 1,
  "appId": "myapp"
}
```

### Issue: Keys don't match between requests

**Cause**: One of the input parameters differs between requests.

**Solution**: Verify that `filename`, `keyVersion`, and `appId` are exactly identical:
- Same spelling and capitalization
- Same whitespace
- Same keyVersion number

### Issue: Age can't decrypt with derived key

**Cause**: Mismatch between encryption and decryption parameters.

**Solution**: 
- Ensure you're using the same `filename`, `keyVersion`, and `appId` for both operations
- Verify the mnemonic hasn't changed
- Check that the encrypted file hasn't been corrupted

---

## Client Libraries

### JavaScript/TypeScript (Node.js)

You can import the core derivation functions directly:

```typescript
import { deriveFromMnemonic } from './src/bip85kms';

const mnemonic = process.env.MNEMONIC_SECRET;
const result = deriveFromMnemonic(mnemonic, 1, "myapp", "file.txt");
console.log(result.age_public_key);
```

### JavaScript (Browser)

The browser demo at `index.html` shows how to use the derivation functions client-side:

```javascript
import { deriveFromMnemonic } from "./src/core.js";

const result = deriveFromMnemonic(mnemonic, keyVersion, appId, filename);
// Use result.age_public_key and result.iv
```

### Python

See `python/cli.py` for a Python implementation using the `bipsea` library.

### Shell/Bash

The scripts in `bin/` show how to integrate with curl and Age:
- `bin/deterministic_age.sh` - Age encryption/decryption wrapper
- `bin/deterministic_openssl_encrypt.sh` - OpenSSL encryption wrapper

---

## Related Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture and design decisions
- [SECURITY.md](./SECURITY.md) - Security model and threat analysis
- [README.md](../readme.md) - Project overview and getting started guide

---

## Support

This is an open-source educational project. For issues or questions:
- Open an issue on GitHub: https://github.com/Amperstrand/BIP85KMS/issues
- Review the existing documentation in the `docs/` folder

**Important**: This project is a proof-of-concept. Use in production at your own risk after thorough security review and hardening.
