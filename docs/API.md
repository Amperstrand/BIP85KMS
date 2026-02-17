# BIP85KMS API Documentation

## Overview

BIP85KMS provides a RESTful HTTP API for deterministic key derivation based on BIP85-style entropy generation. The service derives Age-compatible encryption keys from a master mnemonic and request metadata without storing any per-file keys.

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
- Retrieve public keys and IVs
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
  filename: string;      // File identifier (required)
  keyVersion: number;    // Key rotation version (required, ≥ 0)
  appId: string;         // Application identifier (required)
  getPrivateKey?: boolean; // Return private key material (optional, default: false)
}
```

**Field Descriptions**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `filename` | string | Yes | File identifier used in derivation path and IV generation. Can be any string, typically a filename or unique identifier. |
| `keyVersion` | number | Yes | Key rotation version number (0-2147483647). Increment to derive new keys for the same file/app. |
| `appId` | string | Yes | Application identifier for logical key isolation. Different apps should use different appIds. |
| `getPrivateKey` | boolean | No | If `true`, response includes private key material. Default `false` returns only public key and IV. **Use with extreme caution**. |

---

## Response Formats

### Public Mode Response (getPrivateKey: false or omitted)

Returns only the public key and IV needed for encryption.

**HTTP Status**: `200 OK`

**Response Body**:

```json
{
  "age_public_key": "age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33",
  "iv": "b335630551682c19a781afeb"
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `age_public_key` | string | Age-format public key (bech32 encoding with "age" prefix). Used as the recipient for Age encryption. |
| `iv` | string | 96-bit initialization vector (24 hex characters). Derived deterministically from SHA-256(filename). |

---

### Private Mode Response (getPrivateKey: true)

Returns full key material including private key, entropy, and derivation path.

**HTTP Status**: `200 OK`

**Response Body**:

```json
{
  "derivationPath": "m/83696968'/128169'/1'/1186212674'/859136773'",
  "age_private_key": "AGE-SECRET-KEY-1M4XE5PZGVMPX0D923NHT6HRXT7VEZRMCYHJZYTD8UR6WX0A29WGSR6KPEW",
  "age_public_key": "age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33",
  "raw_entropy": "d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81",
  "iv": "b335630551682c19a781afeb"
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `derivationPath` | string | BIP32 derivation path used for this key. Format: `m/83696968'/128169'/{keyVersion}'/{appIdHash}'/{filenameHash}'` |
| `age_private_key` | string | Age-format private key (bech32 encoding with "AGE-SECRET-KEY-" prefix). Used for Age decryption. **Highly sensitive**. |
| `age_public_key` | string | Age-format public key corresponding to the private key. |
| `raw_entropy` | string | 32 bytes (64 hex chars) of BIP85-derived entropy. The seed material from which keys are derived. **Highly sensitive**. |
| `iv` | string | 96-bit initialization vector (24 hex characters). Same as in public mode. |

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

### 400 Bad Request - Missing Fields

Returned when required fields are missing.

**HTTP Status**: `400 Bad Request`

**Response Body**:

```json
{
  "error": "Missing filename, appId, or keyVersion"
}
```

---

### 400 Bad Request - Invalid Input

Returned when request parsing or key derivation fails.

**HTTP Status**: `400 Bad Request`

**Response Body**:

```json
{
  "error": "<error message>"
}
```

---

## IV (Initialization Vector) Derivation

The IV is derived deterministically from the filename:

```
iv = sha256(filename)[:12]  # 96 bits, hex-encoded (24 characters)
```

**This is consistent with BIP85KMS's core design**: all cryptographic material is derivable from the filename alone, without needing the file content.

### Why Filename-Based IV?

1. **Pre-allocation**: Derive IV before file exists
2. **Consistency**: Same filename always produces same IV
3. **Decoupling**: Encryption parameters independent of file content

### AES-GCM / Symmetric Encryption Warning

For AES-GCM and other AEAD ciphers, IV reuse with the same key is catastrophic. Since filename-based IV produces the same IV for the same filename:

- **Same file content + same keyVersion**: Safe (same ciphertext is acceptable)
- **Different file content + same keyVersion**: Use a different `keyVersion` for each unique content version

**Best Practice**: When re-encrypting a file that has changed, increment `keyVersion` to get a new key and avoid any IV reuse concerns.

**Recommended**: Use Age encryption instead of raw AES. Age handles nonces internally and correctly.

---

## Usage Examples

### Example 1: Encrypt a File (Public Key Only)

Request public key and IV for encrypting a file:

```bash
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "document.pdf",
    "keyVersion": 1,
    "appId": "myapp"
  }'
```

**Response**:

```json
{
  "age_public_key": "age1qyv7kkr...",
  "iv": "a1b2c3d4e5f6..."
}
```

**Use Case**: You have the public key to encrypt `document.pdf` using Age. The IV can be used for additional symmetric encryption schemes.

---

### Example 2: Decrypt a File (Private Key Required)

Request private key for decrypting a previously encrypted file:

```bash
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "document.pdf",
    "keyVersion": 1,
    "appId": "myapp",
    "getPrivateKey": true
  }'
```

**Response**:

```json
{
  "derivationPath": "m/83696968'/128169'/1'/2047162892'/1789546371'",
  "age_private_key": "AGE-SECRET-KEY-1...",
  "age_public_key": "age1qyv7kkr...",
  "raw_entropy": "a1b2c3d4...",
  "iv": "a1b2c3d4e5f6..."
}
```

**Use Case**: You have the private key to decrypt `document.pdf`. The same `filename`, `keyVersion`, and `appId` will always produce the same key pair.

---

### Example 3: Key Rotation

Rotate to a new key for the same file:

```bash
# Old key (version 1)
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{"filename": "data.db", "keyVersion": 1, "appId": "backup"}'

# New key (version 2)
curl -X POST https://keys.example.com \
  -H "Content-Type: application/json" \
  -d '{"filename": "data.db", "keyVersion": 2, "appId": "backup"}'
```

Different `keyVersion` values produce different keys for the same filename/appId combination.

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
