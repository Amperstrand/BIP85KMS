# BIP85KMS Security Model and Considerations

## Executive Summary

BIP85KMS is a **proof-of-concept** deterministic key management service. It prioritizes:
- **Reproducibility**: Same inputs always produce same keys
- **Simplicity**: Minimal moving parts, easy to audit
- **Transparency**: No hidden key storage, all derivation is deterministic

However, it **intentionally omits** many security features required for production use:
- No authentication or authorization
- No rate limiting or abuse protection
- No audit logging
- No key revocation mechanisms
- No defense against side-channel attacks

**Use this project to learn about deterministic key derivation. Do not use it in production without significant security hardening.**

---

## Security Model

### What BIP85KMS Protects Against

1. **Key Storage Vulnerabilities**
   - **Threat**: Database breach exposing stored keys
   - **Protection**: No keys are stored; all are derived on-demand from a single mnemonic

2. **Key Synchronization Issues**
   - **Threat**: Keys getting out of sync across systems
   - **Protection**: Deterministic derivation ensures identical keys everywhere

3. **Key Backup Complexity**
   - **Threat**: Complex key management requiring multiple backups
   - **Protection**: Single mnemonic backup secures all derived keys

### What BIP85KMS Does NOT Protect Against

1. **Mnemonic Compromise**
   - If the master mnemonic is exposed, **all derived keys are compromised**
   - There is no mechanism to revoke or rotate individual keys
   - Mitigation requires generating a new mnemonic and re-encrypting all data

2. **Unauthorized API Access**
   - No authentication means anyone with the endpoint can request keys
   - An attacker can enumerate all possible keys by trying different parameters
   - **Critical**: Must implement authentication before any production use

3. **Replay Attacks**
   - No request uniqueness validation (nonces, timestamps)
   - An attacker can replay captured requests to retrieve the same keys
   - Mitigation requires request signing or authentication tokens

4. **Side-Channel Attacks**
   - No protection against timing attacks, power analysis, or cache attacks
   - Key derivation operations may leak information through timing
   - Not suitable for environments where attackers have physical access

5. **Denial of Service**
   - No rate limiting allows resource exhaustion
   - Cloudflare Workers have some built-in DDoS protection, but not application-level

6. **Man-in-the-Middle Attacks**
   - While Cloudflare Workers use HTTPS, no certificate pinning or extra validation
   - Rely on TLS/SSL for transport security

---

## Threat Model

### Assumptions

1. **Trusted Execution Environment**: The Cloudflare Worker runtime is trusted
2. **TLS Security**: HTTPS/TLS provides adequate transport encryption
3. **Mnemonic Secrecy**: The `MNEMONIC_SECRET` environment variable is kept secret
4. **Client Security**: Clients requesting keys are trusted (no malicious clients)

### Attack Scenarios

#### Scenario 1: Mnemonic Exposure

**Attack**: An attacker obtains the `MNEMONIC_SECRET` through:
- Cloudflare account compromise
- Insider threat
- Backup exposure
- Code repository leak (if hardcoded)

**Impact**: **CRITICAL** - All past, present, and future keys are compromised

**Mitigation**:
- Store mnemonic in Cloudflare Workers secrets (encrypted at rest)
- Never commit mnemonic to version control
- Use hardware security modules (HSMs) for mnemonic storage in high-security scenarios
- Implement key rotation strategy requiring re-encryption of all data
- Consider multi-party computation (MPC) for mnemonic splits

**Recovery**:
1. Generate new mnemonic immediately
2. Deploy new Worker with new mnemonic
3. Re-encrypt all data with newly derived keys
4. Revoke access to old endpoint
5. Audit logs to determine scope of exposure

---

#### Scenario 2: Unauthorized API Access

**Attack**: An attacker discovers the Worker endpoint and requests private keys

**Impact**: **HIGH** - Attacker can decrypt specific files if they know parameters

**Current Vulnerability**: No authentication, any requester can set `getPrivateKey: true`

**Mitigation Options**:

**Option A: Mutual TLS (mTLS)**
```typescript
// Validate client certificate
if (!request.cf?.tlsClientAuth?.certVerified) {
  return new Response("Unauthorized", { status: 401 });
}
```

**Option B: JWT Authentication**
```typescript
import { verify } from '@tsndr/cloudflare-worker-jwt';

async function validateJWT(request: Request): Promise<boolean> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return false;
  
  const token = authHeader.substring(7);
  return await verify(token, env.JWT_SECRET);
}
```

**Option C: HMAC Request Signing**
```typescript
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';

function verifyRequestSignature(request: Request, body: string, signature: string): boolean {
  const expectedSig = hmac(sha256, env.HMAC_SECRET, body);
  const providedSig = hexToBytes(signature);
  return timingSafeEqual(expectedSig, providedSig);
}
```

**Option D: IP Allowlisting**
```typescript
const ALLOWED_IPS = ['192.168.1.0/24', '10.0.0.0/8'];

function isAllowedIP(ip: string): boolean {
  return ALLOWED_IPS.some(range => ipInRange(ip, range));
}
```

**Option E: Cloudflare Access**
- Configure Cloudflare Access for identity-based authentication
- Integrates with IdP (Google, GitHub, Okta, etc.)
- Provides audit logs and session management

---

#### Scenario 3: Key Enumeration Attack

**Attack**: Attacker systematically requests keys for all possible parameter combinations

**Impact**: **MEDIUM to HIGH** - Depends on keyspace size and attacker's knowledge

**Current Vulnerability**: No rate limiting, unlimited requests allowed

**Mitigation**:

**Rate Limiting with Durable Objects**:
```typescript
// Track requests per IP
const rateLimiter = await env.RATE_LIMITER.get(clientIP);
if (rateLimiter.isExceeded()) {
  return new Response("Too Many Requests", { status: 429 });
}
```

**Cloudflare Rate Limiting Rules**:
- Configure at Cloudflare Dashboard
- Limit requests per IP or per endpoint
- Apply progressive delays or blocking

**Application-Level Throttling**:
```typescript
// Add artificial delay to slow brute force
await new Promise(resolve => setTimeout(resolve, 100));
```

---

#### Scenario 4: Deterministic IV Vulnerabilities

**Attack**: Exploit the deterministic IV generation from filename hash

**Impact**: **MEDIUM** - Information leakage in specific scenarios

**Vulnerability Details**:

The current implementation uses:
```javascript
iv: bufferToHex(sha256(filename).slice(0, 12))
```

This means:
- Same filename always produces same IV
- IV is not a secret (derived from known filename)
- Pattern analysis could reveal which ciphertexts correspond to same files

**Implications**:

1. **Identical Plaintext Detection**: If the same file content is encrypted multiple times with the same key and IV, the ciphertexts will be identical, revealing that the same data was encrypted.

2. **Chosen-Plaintext Attacks**: If an attacker can influence the plaintext and observe ciphertexts, deterministic IVs may leak information.

3. **Not Recommended for AES-GCM**: Modern AEAD schemes like AES-GCM require unique IVs for each encryption with the same key. Reusing IVs catastrophically breaks security.

**Mitigation**:

For Age encryption: Age handles nonce generation internally, the `iv` field is for auxiliary use.

For symmetric encryption (AES, ChaCha20):
- **Option 1**: Include a random component in the filename (e.g., `file-{uuid}.txt`)
- **Option 2**: Append a counter or timestamp to ensure unique IVs
- **Option 3**: Use a different IV derivation: `SHA-256(filename || keyVersion || timestamp)`

**When Deterministic IVs Are Acceptable**:
- File content changes between encryptions (different data each time)
- Content-addressable encryption (deterministic by design)
- Use with stream ciphers where IV uniqueness is not critical (with proper key rotation)

---

#### Scenario 5: Logging and Audit Failures

**Attack**: Attacker accesses keys without detection

**Impact**: **MEDIUM** - No forensic evidence of compromise

**Current State**: No logging implemented

**Recommended Logging Strategy**:

**What TO Log**:
```typescript
interface AuditLog {
  timestamp: string;
  clientIP: string;
  requestId: string;
  appId: string;
  filename: string;  // May need redaction depending on sensitivity
  keyVersion: number;
  requestedPrivateKey: boolean;
  responseStatus: number;
  userAgent?: string;
}
```

**What NOT TO Log**:
- Never log the mnemonic
- Never log derived private keys
- Never log raw entropy
- Be careful with filename if it contains PII

**Implementation Options**:

**Cloudflare Logpush**:
```typescript
// Worker automatically logs to Cloudflare
// Access via Dashboard → Analytics → Logs
```

**External Logging Service**:
```typescript
await fetch('https://logs.example.com/api/events', {
  method: 'POST',
  body: JSON.stringify(auditLog),
  headers: { 'Authorization': `Bearer ${env.LOG_TOKEN}` }
});
```

**Durable Objects for Log Storage**:
```typescript
const logStore = await env.AUDIT_LOGS.get(logId);
await logStore.append(auditLog);
```

---

## Cryptographic Security Analysis

### BIP39 Mnemonic Strength

**24-word mnemonic**:
- Entropy: 256 bits
- Possible combinations: 2^256 ≈ 1.16 × 10^77
- **Verdict**: Cryptographically secure if generated properly

**12-word mnemonic**:
- Entropy: 128 bits
- Possible combinations: 2^128 ≈ 3.4 × 10^38
- **Verdict**: Adequate for most use cases, secure for non-quantum adversaries

**Recommendation**: Use 24-word mnemonics for high-security applications.

### BIP32 Hierarchical Derivation

**Algorithm**: BIP32 uses HMAC-SHA512 for child key derivation

**Hardened Derivation**: All indexes use hardened derivation (')
- Prevents parent public key from deriving child keys
- Necessary when exposing public keys

**Security Properties**:
- Forward security: Parent key compromise doesn't reveal child keys
- Backward security: Child key compromise doesn't reveal parent or sibling keys (with hardened derivation)

### BIP85 Entropy Derivation

**Process**:
1. Derive child at `m/83696968'/{index}'`
2. SHA-256 hash the private key

**Security**:
- Entropy quality: As strong as SHA-256 (256-bit collision resistance)
- Deterministic: Same index always produces same entropy
- Index isolation: Different indexes produce independent entropy

**Concern**: Current implementation only uses `keyVersion` (indexes[0]) for entropy
- `appId` and `filename` only affect derivation path string, not entropy
- Same `keyVersion` produces same entropy across different files/apps
- **Recommendation**: Incorporate all three parameters into entropy derivation

### Age Key Derivation

**Algorithm**: X25519 (Curve25519) for ECDH

**Key Generation**:
```javascript
const rawSecret = hmac(sha256, entropy, indexBytes);  // 32-byte secret scalar
const pubBytes = x25519.getPublicKey(rawSecret);       // Curve25519 point
```

**Security Properties**:
- X25519 provides ~128-bit security against quantum computers (best known attacks)
- ~256-bit security against classical computers
- Key indistinguishability: Derived keys are computationally indistinguishable from random

**Age Specification**: https://age-encryption.org/v1

---

## Key Isolation Analysis

### Current Architecture

**Single Mnemonic Design**:
- All applications share the same root mnemonic
- Isolation achieved through different derivation paths
- If mnemonic is compromised, all applications are compromised

**Isolation Levels**:

1. **Application-level**: Different `appId` values
   - Derivation paths differ in the `appIdHash` component
   - Keys are cryptographically independent
   - **Limitation**: Same entropy if same `keyVersion` is used

2. **File-level**: Different `filename` values
   - Derivation paths differ in `filenameHash` component
   - **Limitation**: Same entropy if same `keyVersion` is used

3. **Version-level**: Different `keyVersion` values
   - Actually affects entropy derivation
   - **Best practice**: Use different versions for true key isolation

### Recommendations for Multi-Tenancy

If you need to support multiple tenants or isolated environments:

**Option 1: Multiple Workers**
- Deploy separate Workers with different mnemonics
- Each tenant gets their own Worker instance
- **Pros**: Complete isolation, independent security boundaries
- **Cons**: Management overhead, higher costs

**Option 2: Mnemonic-per-Tenant Storage**
```typescript
// Store mnemonics in KV or Durable Objects
const mnemonic = await env.TENANT_MNEMONICS.get(tenantId);
const result = deriveFromMnemonic(mnemonic, keyVersion, appId, filename);
```
- **Pros**: Single Worker, logical isolation
- **Cons**: More complex, mnemonic storage security critical

**Option 3: Tenant-specific Key Derivation**
```typescript
// Include tenantId in derivation
const tenantHash = sha256(new TextEncoder().encode(tenantId));
const tenantIndex = intFromBytes(tenantHash.slice(0, 4)) & 0x7fffffff;

// Derive tenant-specific master node
const tenantNode = masterNode.derive(`m/${tenantIndex}'`);
// Then derive keys from tenantNode
```
- **Pros**: Single mnemonic, cryptographic isolation
- **Cons**: All tenants compromised if mnemonic leaks

---

## Production Hardening Checklist

Before deploying to production, implement the following:

### Authentication & Authorization
- [ ] Implement client authentication (mTLS, JWT, HMAC, or Access)
- [ ] Restrict `getPrivateKey: true` to authorized clients only
- [ ] Consider separate endpoints for public vs private key retrieval
- [ ] Implement role-based access control (RBAC)

### Rate Limiting & DoS Protection
- [ ] Implement rate limiting per IP address
- [ ] Implement rate limiting per appId/tenant
- [ ] Set up Cloudflare rate limiting rules
- [ ] Add exponential backoff for failed requests

### Audit & Monitoring
- [ ] Implement comprehensive audit logging
- [ ] Set up alerting for suspicious patterns:
  - High request volumes
  - Multiple `getPrivateKey` requests
  - Requests from unusual geographic locations
  - Failed authentication attempts
- [ ] Log to secure, append-only storage
- [ ] Implement log retention policies

### Key Management
- [ ] Document mnemonic backup procedures
- [ ] Implement mnemonic rotation strategy
- [ ] Store mnemonic in secure key management service (not just Workers secrets)
- [ ] Consider multi-party computation (MPC) for mnemonic splits
- [ ] Test disaster recovery procedures

### Security Headers & Policies
- [ ] Configure Content Security Policy (CSP)
- [ ] Set strict CORS policies
- [ ] Implement request size limits
- [ ] Add security headers (HSTS, X-Frame-Options, etc.)

### Code Security
- [ ] Run security audit (SAST/DAST)
- [ ] Enable dependency scanning
- [ ] Implement input validation and sanitization
- [ ] Use timing-safe comparison for secrets
- [ ] Review and test error handling (avoid information leakage)

### Operational Security
- [ ] Implement health checks and monitoring
- [ ] Set up incident response procedures
- [ ] Document security policies and procedures
- [ ] Regular security reviews and penetration testing
- [ ] Principle of least privilege for Worker permissions

---

## Known Vulnerabilities

### CRITICAL

1. **No Authentication on Private Key Endpoint**
   - **Risk**: Anyone can request private keys
   - **Status**: By design for PoC, must fix for production
   - **Mitigation**: Implement authentication (see Scenario 2)

2. **Single Point of Failure (Mnemonic)**
   - **Risk**: Mnemonic compromise exposes all keys forever
   - **Status**: Architectural limitation
   - **Mitigation**: Secure mnemonic storage, consider HSM or MPC

### HIGH

3. **No Rate Limiting**
   - **Risk**: Brute-force enumeration, DoS attacks
   - **Status**: Not implemented
   - **Mitigation**: Implement rate limiting

4. **No Audit Logging**
   - **Risk**: No forensic evidence of attacks
   - **Status**: Not implemented
   - **Mitigation**: Implement comprehensive logging

5. **Key Entropy Limited to keyVersion**
   - **Risk**: Same keyVersion produces same entropy across files/apps
   - **Status**: Design limitation requiring code change
   - **Mitigation**: Modify `deriveKeyAndIV` to incorporate all parameters

### MEDIUM

6. **Deterministic IV Generation**
   - **Risk**: Information leakage in specific scenarios
   - **Status**: By design, has trade-offs
   - **Mitigation**: Document limitations, recommend Age (which handles nonces internally)

7. **No Request Replay Protection**
   - **Risk**: Captured requests can be replayed
   - **Status**: No nonce or timestamp validation
   - **Mitigation**: Implement request signing with nonces

---

## Security Recommendations by Deployment Scenario

### Development / Testing

**Acceptable**:
- No authentication (if running locally)
- Demo mnemonics
- No audit logging
- Public `getPrivateKey` access

**Still Recommended**:
- Use HTTPS even in development
- Never commit mnemonics to git
- Test authentication implementations

### Staging / Pre-Production

**Required**:
- Authentication implementation
- Unique mnemonic (not demo)
- Basic audit logging
- Rate limiting

**Recommended**:
- Monitor for anomalies
- Test disaster recovery
- Security scanning

### Production

**Absolutely Required**:
- Strong authentication and authorization
- Secure mnemonic storage (secrets management service or HSM)
- Comprehensive audit logging with alerting
- Rate limiting and DoS protection
- Regular security audits
- Incident response plan
- Backup and recovery procedures tested

**Strongly Recommended**:
- Multi-factor authentication for administrative access
- Penetration testing
- Bug bounty program
- Regular threat model reviews
- Security training for team

---

## Cryptographic Best Practices

### For Users of BIP85KMS

1. **Never Reuse Keys Across Security Boundaries**
   - Use different `appId` for different applications
   - Use different `keyVersion` for key rotation

2. **Properly Handle Key Material**
   - Never log private keys
   - Clear keys from memory after use (if possible in your language)
   - Use secure key storage on clients (keychain, TPM)

3. **Use Age Correctly**
   - Age handles nonces/IVs internally, use its built-in security
   - Don't roll your own encryption schemes
   - Follow Age best practices: https://age-encryption.org/

4. **Validate Derived Keys**
   - Verify public key matches private key
   - Check derivation path matches expectations
   - Detect key rollover/rotation

### For BIP85KMS Developers

1. **Use Constant-Time Comparisons**
   ```typescript
   function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
     if (a.length !== b.length) return false;
     let result = 0;
     for (let i = 0; i < a.length; i++) {
       result |= a[i] ^ b[i];
     }
     return result === 0;
   }
   ```

2. **Validate All Inputs**
   ```typescript
   if (typeof keyVersion !== 'number' || keyVersion < 0 || keyVersion > 0x7fffffff) {
     throw new Error('Invalid keyVersion');
   }
   ```

3. **Fail Securely**
   - Generic error messages (avoid leaking derivation details)
   - Return early on authentication failures
   - Log security-relevant events

4. **Keep Dependencies Updated**
   - Monitor for vulnerabilities in crypto libraries
   - Use `npm audit` regularly
   - Pin versions but update regularly

---

## Conclusion

BIP85KMS demonstrates powerful deterministic key derivation concepts but lacks critical security features for production use. It serves as:

- ✅ **Educational tool** for learning about BIP39/BIP32/BIP85
- ✅ **Reference implementation** for deterministic key derivation
- ✅ **Prototype** for key management architectures
- ❌ **Production KMS** without significant security hardening

**Bottom Line**: Understand the risks, implement the recommended mitigations, and conduct thorough security review before any production deployment.

---

## References

- [BIP39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP85: Deterministic Entropy From BIP32 Keychains](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
- [Age Encryption Specification](https://age-encryption.org/v1)
- [NIST SP 800-57: Key Management Recommendations](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

---

**Document Version**: 1.0  
**Last Updated**: 2026-02-16  
**Status**: Initial Release
