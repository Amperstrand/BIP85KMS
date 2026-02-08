# BIP85KMS (Proof of Concept)

Deterministic key derivation service for file encryption workflows.

This project runs as a Cloudflare Worker and derives keys from a single master mnemonic (`MNEMONIC_SECRET`). The goal is to avoid storing per-file keys at rest: the same inputs deterministically recreate the same derived key material.

## What this repository is trying to do

At a high level, this project is a **deterministic KMS-like service**:

- Input: `filename`, `keyVersion`, `appId` (and optionally `getPrivateKey`).
- Secret root: a BIP39 mnemonic stored as a Worker secret.
- Output:
  - Public mode: return an `age_public_key` and IV.
  - Private mode: additionally return `age_private_key`, derivation metadata, and raw entropy.

Core flow in the Worker:

1. Read JSON request.
2. Convert mnemonic -> seed -> BIP32 master node.
3. Derive deterministic entropy/key material.
4. Return either public-only or full key material.

## Current architecture

- `src/index.ts`: Worker HTTP API.
- `src/core.js`: shared derivation logic used by both Worker and browser app (single source of truth).
- `src/bip85kms.ts`: typed re-exports/wrapper for Worker/test imports.
- `bin/deterministic_age.sh`: age encrypt/decrypt helper script backed by remote key API.
- `bin/deterministic_openssl_encrypt.sh`: OpenSSL deterministic encrypt/decrypt helper script.
- `src/cli.ts` and `python/cli.py`: local CLIs to derive values without deploying.
- `index.html` + `web/app.js`: static GitHub Pages-friendly client app (all derivation in browser).

## What currently works

- Worker enforces `POST` and returns JSON for valid requests.
- Deterministic outputs are generated for the same input tuple and mnemonic.
- `bin/deterministic_age.sh` is usable for end-to-end encrypt/decrypt against a running key server.
- `bin/deterministic_openssl_encrypt.sh` can encrypt/decrypt and verify hash suffix consistency.

## Current status

- ✅ `npx vitest run` passes in this repository.
- ✅ Worker endpoint tests now validate method handling, validation errors, public response shape, and private-key response shape.
- ✅ Static browser app can derive keys client-side using the same shared functions as the Worker.
- ✅ Deterministic key tests validate repeatability and index separation.
- ⚠️ There is still no `npm run build` script in `package.json` (this project currently relies on Wrangler and direct TypeScript execution in tests).

## Important design/security gaps to fix next

These are the biggest issues to address before considering production use:

1. **No authentication/authorization on private key retrieval**
   - Anyone who can call the endpoint with `getPrivateKey: true` can receive private key material and raw entropy.
   - Add strong auth (mTLS, signed JWT, HMAC request signing, allowlist, etc.) before exposing this endpoint.

2. **Derivation is not fully scoped by `appId` + `filename`**
   - The current entropy/key derivation effectively depends only on `keyVersion` for the Age key material.
   - `appId` and `filename` are hashed into reported path metadata and IV, but not into the entropy used for the private key itself.
   - This can cause key reuse across different apps/files using the same `keyVersion`.

3. **Deterministic encryption caveats**
   - Deterministic schemes leak equality patterns (same plaintext and settings => same ciphertext in some modes/configs).
   - OpenSSL helper currently uses AES-256-CBC with deterministic IV construction and `-nosalt`; this requires a careful security review and likely redesign.

4. **Inconsistent IV behavior across components**
   - Worker returns IV from `sha256(filename)[:12]`.
   - OpenSSL helper derives IV from file content hash (first 16 bytes of SHA-256).
   - This mismatch creates confusion and indicates protocol drift.

5. **Hardcoded / non-standard elements**
   - `deriveMasterKey` uses Argon2id with a hardcoded salt string and is not wired into Worker flow.
   - Either remove dead code or clearly define and test where it should be used.

6. **Operational hardening missing**
   - No rate limiting, structured audit logging, request schema validation, rotation policy docs, or abuse controls.

## Recommended cleanup plan

1. Fix key derivation scope:
   - Include `appId` and `filename` (or domain-separated hashes of both) in actual key derivation inputs, not just metadata/path string.

2. Add access control:
   - Disallow unauthenticated `getPrivateKey` calls.

3. Unify deterministic-encryption protocol:
   - Decide one IV derivation strategy per algorithm and document it.

4. Improve developer ergonomics:
   - Add a real `build` script or remove references to it.
   - Add schema docs for request/response payloads.



## Static GitHub Pages mode (client-side only)

This repository now supports a fully static workflow:

- Open `index.html` in a browser (or host it on GitHub Pages).
- Enter mnemonic + input parameters.
- Derivation runs entirely client-side in `web/app.js`.
- The app imports the exact same derivation functions from `src/core.js` that the Worker uses, keeping behavior DRY and consistent.

To serve locally:

```bash
python3 -m http.server 8788
# then open http://localhost:8788
```

## Minimal local usage

Install dependencies:

```bash
npm install
```

Run tests:

```bash
npx vitest run
```

Run local worker dev server:

```bash
npx wrangler dev
```

Set secret and deploy:

```bash
echo "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon" | wrangler secret put MNEMONIC_SECRET
npx wrangler deploy
```

Example API call (public response):

```bash
curl -s -X POST https://<your-worker-host> \
  -H "Content-Type: application/json" \
  -d '{"filename":"README.md","keyVersion":1,"appId":"docs"}' | jq -r
```

Example API call (full/private response):

```bash
curl -s -X POST https://<your-worker-host> \
  -H "Content-Type: application/json" \
  -d '{"filename":"README.md","keyVersion":1,"appId":"docs","getPrivateKey":true}' | jq -r
```

## Disclaimer

This repository is still a proof of concept. Do not use it for production key management without completing the hardening items above.
