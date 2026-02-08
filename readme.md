## Dependencies that have already been installed
```
npm install @scure/bip39 @scure/bip32 @noble/hashes
npm install @noble/secp256k1
npm install bech32@latest
```

## DISCLAIMER

not tested. just a proof of concept. Use your own keys. Host your own instance.

## Deploy
```
echo "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon" | wrangler secret put MNEMONIC_SECRET
npx wrangler deploy --routes https://keys.dns4sats.xyz/*
```

## curl demo
```
curl -s -X POST https://keys.dns4sats.xyz -H "Content-Type: application/json" -d '{"filename":"README.md","keyVersion":1,"appId":"docs","getPrivateKey":true}' | jq -r
```

```
{
  "derivationPath": "m/83696968'/128169'/1'/1186212674'/859136773'",
  "age_private_key": "AGE-SECRET-KEY-1M4XE5PZGVMPX0D923NHT6HRXT7VEZRMCYHJZYTD8UR6WX0A29WGSR6KPEW",
  "age_public_key": "age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33",
  "raw_entropy": "d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81",
  "iv": "b335630551682c19a781afeb"
}
```

```
curl -s -X POST https://keys.dns4sats.xyz -H "Content-Type: application/json" -d '{"filename":"README.md","keyVersion":1,"appId":"docs"}' | jq -r
```

```
{
  "age_public_key": "age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33",
  "iv": "b335630551682c19a781afeb"
}
```

## age demo

```
cd bin && ./age_demo.sh
[DEBUG] Operation mode determined: encrypt
[DEBUG] Private key file: /dev/shm/age_prv.TQVHfD
[DEBUG] Public key file:  /dev/shm/age_pub.y9QFb2
[DEBUG] Encrypting: hello_age.txt
[DEBUG] Fetching keys from server with payload: {"filename":"hello_age.txt","keyVersion":1,"appId":"docs"}
[DEBUG] Server response JSON: {"age_public_key":"age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33","iv":"16156fb9664f1d85f07d0793"}
[DEBUG] Encrypt output file: hello_age.txt.age
✅ Encrypted: hello_age.txt => hello_age.txt.age
[DEBUG] Cleaning up key files.
[DEBUG] Operation mode determined: decrypt
[DEBUG] Private key file: /dev/shm/age_prv.kqx68T
[DEBUG] Public key file:  /dev/shm/age_pub.yWH8Q4
[DEBUG] Decrypting: hello_age.txt.age
[DEBUG] Fetching keys from server with payload: {"filename":"hello_age.txt.age","keyVersion":1,"appId":"docs","getPrivateKey":true}
[DEBUG] Server response JSON: {"derivationPath":"m/83696968'/128169'/1'/1186212674'/1347622895'","age_private_key":"AGE-SECRET-KEY-1M4XE5PZGVMPX0D923NHT6HRXT7VEZRMCYHJZYTD8UR6WX0A29WGSR6KPEW","age_public_key":"age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33","raw_entropy":"d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81","iv":"d05317efd337e657a189108e"}
[DEBUG] Verified: private key => public key matches the server's public key.
[DEBUG] Decrypt output file: hello_age.txt
✅ Decrypted: hello_age.txt.age => hello_age.txt
[DEBUG] Cleaning up key files.
```

## openssl demo

WARNING: the encryption method needs feedback/review

```
cd bin && ./openssl_demo.sh
[DEBUG] Operation mode determined: encrypt
[DEBUG] Base filename for key retrieval: hello_openssl.txt
[DEBUG] Temporary key file: /dev/shm/openssl_key.J3Vluy
[DEBUG] Encrypting file: hello_openssl.txt
[DEBUG] Computed SHA256: 32a4652ec63b896e60e82bdecbcfe97394037243cb2c8e63d7dd79b0a7d4f383
[DEBUG] Derived IV (first 32 hex digits): 32a4652ec63b896e60e82bdecbcfe973
[DEBUG] Output file will be: hello_openssl.txt.32a4652ec63b896e60e82bdecbcfe97394037243cb2c8e63d7dd79b0a7d4f383.enc
[DEBUG] Fetching key from server with payload: {"filename":"hello_openssl.txt","keyVersion":1,"appId":"docs","getPrivateKey":true}
[DEBUG] Server response JSON: {"derivationPath":"m/83696968'/128169'/1'/1186212674'/2137221032'","age_private_key":"AGE-SECRET-KEY-1M4XE5PZGVMPX0D923NHT6HRXT7VEZRMCYHJZYTD8UR6WX0A29WGSR6KPEW","age_public_key":"age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33","raw_entropy":"d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81","iv":"7f6367a858d7a6c7700988a0"}
[DEBUG] Using key: d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81
✅ Encrypted: hello_openssl.txt => hello_openssl.txt.32a4652ec63b896e60e82bdecbcfe97394037243cb2c8e63d7dd79b0a7d4f383.enc
[DEBUG] Cleaning up temporary key file.
[DEBUG] Operation mode determined: decrypt
[DEBUG] Base filename for key retrieval: hello_openssl.txt
[DEBUG] Temporary key file: /dev/shm/openssl_key.KFlFMk
[DEBUG] Decrypting file: hello_openssl.txt.32a4652ec63b896e60e82bdecbcfe97394037243cb2c8e63d7dd79b0a7d4f383.enc
[DEBUG] Using IV (derived from filename): 32a4652ec63b896e60e82bdecbcfe973
[DEBUG] Fetching key from server with payload: {"filename":"hello_openssl.txt","keyVersion":1,"appId":"docs","getPrivateKey":true}
[DEBUG] Server response JSON: {"derivationPath":"m/83696968'/128169'/1'/1186212674'/2137221032'","age_private_key":"AGE-SECRET-KEY-1M4XE5PZGVMPX0D923NHT6HRXT7VEZRMCYHJZYTD8UR6WX0A29WGSR6KPEW","age_public_key":"age15vzcvrduzysjsns520xkrd9les2nxjllnrhql9lefm4rhtkjmqeqglns33","raw_entropy":"d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81","iv":"7f6367a858d7a6c7700988a0"}
[DEBUG] Using key: d81b4fb9db6d620a5d8b26b24ee4423f74bf1a555137d2e0c6eec2ef088ddd81
[DEBUG] Decrypted output file will be: hello_openssl.txt
✅ Decrypted: hello_openssl.txt.32a4652ec63b896e60e82bdecbcfe97394037243cb2c8e63d7dd79b0a7d4f383.enc => hello_openssl.txt (SHA256 match: 32a4652ec63b896e60e82bdecbcfe97394037243cb2c8e63d7dd79b0a7d4f383)
[DEBUG] Cleaning up temporary key file.
```

## node cli

```
npm install
npm run build
export MNEMONIC_SECRET="bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon"
node dist/cli.js --filename "hello_openssl.txt" --keyVersion 1 --appId "docs" --getPrivateKey
```


## python cli
```
pip install bipsea cryptography --break-system-packages
python3 python/cli.py --filename "hello_openssl.txt" --keyVersion 1 --appId "docs" --getPrivateKey
```

## GitHub Pages standalone browser demo

A client-side demo is available in `docs/` and can be published with GitHub Pages.

- The demo runs derivation entirely in the browser.
- It defaults to the educational mnemonic `bacon bacon ...` so people can click-and-learn quickly.
- **Do not use real mnemonics/private secrets in this demo.**

- The browser demo defaults to public output only; check **Include private key output** only if you explicitly want full key material in the page output.

### Local preview

```bash
python3 -m http.server 4173 --directory docs
# open http://localhost:4173
```

### Publish on GitHub Pages

This repository includes `.github/workflows/pages.yml` to deploy `docs/`.

Workflow name in Actions: **Deploy demo to GitHub Pages**.

#### Do I need manual steps?

Yes — there is a **one-time manual setup** in GitHub. After that, deployment is automatic.

#### One-time manual setup

1. Open your GitHub repository.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.
4. Save.

#### After one-time setup (automatic deploys)

- Pushes to `main` trigger the Pages workflow automatically.
- You can also run it manually from **Actions → Deploy demo to GitHub Pages → Run workflow** and set `ref` to a branch (for example `work`) or `main`.
- The workflow uploads `docs/` and publishes it to GitHub Pages.


#### Fastest way to test before merge

1. Push your feature branch (for example `work`).
2. Go to **Actions → Deploy demo to GitHub Pages → Run workflow**.
3. Set `ref` to your branch name (`work`) and run it.
4. Open the run logs and copy `page_url` from the deploy step.
5. Verify the live demo loads and derives keys.

#### How to verify it worked

1. Open the workflow run in **Actions**.
2. Check the final deploy step for `page_url`.
3. Visit that URL.

For a typical public repo named `BIP85KMS`, the URL will look like:

`https://<your-github-username>.github.io/BIP85KMS/`
