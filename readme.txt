npm install @scure/bip39 @scure/bip32 @noble/hashes
npm install @noble/secp256k1
npm install bech32@latest

wrangler deploy --routes https://keys.dns4sats.xyz/*


curl -s -X POST https://keys.dns4sats.xyz -H "Content-Type: application/json" -d '{"filename":"README.md","keyVersion":1,"appId":"docs"}' | jq -r

curl -s -X POST https://keys.dns4sats.xyz -H "Content-Type: application/json" -d '{"filename":"README.md","keyVersion":1,"appId":"docs","getPrivateKey":true}' | jq -r


based on https://github.com/keisentraut/age-keygen-deterministic/blob/main/src/main.rs

cat mnemonic.txt | wrangler secret put MNEMONIC_SECRET
