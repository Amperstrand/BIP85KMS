import { HDKey } from 'https://esm.sh/@scure/bip32@1.6.2';
import { mnemonicToSeedSync } from 'https://esm.sh/@scure/bip39@1.5.4';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.7.1/sha256';
import { hmac } from 'https://esm.sh/@noble/hashes@1.7.1/hmac';
import { bech32 } from 'https://esm.sh/bech32@2.0.0';
import { x25519 } from 'https://esm.sh/@noble/curves@1.9.7/ed25519';

const output = document.getElementById('output');
const deriveButton = document.getElementById('derive');

function bufferToHex(buf) {
  return [...buf].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function intFromBytes(bytes) {
  return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
}

function deriveBIP85Entropy(index, masterNode) {
  const path = `m/83696968'/${index}'`;
  const child = masterNode.derive(path);
  if (!child.privateKey) {
    throw new Error('Failed to derive private key from child node');
  }
  return sha256(child.privateKey);
}

function deriveDeterministicAgeKey(masterKey, index) {
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false);
  const key = hmac(sha256, masterKey, indexBytes);
  const keyU5 = bech32.toWords(key);
  return bech32.encode('AGE-SECRET-KEY-', keyU5, 1023).toUpperCase();
}

function deriveKeyAndIV(masterNode, keyVersion, appId, filename) {
  const appIdHash = sha256(new TextEncoder().encode(appId));
  const filenameHash = sha256(new TextEncoder().encode(filename));

  const indexes = [
    keyVersion,
    intFromBytes(appIdHash.slice(0, 4)),
    intFromBytes(filenameHash.slice(0, 4)),
  ].map((x) => x & 0x7fffffff);

  const derivationPath = `m/83696968'/128169'/${indexes[0]}'/${indexes[1]}'/${indexes[2]}'`;

  const entropy = deriveBIP85Entropy(indexes[0], masterNode);
  const agePrivateKey = deriveDeterministicAgeKey(entropy, indexes[0]);
  const ivHex = bufferToHex(filenameHash.slice(0, 12));

  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(indexes[0]), false);
  const rawSecret = hmac(sha256, entropy, indexBytes);
  const pubBytes = x25519.getPublicKey(rawSecret);
  const agePublicKey = bech32.encode('age', bech32.toWords(pubBytes), 1023).toLowerCase();

  return {
    derivationPath,
    age_private_key: agePrivateKey,
    age_public_key: agePublicKey,
    raw_entropy: bufferToHex(entropy),
    iv: ivHex,
  };
}

function derive() {
  try {
    const mnemonic = document.getElementById('mnemonic').value.trim();
    const filename = document.getElementById('filename').value.trim();
    const appId = document.getElementById('appId').value.trim();
    const keyVersion = Number(document.getElementById('keyVersion').value);
    const includePrivate = document.getElementById('includePrivate').checked;

    if (!mnemonic || !filename || !appId || Number.isNaN(keyVersion)) {
      throw new Error('Missing required values.');
    }

    const seed = mnemonicToSeedSync(mnemonic);
    const masterNode = HDKey.fromMasterSeed(seed);
    const result = deriveKeyAndIV(masterNode, keyVersion, appId, filename);

    output.textContent = JSON.stringify(
      includePrivate
        ? result
        : { age_public_key: result.age_public_key, iv: result.iv },
      null,
      2,
    );
  } catch (error) {
    output.textContent = `Error: ${error.message}`;
  }
}

deriveButton.addEventListener('click', derive);
derive();
