import { deriveBIP85Entropy, deriveDeterministicAgeKey, deriveFromMnemonic, deriveMasterNodeFromMnemonic, deriveMasterKey, bufferToHex } from './src/bip85kms.ts';

const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const BACON_MNEMONIC = 'bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon';

console.log('=== BIP85 Entropy Vectors ===');
const masterNode = deriveMasterNodeFromMnemonic(TEST_MNEMONIC);
const entropy1 = deriveBIP85Entropy(1, masterNode);
console.log(`deriveBIP85Entropy(1, TEST_MNEMONIC):`);
console.log(`  Value: ${bufferToHex(entropy1)}`);
console.log(`  Length: ${entropy1.length * 2} hex chars (${entropy1.length} bytes)\n`);

console.log('=== Deterministic Age Key Vectors (from passphrase) ===');
const testPassphrase = 'example-passphrase-do-not-use!';
const testMasterKey = deriveMasterKey(testPassphrase);

console.log(`deriveDeterministicAgeKey(testMasterKey, 0):`);
console.log(`  ${deriveDeterministicAgeKey(testMasterKey, 0)}\n`);

console.log(`deriveDeterministicAgeKey(testMasterKey, 2):`);
console.log(`  ${deriveDeterministicAgeKey(testMasterKey, 2)}\n`);

console.log(`deriveDeterministicAgeKey(testMasterKey, 3):`);
console.log(`  ${deriveDeterministicAgeKey(testMasterKey, 3)}\n`);

console.log(`deriveDeterministicAgeKey(testMasterKey, 4):`);
console.log(`  ${deriveDeterministicAgeKey(testMasterKey, 4)}\n`);

console.log('=== deriveFromMnemonic Vectors ===');
const result = deriveFromMnemonic(BACON_MNEMONIC, 1, 'docs', 'README.md');
console.log(`deriveFromMnemonic(BACON_MNEMONIC, 1, 'docs', 'README.md'):`);
console.log(`  age_private_key: ${result.age_private_key}`);
console.log(`  age_public_key: ${result.age_public_key}`);
console.log(`  raw_entropy: ${result.raw_entropy} (${result.raw_entropy.length / 2} bytes)`);
console.log(`  iv: ${result.iv}`);
console.log(`  derivationPath: ${result.derivationPath}`);
