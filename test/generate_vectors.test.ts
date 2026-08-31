import { describe, it } from 'vitest';
import {
  deriveBIP85Entropy,
  deriveDeterministicAgeKey,
  deriveFromMnemonic,
  deriveMasterNodeFromMnemonic,
  deriveMasterKey,
  bufferToHex,
} from '../src/bip85kms';

const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const BACON_MNEMONIC = 'bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon';

describe('Generate New Golden Vectors (for Phase 3c)', () => {
  it('BIP85 Entropy - TEST_MNEMONIC index 1', () => {
    const masterNode = deriveMasterNodeFromMnemonic(TEST_MNEMONIC);
    const entropy = deriveBIP85Entropy(1, masterNode);
    console.log(`\n✓ deriveBIP85Entropy(1, TEST_MNEMONIC):`);
    console.log(`  ${bufferToHex(entropy)}`);
    console.log(`  Length: ${entropy.length} bytes (${entropy.length * 2} hex chars)`);
  });

  it('Deterministic Age Keys - from passphrase', () => {
    const testPassphrase = 'example-passphrase-do-not-use!';
    const testMasterKey = deriveMasterKey(testPassphrase);

    console.log(`\n✓ deriveDeterministicAgeKey vectors:`);
    console.log(`  Index 0: ${deriveDeterministicAgeKey(testMasterKey, 0)}`);
    console.log(`  Index 2: ${deriveDeterministicAgeKey(testMasterKey, 2)}`);
    console.log(`  Index 3: ${deriveDeterministicAgeKey(testMasterKey, 3)}`);
    console.log(`  Index 4: ${deriveDeterministicAgeKey(testMasterKey, 4)}`);
  });

  it('deriveFromMnemonic - BACON_MNEMONIC', () => {
    const result = deriveFromMnemonic(BACON_MNEMONIC, 1, 'docs', 'README.md');
    console.log(`\n✓ deriveFromMnemonic(BACON_MNEMONIC, 1, 'docs', 'README.md'):`);
    console.log(`  derivationPath: ${result.derivationPath}`);
    console.log(`  age_private_key: ${result.age_private_key}`);
    console.log(`  age_public_key: ${result.age_public_key}`);
    console.log(`  raw_entropy: ${result.raw_entropy} (${result.raw_entropy.length / 2} bytes)`);
    console.log(`  iv: ${result.iv}`);
  });
});
