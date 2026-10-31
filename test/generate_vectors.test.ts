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

const PASSPHRASE_MASTER_KEY = deriveMasterKey('example-passphrase-do-not-use!');

describe('Generate New Golden Vectors (for Phase 3c)', () => {
  it('BIP85 Entropy - TEST_MNEMONIC index 1', () => {
    const masterNode = deriveMasterNodeFromMnemonic(TEST_MNEMONIC);
    const entropy = deriveBIP85Entropy(1, masterNode);
    console.log(`\n✓ deriveBIP85Entropy(1, TEST_MNEMONIC):`);
    console.log(`  ${bufferToHex(entropy)}`);
    console.log(`  Length: ${entropy.length} bytes (${entropy.length * 2} hex chars)`);
  });

  it('Deterministic Age Keys - from passphrase', () => {
    console.log(`\n✓ deriveDeterministicAgeKey vectors:`);
    console.log(`  Index 0: ${deriveDeterministicAgeKey(PASSPHRASE_MASTER_KEY, 0)}`);
    console.log(`  Index 2: ${deriveDeterministicAgeKey(PASSPHRASE_MASTER_KEY, 2)}`);
    console.log(`  Index 3: ${deriveDeterministicAgeKey(PASSPHRASE_MASTER_KEY, 3)}`);
    console.log(`  Index 4: ${deriveDeterministicAgeKey(PASSPHRASE_MASTER_KEY, 4)}`);
    // argon2id(64MiB) derived at module scope like deterministic_age.test.ts —
    // inside a test body the ~12s sync block makes workerd's io-context disconnect
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
