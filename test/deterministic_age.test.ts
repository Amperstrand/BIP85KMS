import { describe, it, expect } from 'vitest';
import { deriveDeterministicAgeKey } from '../src/bip85kms';

const testMasterKey = new TextEncoder().encode('deterministic-test-master-key-material-32bytes!');

describe('Deterministic Age Key Generation', () => {
  it('is deterministic for the same master key + index', () => {
    const k1 = deriveDeterministicAgeKey(testMasterKey, 0);
    const k2 = deriveDeterministicAgeKey(testMasterKey, 0);

    expect(k1).toBe(k2);
    expect(k1).toMatch(/^AGE-SECRET-KEY-1[AC-HJ-NP-Z02-9]+$/);
  });

  it('produces different keys for different indexes', () => {
    const k1 = deriveDeterministicAgeKey(testMasterKey, 1);
    const k2 = deriveDeterministicAgeKey(testMasterKey, 2);

    expect(k1).not.toBe(k2);
  });
});
