import { describe, it, expect } from 'vitest'; // Use Vitest's native imports
import { deriveDeterministicAgeKey, deriveMasterKey } from '../src/index.js'; // Ensure .js extension if using ESM

// Define the passphrase to derive the master key
const testPassphrase = "example-passphrase-do-not-use!";
const testMasterKey = deriveMasterKey(testPassphrase);

describe('Deterministic Age Key Generation', () => {
    // Test the deterministic Age key generation for index 0
    it('should generate the correct key for index 0', () => {
        expect(deriveDeterministicAgeKey(testMasterKey, 0)).toBe(
            "AGE-SECRET-KEY-1VZ3CREDN87LLHYDVS6FK36EZEVWNZGGFFSWZDN7DL0J04WG723MQCZUS9Q"
        );
    });

    // Test the deterministic Age key generation for index 4
    it('should generate the correct key for index 4', () => {
        expect(deriveDeterministicAgeKey(testMasterKey, 4)).toBe(
            "AGE-SECRET-KEY-1FMPVFDE9WD8CSTNS4J3QRNQ5VRTFE8973FVJ2JANT56HEPZTKA4SQZZ84R"
        );
    });

    // Test the deterministic Age key generation for index 2
    it('should generate the correct key for index 2', () => {
        expect(deriveDeterministicAgeKey(testMasterKey, 2)).toBe(
            "AGE-SECRET-KEY-1RSWAHJR48AWPN6HHTVVGXN7X3X0YWWA7TM7H22T7TF35EZPPVHHQ7WYGRZ"
        );
    });

    // Test the deterministic Age key generation for index 3
    it('should generate the correct key for index 3', () => {
        expect(deriveDeterministicAgeKey(testMasterKey, 3)).toBe(
            "AGE-SECRET-KEY-144T9ZKX0HK6CMMGYEN6WPN82Q4K9LVR376NUJF33HKVAQ70TXMHSPV96MY"
        );
    });

    // Optionally, you can add additional tests for other indices or edge cases if necessary
});
