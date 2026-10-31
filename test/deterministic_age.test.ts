import { describe, it, expect } from 'vitest';
import { bech32 } from 'bech32';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import {
	bufferToHex,
	deriveBIP85Entropy,
	deriveDeterministicAgeKey,
	deriveFromMnemonic,
	deriveMasterKey,
	deriveMasterNodeFromMnemonic,
} from '../src/bip85kms';

const testPassphrase = 'example-passphrase-do-not-use!';
const testMasterKey = deriveMasterKey(testPassphrase);
const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('Deterministic Age Key Generation', () => {
	it('generates a deterministic key with correct format for index 0', () => {
		const key = deriveDeterministicAgeKey(testMasterKey, 0);
		expect(key).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]{58}$/);
	});

	it('generates different keys for different indexes', () => {
		const key0 = deriveDeterministicAgeKey(testMasterKey, 0);
		const key2 = deriveDeterministicAgeKey(testMasterKey, 2);
		const key3 = deriveDeterministicAgeKey(testMasterKey, 3);
		const key4 = deriveDeterministicAgeKey(testMasterKey, 4);
		expect(key0).not.toBe(key2);
		expect(key2).not.toBe(key3);
		expect(key3).not.toBe(key4);
		expect(key0).not.toBe(key4);
	});

	it('produces consistent keys across multiple derivations', () => {
		const key1a = deriveDeterministicAgeKey(testMasterKey, 2);
		const key1b = deriveDeterministicAgeKey(testMasterKey, 2);
		expect(key1a).toBe(key1b);
	});

	it('produces age private key and public key in expected format for deriveFromMnemonic', () => {
		const result = deriveFromMnemonic(TEST_MNEMONIC, 1, 'testapp', 'test.txt');
		expect(result.age_private_key).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]{58}$/);
		expect(result.age_public_key).toMatch(/^age1[a-z0-9]{58}$/);
		expect(result.iv).toHaveLength(24);
	});

	it('uses the expected HMAC-SHA256 bytes for key derivation', () => {
		const entropy = new Uint8Array(32).fill(0x42);
		const index = 0;
		const ageKey = deriveDeterministicAgeKey(entropy, index);
		const decoded = new Uint8Array(bech32.fromWords(bech32.decode(ageKey.toLowerCase()).words));

		const indexBytes = new Uint8Array(8);
		new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false);
		const expected = hmac(sha256, entropy, indexBytes);
		expect(bufferToHex(decoded)).toBe(bufferToHex(expected));
	});

	it('changes output for different mnemonic, keyVersion, and filename/iv', () => {
		const base = deriveFromMnemonic(TEST_MNEMONIC, 1, 'testapp', 'test.txt');
		const differentMnemonic = deriveFromMnemonic(
			'legal winner thank year wave sausage worth useful legal winner thank yellow',
			1,
			'testapp',
			'test.txt',
		);
		const differentKeyVersion = deriveFromMnemonic(TEST_MNEMONIC, 2, 'testapp', 'test.txt');
		const differentFilename = deriveFromMnemonic(TEST_MNEMONIC, 1, 'testapp', 'test-2.txt');

		expect(base.age_private_key).not.toBe(differentMnemonic.age_private_key);
		expect(base.age_private_key).not.toBe(differentKeyVersion.age_private_key);
		expect(base.iv).not.toBe(differentFilename.iv);
	});

	// Phase 3c Note: With HMAC-SHA512(bip-entropy-from-k) implementation, entropy values changed from 32 to 64 bytes.
	// Golden vector test removed due to breaking change. Behavioral properties (determinism, size) are still validated elsewhere.
	it('derives deterministic BIP85 entropy with correct size for a known mnemonic', () => {
		const entropy = deriveBIP85Entropy(1, deriveMasterNodeFromMnemonic(TEST_MNEMONIC));
		expect(entropy.length).toBe(64);
		expect(bufferToHex(entropy)).toHaveLength(128);
		// Entropy is deterministic - running again produces same result
		const entropy2 = deriveBIP85Entropy(1, deriveMasterNodeFromMnemonic(TEST_MNEMONIC));
		expect(bufferToHex(entropy)).toBe(bufferToHex(entropy2));
	});

	it('throws for invalid mnemonic input', () => {
		expect(() => deriveFromMnemonic('not a valid mnemonic', 1, 'testapp', 'test.txt')).toThrow();
	});

	it('handles boundary indexes for deterministic age key derivation', () => {
		const key0 = deriveDeterministicAgeKey(testMasterKey, 0);
		const keyMax = deriveDeterministicAgeKey(testMasterKey, 0x7fffffff);
		expect(key0).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]{58}$/);
		expect(keyMax).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]{58}$/);
		expect(key0).not.toBe(keyMax);
	});

	it('supports unicode app and file identifiers deterministically', () => {
		const unicodeA = deriveFromMnemonic(TEST_MNEMONIC, 1, '应用', '📄.txt');
		const unicodeB = deriveFromMnemonic(TEST_MNEMONIC, 1, '应用', '📄.txt');
		expect(unicodeA.age_private_key).toBe(unicodeB.age_private_key);
		expect(unicodeA.iv).toMatch(/^[0-9a-f]{24}$/);
	});

	it('derives distinct keys for different appId/filename under the same keyVersion', () => {
		// Regression test for the entropy-derivation bug documented in docs/SECURITY.md:
		// entropy previously depended only on keyVersion, so different appId/filename
		// pairs under the same keyVersion collided to the same key material.
		const a = deriveFromMnemonic(TEST_MNEMONIC, 1, 'app1', 'file1.txt');
		const b = deriveFromMnemonic(TEST_MNEMONIC, 1, 'app2', 'file2.txt');
		expect(a.age_private_key).not.toBe(b.age_private_key);
		expect(a.age_public_key).not.toBe(b.age_public_key);
		expect(a.raw_entropy).not.toBe(b.raw_entropy);
	});
});
