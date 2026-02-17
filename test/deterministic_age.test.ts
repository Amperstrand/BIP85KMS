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
	it('generates a deterministic key for index 0', () => {
		expect(deriveDeterministicAgeKey(testMasterKey, 0)).toBe(
			'AGE-SECRET-KEY-1VZ3CREDN87LLHYDVS6FK36EZEVWNZGGFFSWZDN7DL0J04WG723MQCZUS9Q',
		);
	});

	it('generates a deterministic key for index 2', () => {
		expect(deriveDeterministicAgeKey(testMasterKey, 2)).toBe(
			'AGE-SECRET-KEY-1RSWAHJR48AWPN6HHTVVGXN7X3X0YWWA7TM7H22T7TF35EZPPVHHQ7WYGRZ',
		);
	});

	it('generates a deterministic key for index 3', () => {
		expect(deriveDeterministicAgeKey(testMasterKey, 3)).toBe(
			'AGE-SECRET-KEY-144T9ZKX0HK6CMMGYEN6WPN82Q4K9LVR376NUJF33HKVAQ70TXMHSPV96MY',
		);
	});

	it('generates a deterministic key for index 4', () => {
		expect(deriveDeterministicAgeKey(testMasterKey, 4)).toBe(
			'AGE-SECRET-KEY-1FMPVFDE9WD8CSTNS4J3QRNQ5VRTFE8973FVJ2JANT56HEPZTKA4SQZZ84R',
		);
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

	it('derives deterministic BIP85 entropy for a known mnemonic/index', () => {
		const entropy = deriveBIP85Entropy(1, deriveMasterNodeFromMnemonic(TEST_MNEMONIC));
		expect(bufferToHex(entropy)).toBe('423c2ee380f4f3e36abf538d90a34c6d993a80786de3293f62f0cd4bd7d1e769');
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
});
