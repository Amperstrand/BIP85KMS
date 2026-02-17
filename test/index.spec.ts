import { createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { deriveFromMnemonic } from '../src/bip85kms';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;
const TEST_MNEMONIC =
	'bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon';
const TEST_ENV = { MNEMONIC_SECRET: TEST_MNEMONIC };

describe('BIP85KMS worker - Semantic Path API', () => {
	it('rejects non-POST requests', async () => {
		const request = new IncomingRequest('http://example.com');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, TEST_ENV, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(405);
		expect(await response.text()).toBe('Method Not Allowed');
	});

	it('rejects requests with missing semanticPath', async () => {
		const request = new IncomingRequest('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({}),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, TEST_ENV, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(400);
		const body = await response.json<{ error: string }>();
		expect(body.error).toContain('non-empty array');
	});

	it('rejects empty semantic paths', async () => {
		const request = new IncomingRequest('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				semanticPath: [],
			}),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, TEST_ENV, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(400);
		const body = await response.json<{ error: string }>();
		expect(body.error).toContain('non-empty array');
	});

	it('returns public key for valid semantic path request', async () => {
		const response = await SELF.fetch('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				semanticPath: [
					{ "@type": "WebSite", "url": "https://github.com" }
				],
				getPrivateKey: false,
			}),
		});
		expect(response.status).toBe(200);
		const body = await response.json<{
			age_public_key: string;
			derivationPath: string;
			semanticPath: any[];
		}>();
		expect(body.age_public_key).toMatch(/^age1[0-9a-z]+$/);
		expect(body.derivationPath).toMatch(/^m\/83696968'\/67797668'\/\d+'/);
		expect(body.semanticPath).toEqual([
			{ "@type": "WebSite", "url": "https://github.com" }
		]);
	});

	it('returns full material when getPrivateKey is true', async () => {
		const response = await SELF.fetch('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				semanticPath: [
					{ "@type": "Organization", "name": "AcmeCorp" },
					{ "@type": "DigitalDocument", "name": "file.txt" }
				],
				getPrivateKey: true,
			}),
		});
		expect(response.status).toBe(200);
		const body = await response.json<{
			derivationPath: string;
			age_private_key: string;
			age_public_key: string;
			raw_entropy: string;
			semanticPath: any[];
		}>();
		expect(body.derivationPath).toMatch(/^m\/83696968'\/67797668'\/\d+'\/\d+'/);
		expect(body.age_private_key).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]+$/);
		expect(body.age_public_key).toMatch(/^age1[0-9a-z]+$/);
		expect(body.raw_entropy).toMatch(/^[0-9a-f]{64}$/);
		expect(body.semanticPath).toHaveLength(2);
	});

	it('rejects invalid semantic segments', async () => {
		const response = await SELF.fetch('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				semanticPath: [
					{ "url": "https://github.com" } // Missing @type
				],
			}),
		});
		expect(response.status).toBe(400);
		const body = await response.json<{ error: string }>();
		expect(body.error).toContain('Invalid segment');
	});

	it('produces deterministic keys for same semantic path', async () => {
		const payload = {
			semanticPath: [
				{ "@type": "Organization", "name": "TestOrg" },
				{ "@type": "DigitalDocument", "name": "test.txt" }
			],
			getPrivateKey: true,
		};

		const response1 = await SELF.fetch('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
		});
		const body1 = await response1.json<{ age_private_key: string }>();

		const response2 = await SELF.fetch('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
		});
		const body2 = await response2.json<{ age_private_key: string }>();

		expect(body1.age_private_key).toBe(body2.age_private_key);
	});
});

// Keep legacy function tests as they test the underlying deriveFromMnemonic function
describe('Legacy deriveFromMnemonic function', () => {
	it('still works for library usage', () => {
		const result = deriveFromMnemonic(TEST_MNEMONIC, 1, 'docs', 'README.md');
		expect(result.derivationPath).toMatch(/^m\/83696968'\/128169'\/\d+'\/\d+'\/\d+'$/);
		expect(result.age_private_key).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]+$/);
		expect(result.age_public_key).toMatch(/^age1[0-9a-z]+$/);
		expect(result.raw_entropy).toMatch(/^[0-9a-f]{64}$/);
		expect(result.iv).toMatch(/^[0-9a-f]{24}$/);
	});
});
