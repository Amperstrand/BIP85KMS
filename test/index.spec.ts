import { createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { deriveFromMnemonic } from '../src/bip85kms';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;
const TEST_MNEMONIC =
	'bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon';
const TEST_ENV = { MNEMONIC_SECRET: TEST_MNEMONIC };

describe('BIP85KMS worker', () => {
	it('rejects non-POST requests (unit style)', async () => {
		const request = new IncomingRequest('http://example.com');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, TEST_ENV, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(405);
		expect(await response.text()).toBe('Method Not Allowed');
	});

	it('rejects non-POST requests (integration style)', async () => {
		const response = await SELF.fetch('https://example.com');
		expect(response.status).toBe(405);
		expect(await response.text()).toBe('Method Not Allowed');
	});

	it('returns 400 when required fields are missing', async () => {
		const missingFieldPayloads = [
			{ keyVersion: 1, appId: 'docs' },
			{ filename: 'README.md', appId: 'docs' },
			{ filename: 'README.md', keyVersion: 1 },
		];
		for (const payload of missingFieldPayloads) {
			const request = new IncomingRequest('https://example.com', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(payload),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, TEST_ENV, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			await expect(response.json()).resolves.toEqual({
				error: 'Missing filename, appId, or keyVersion',
			});
		}
	});

	it('returns public key + iv for valid requests', async () => {
		const payload = { filename: 'README.md', keyVersion: 1, appId: 'docs' };
		const expected = deriveFromMnemonic(
			TEST_MNEMONIC,
			payload.keyVersion,
			payload.appId,
			payload.filename,
		);
		const request = new IncomingRequest('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, TEST_ENV, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		const body = await response.json<{
			age_public_key: string;
			iv: string;
			age_private_key?: string;
		}>();
		expect(body.age_public_key).toMatch(/^age1[0-9a-z]+$/);
		expect(body.iv).toMatch(/^[0-9a-f]{24}$/);
		expect(body.age_public_key).toBe(expected.age_public_key);
		expect(body.iv).toBe(expected.iv);
		expect(body.age_private_key).toBeUndefined();
	});

	it('returns private material in integration response when requested', async () => {
		const response = await SELF.fetch('https://example.com', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				filename: 'README.md',
				keyVersion: 1,
				appId: 'docs',
				getPrivateKey: true,
			}),
		});
		expect(response.status).toBe(200);
		const body = await response.json<{
			derivationPath: string;
			age_private_key: string;
			age_public_key: string;
			raw_entropy: string;
			iv: string;
		}>();
		expect(body.derivationPath).toMatch(/^m\/83696968'\/128169'\/\d+'\/\d+'\/\d+'$/);
		expect(body.age_private_key).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]+$/);
		expect(body.age_public_key).toMatch(/^age1[0-9a-z]+$/);
		expect(body.raw_entropy).toMatch(/^[0-9a-f]{64}$/);
		expect(body.iv).toMatch(/^[0-9a-f]{24}$/);
	});
});
