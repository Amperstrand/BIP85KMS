import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('BIP85KMS worker', () => {
	it('rejects non-POST requests (unit style)', async () => {
		const request = new IncomingRequest('http://example.com');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(405);
		expect(await response.text()).toBe('Method Not Allowed');
	});

	it('rejects non-POST requests (integration style)', async () => {
		const response = await SELF.fetch('https://example.com');
		expect(response.status).toBe(405);
		expect(await response.text()).toBe('Method Not Allowed');
	});
});
