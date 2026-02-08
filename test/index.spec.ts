import { createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;
const TEST_MNEMONIC = 'bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon';

describe('BIP85KMS worker API', () => {
  it('rejects non-POST requests', async () => {
    const request = new IncomingRequest('http://example.com');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, { MNEMONIC_SECRET: TEST_MNEMONIC }, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(405);
    expect(await response.text()).toBe('Method Not Allowed');
  });

  it('returns 400 when required fields are missing', async () => {
    const request = new IncomingRequest('http://example.com', {
      method: 'POST',
      body: JSON.stringify({ appId: 'docs' }),
      headers: { 'Content-Type': 'application/json' },
    });

    const ctx = createExecutionContext();
    const response = await worker.fetch(request, { MNEMONIC_SECRET: TEST_MNEMONIC }, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: 'Missing filename, appId, or keyVersion',
    });
  });

  it('returns public key + iv for valid requests', async () => {
    const request = new IncomingRequest('http://example.com', {
      method: 'POST',
      body: JSON.stringify({ filename: 'README.md', keyVersion: 1, appId: 'docs' }),
      headers: { 'Content-Type': 'application/json' },
    });

    const ctx = createExecutionContext();
    const response = await worker.fetch(request, { MNEMONIC_SECRET: TEST_MNEMONIC }, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      age_public_key: expect.stringMatching(/^age1[ac-hj-np-z02-9]+$/),
      iv: expect.stringMatching(/^[0-9a-f]{24}$/),
    });
  });

  it('integration: returns private material when explicitly requested', async () => {
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
    await expect(response.json()).resolves.toMatchObject({
      derivationPath: expect.stringMatching(/^m\//),
      age_private_key: expect.stringMatching(/^AGE-SECRET-KEY-1[AC-HJ-NP-Z02-9]+$/),
      age_public_key: expect.stringMatching(/^age1[ac-hj-np-z02-9]+$/),
      raw_entropy: expect.stringMatching(/^[0-9a-f]{64}$/),
      iv: expect.stringMatching(/^[0-9a-f]{24}$/),
    });
  });
});
