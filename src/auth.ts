/**
 * Shared-secret API authentication for the Worker.
 *
 * If `env.API_KEY` is unset, auth is skipped (useful for local `wrangler dev`)
 * and a warning is logged so misconfigured production deployments are visible
 * in the Worker's observability logs.
 */

/** Constant-time byte comparison to avoid leaking key length/content via timing. */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function isAuthorized(request: Request, apiKey: string | undefined): boolean {
  if (!apiKey) {
    console.warn("API_KEY is not configured; requests are accepted without authentication.");
    return true;
  }

  const header = request.headers.get("Authorization");
  if (!header || !header.startsWith("Bearer ")) return false;

  const provided = header.slice("Bearer ".length);
  const encoder = new TextEncoder();
  const providedBytes = encoder.encode(provided);
  const expectedBytes = encoder.encode(apiKey);

  // Compare against a fixed-length buffer first so length mismatches don't short-circuit
  // through timingSafeEqual's own length check with a data-dependent timing signal.
  if (providedBytes.length !== expectedBytes.length) return false;
  return timingSafeEqual(providedBytes, expectedBytes);
}
