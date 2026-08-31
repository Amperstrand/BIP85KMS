/// <reference types="@cloudflare/workers-types" />

import { Env, deriveFromSemanticPath, deriveMasterNodeFromMnemonic, SemanticSegment } from "./bip85kms";
import { isAuthorized } from "./auth";

interface SemanticRequest {
  semanticPath: SemanticSegment[];
  getPrivateKey?: boolean;
}

/** Reject oversized bodies before parsing to avoid unbounded memory use. */
const MAX_BODY_BYTES = 16 * 1024;
/** Reject unreasonably deep/long semantic paths to bound derivation work per request. */
const MAX_SEMANTIC_PATH_LENGTH = 32;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(message: string, status = 400): Response {
  return jsonResponse({ error: message }, status);
}

async function handleDerive(request: Request, env: Env): Promise<Response> {
  const contentLength = request.headers.get("Content-Length");
  if (contentLength && Number(contentLength) > MAX_BODY_BYTES) {
    return errorResponse("Request body too large", 413);
  }

  const rawBody = await request.text();
  if (rawBody.length > MAX_BODY_BYTES) {
    return errorResponse("Request body too large", 413);
  }

  let body: SemanticRequest;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return errorResponse("Request body must be valid JSON");
  }

  const { semanticPath, getPrivateKey } = body;

  if (!semanticPath || !Array.isArray(semanticPath) || semanticPath.length === 0) {
    return errorResponse("semanticPath must be a non-empty array of JSON-LD objects");
  }
  if (semanticPath.length > MAX_SEMANTIC_PATH_LENGTH) {
    return errorResponse(`semanticPath must not exceed ${MAX_SEMANTIC_PATH_LENGTH} segments`);
  }

  try {
    const masterNode = deriveMasterNodeFromMnemonic(env.MNEMONIC_SECRET);
    const result = deriveFromSemanticPath(masterNode, semanticPath);

    if (getPrivateKey) {
      return jsonResponse(result);
    }

    return jsonResponse({
      age_public_key: result.age_public_key,
      derivationPath: result.derivationPath,
      semanticPath: result.semanticPath,
    });
  } catch (err) {
    // Error messages here are derivation-validation errors only (no secret material).
    return errorResponse((err as Error).message);
  }
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "GET" && url.pathname === "/health") {
    return jsonResponse({ status: "ok" });
  }

  if (request.method !== "POST" || (url.pathname !== "/" && url.pathname !== "/derive")) {
    return new Response("Method Not Allowed", { status: 405 });
  }

  if (!isAuthorized(request, env.API_KEY)) {
    return errorResponse("Unauthorized", 401);
  }

  return handleDerive(request, env);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env);
  },
};
