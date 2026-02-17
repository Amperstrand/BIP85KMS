/// <reference types="@cloudflare/workers-types" />

import { Env, deriveFromSemanticPath, deriveMasterNodeFromMnemonic, SemanticSegment } from "./bip85kms";

interface SemanticRequest {
  semanticPath: SemanticSegment[];
  getPrivateKey?: boolean;
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  try {
    const body = await request.json() as SemanticRequest;
    const { semanticPath, getPrivateKey } = body;
    
    if (!semanticPath || !Array.isArray(semanticPath) || semanticPath.length === 0) {
      return new Response(
        JSON.stringify({ error: "semanticPath must be a non-empty array of JSON-LD objects" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }
    
    const masterNode = deriveMasterNodeFromMnemonic(env.MNEMONIC_SECRET);
    const result = deriveFromSemanticPath(masterNode, semanticPath);
    
    if (getPrivateKey) {
      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" }
      });
    }
    
    return new Response(
      JSON.stringify({
        age_public_key: result.age_public_key,
        derivationPath: result.derivationPath,
        semanticPath: result.semanticPath
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env);
  }
};
