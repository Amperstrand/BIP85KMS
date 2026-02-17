/// <reference types="@cloudflare/workers-types" />

import { Env, deriveFromMnemonic, deriveFromSemanticPath, deriveMasterNodeFromMnemonic, SemanticSegment } from "./bip85kms";

// Request types
interface LegacyRequest {
  filename: string;
  keyVersion: number;
  appId: string;
  getPrivateKey?: boolean;
}

interface SemanticRequest {
  semanticPath: SemanticSegment[];
  getPrivateKey?: boolean;
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  try {
    const body = await request.json() as any;
    
    // Detect request type: semantic path vs legacy
    if (body.semanticPath && Array.isArray(body.semanticPath)) {
      // Semantic path mode
      const { semanticPath, getPrivateKey } = body as SemanticRequest;
      
      if (!semanticPath || semanticPath.length === 0) {
        return new Response(
          JSON.stringify({ error: "semanticPath must be a non-empty array" }),
          { status: 400 }
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
    } else {
      // Legacy mode
      const { filename, keyVersion, appId, getPrivateKey } = body as LegacyRequest;

      if (!filename || !appId || keyVersion === undefined) {
        return new Response(
          JSON.stringify({ error: "Missing filename, appId, or keyVersion" }),
          { status: 400 }
        );
      }

      const result = deriveFromMnemonic(env.MNEMONIC_SECRET, keyVersion, appId, filename);

      if (getPrivateKey) {
        return new Response(JSON.stringify(result), {
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(
        JSON.stringify({
          age_public_key: result.age_public_key,
          iv: result.iv
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), {
      status: 400
    });
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env);
  }
};
