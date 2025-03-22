/// <reference types="@cloudflare/workers-types" />

import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { Env, deriveKeyAndIV } from "./bip85kms";

async function handleRequest(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  try {
    const { filename, keyVersion, appId, getPrivateKey } = await request.json() as {
      filename: string;
      keyVersion: number;
      appId: string;
      getPrivateKey?: boolean;
    };

    if (!filename || !appId || keyVersion === undefined) {
      return new Response(
        JSON.stringify({ error: "Missing filename, appId, or keyVersion" }),
        { status: 400 }
      );
    }

    const mnemonic = env.MNEMONIC_SECRET;
    const seed = mnemonicToSeedSync(mnemonic);
    const masterNode = HDKey.fromMasterSeed(seed);

    const result = await deriveKeyAndIV(masterNode, keyVersion, appId, filename);

    if (getPrivateKey) {
      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" }
      });
    } else {
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
