export interface Env {
  MNEMONIC_SECRET: string;
  /** Shared-secret API key required in the `Authorization: Bearer <key>` header. */
  API_KEY?: string;
}

export type { SemanticSegment, DerivationResult, SemanticDerivationResult } from "./core";

export {
  bufferToHex,
  deriveBIP85Entropy,
  deriveDeterministicAgeKey,
  deriveFromMnemonic,
  deriveFromSemanticPath,
  deriveIndexes,
  deriveKeyAndIV,
  deriveMasterKey,
  deriveMasterNodeFromMnemonic,
  intFromBytes,
  jcs,
  semanticToIndex,
  validateSemanticSegment,
} from "./core";
