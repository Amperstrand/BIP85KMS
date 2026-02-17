export interface Env {
  MNEMONIC_SECRET: string;
}

// Semantic path types
export interface SemanticSegment {
  "@type": string;
  [key: string]: any;
}

export interface SemanticDerivationResult {
  derivationPath: string;
  age_private_key: string;
  age_public_key: string;
  raw_entropy: string;
  semanticPath: SemanticSegment[];
}

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
} from "./core.js";
