export interface Env {
  MNEMONIC_SECRET: string;
}

export {
  bufferToHex,
  deriveBIP85Entropy,
  deriveDeterministicAgeKey,
  deriveFromMnemonic,
  deriveIndexes,
  deriveKeyAndIV,
  deriveMasterKey,
  deriveMasterNodeFromMnemonic,
  intFromBytes,
} from "./core.js";
