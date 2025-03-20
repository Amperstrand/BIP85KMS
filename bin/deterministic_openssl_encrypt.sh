#!/bin/bash
set -e

###############################################################################
# OpenSSL Deterministic Encryption Utility
#
# Overview:
#   - Encryption:
#       * Computes the SHA-256 hash of the input file.
#       * Uses the first 32 hex digits (16 bytes) of that hash as the IV.
#       * Stores the full hash as part of the encrypted filename:
#             original_filename.<sha256sum>.enc
#       * Fetches the symmetric key from a remote key server using the original
#         filename as the identifier.
#       * Uses OpenSSL's AES-256-CBC with -nosalt for deterministic encryption.
#
#   - Decryption:
#       * Expects the input filename to be in the format:
#             original_filename.<sha256sum>.enc
#       * Extracts the SHA-256 hash from the filename and uses its first 32 hex
#         digits as the IV.
#       * Fetches the symmetric key from the key server using the base filename.
#       * Decrypts the file to recover the original plaintext (output filename is
#         the original filename).
#       * Computes the SHA-256 hash of the decrypted file and compares it to the
#         embedded hash. The result is logged as part of the final output.
#
# Requirements:
#   - OpenSSL, curl, jq, and sha256sum must be installed.
#
# Usage:
#   Encryption:
#     ./openssl_deterministic.sh plaintext.txt
#       => Produces plaintext.txt.<sha256sum>.enc
#
#   Decryption:
#     ./openssl_deterministic.sh plaintext.txt.<sha256sum>.enc
#       => Produces plaintext.txt, and verifies the file hash.
###############################################################################

###############################################################################
# Configuration
###############################################################################
KEY_VERSION=1
APP_ID="docs"
KEY_SERVER="https://keys.dns4sats.xyz"

###############################################################################
# Help & Usage
###############################################################################
usage() {
  cat <<EOF
Usage: $0 [OPTIONS] <file>

Encrypt or decrypt a file using OpenSSL with deterministic IVs.

OPTIONS:
  -v, --verbose   Enable verbose debug messages.
  -h, --help      Display this help and exit.

OPERATIONS:
  1) Encrypt:
       Provide a file WITHOUT the ".enc" extension.
       The script will:
         - Compute the SHA-256 hash of the file.
         - Use the first 32 hex digits of the hash as the IV.
         - Fetch the symmetric key from the remote server.
         - Encrypt the file using AES-256-CBC with -nosalt.
         - Save the output as: <file>.<sha256sum>.enc

  2) Decrypt:
       Provide a file with the format: <file>.<sha256sum>.enc
       The script will:
         - Extract the SHA-256 hash from the filename.
         - Use the first 32 hex digits as the IV.
         - Fetch the symmetric key from the remote server (using the base filename).
         - Decrypt the file, outputting the original <file>.
         - Compute and verify the SHA-256 hash of the decrypted file.
EOF
}

###############################################################################
# Parse Arguments
###############################################################################
VERBOSE=0

while [[ "$1" == -* ]]; do
  case "$1" in
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [ -z "$1" ]; then
  echo "❌ Missing file argument."
  usage
  exit 1
fi

INPUT_FILE="$1"
if [ ! -f "$INPUT_FILE" ]; then
  echo "❌ File '$INPUT_FILE' does not exist."
  exit 1
fi

###############################################################################
# Debug function
###############################################################################
debug() {
  if [ "$VERBOSE" -eq 1 ]; then
    echo "[DEBUG] $*"
  fi
}

###############################################################################
# Determine Mode and Base Filename
###############################################################################
# Encryption mode: input file does NOT end with ".enc"
# Decryption mode: input file must match pattern *.{64}.enc
if [[ "$INPUT_FILE" =~ \.[0-9a-fA-F]{64}\.enc$ ]]; then
  MODE="decrypt"
  # Remove trailing ".enc"
  FILENAME_NOEXT="${INPUT_FILE%.enc}"
  # Extract SHA256 (portion after the last dot)
  SHA256_HASH="${FILENAME_NOEXT##*.}"
  # Base filename is everything before the last dot
  BASE_FILE="${FILENAME_NOEXT%.*}"
else
  MODE="encrypt"
  BASE_FILE="$INPUT_FILE"
fi
debug "Operation mode determined: $MODE"
debug "Base filename for key retrieval: $BASE_FILE"

###############################################################################
# Temporary file for key storage in /dev/shm
###############################################################################
KEY_FILE=$(mktemp /dev/shm/openssl_key.XXXXXX)
chmod 600 "$KEY_FILE"
debug "Temporary key file: $KEY_FILE"

# Cleanup on exit
cleanup() {
  debug "Cleaning up temporary key file."
  rm -f "$KEY_FILE"
}
trap cleanup EXIT

###############################################################################
# Fetch Key from Remote Server
###############################################################################
fetch_key() {
  local payload="{\"filename\":\"$BASE_FILE\",\"keyVersion\":$KEY_VERSION,\"appId\":\"$APP_ID\",\"getPrivateKey\":true}"
  debug "Fetching key from server with payload: $payload"
  KEY_JSON=$(curl -s -X POST "$KEY_SERVER" \
    -H "Content-Type: application/json" \
    -d "$payload")
  debug "Server response JSON: $KEY_JSON"

  RAW_ENTROPY=$(echo "$KEY_JSON" | jq -r '.raw_entropy')
  if [ -z "$RAW_ENTROPY" ] || [ "$RAW_ENTROPY" == "null" ]; then
    echo "❌ raw_entropy not found in the server response."
    exit 1
  fi

  # Write the symmetric key to temporary file.
  echo "$RAW_ENTROPY" > "$KEY_FILE"
}

###############################################################################
# Encryption Function
###############################################################################
encrypt_file() {
  debug "Encrypting file: $INPUT_FILE"

  # Compute SHA256 hash of the input file (full 64 hex characters)
  SHA256_FULL=$(sha256sum "$INPUT_FILE" | awk '{print $1}')
  debug "Computed SHA256: $SHA256_FULL"
  # Use the first 32 hex digits (16 bytes) as the IV
  IV_HEX="${SHA256_FULL:0:32}"
  debug "Derived IV (first 32 hex digits): $IV_HEX"

  # Construct output filename: basefilename.<sha256>.enc
  OUTPUT_FILE="${INPUT_FILE}.${SHA256_FULL}.enc"
  debug "Output file will be: $OUTPUT_FILE"

  # Fetch symmetric key from server using the base filename
  fetch_key
  KEY_HEX=$(cat "$KEY_FILE")
  debug "Using key: $KEY_HEX"

  # Encrypt using OpenSSL AES-256-CBC, no salt for determinism.
  openssl enc -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" -nosalt -in "$INPUT_FILE" -out "$OUTPUT_FILE"
  echo "✅ Encrypted: $INPUT_FILE => $OUTPUT_FILE"
}

###############################################################################
# Decryption Function
###############################################################################
decrypt_file() {
  debug "Decrypting file: $INPUT_FILE"
  # SHA256_HASH and BASE_FILE were parsed above.

  # Derive IV from the SHA256_HASH (first 32 hex digits)
  IV_HEX="${SHA256_HASH:0:32}"
  debug "Using IV (derived from filename): $IV_HEX"

  # Fetch symmetric key from server using the base filename
  fetch_key
  KEY_HEX=$(cat "$KEY_FILE")
  debug "Using key: $KEY_HEX"

  # Output file will be the base filename (original file)
  OUTPUT_FILE="$BASE_FILE"
  debug "Decrypted output file will be: $OUTPUT_FILE"

  openssl enc -d -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" -nosalt -in "$INPUT_FILE" -out "$OUTPUT_FILE"

  # After decryption, compute the SHA256 hash of the output file
  CALC_HASH=$(sha256sum "$OUTPUT_FILE" | awk '{print $1}')
  if [ "$CALC_HASH" == "$SHA256_HASH" ]; then
    echo "✅ Decrypted: $INPUT_FILE => $OUTPUT_FILE (SHA256 match: $SHA256_HASH)"
  else
    echo "❌ Decrypted: $INPUT_FILE => $OUTPUT_FILE (SHA256 mismatch: expected $SHA256_HASH, got $CALC_HASH)"
  fi
}

###############################################################################
# Main Flow
###############################################################################
if [ "$MODE" == "encrypt" ]; then
  encrypt_file
else
  decrypt_file
fi
