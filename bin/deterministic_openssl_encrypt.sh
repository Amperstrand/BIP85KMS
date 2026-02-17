#!/bin/bash
set -e

###############################################################################
# OpenSSL Deterministic Encryption Utility
#
# Overview:
#   - Encryption:
#       * Fetches the symmetric key and IV from a remote key server using the
#         original filename as the identifier.
#       * The IV is derived deterministically from SHA-256(filename) on the server.
#       * Computes the SHA-256 hash of the input file for integrity verification.
#       * Stores the content hash as part of the encrypted filename:
#             original_filename.<sha256sum>.enc
#       * Uses OpenSSL's AES-256-CBC with -nosalt for deterministic encryption.
#
#   - Decryption:
#       * Expects the input filename to be in the format:
#             original_filename.<sha256sum>.enc
#       * Fetches the symmetric key and IV from the key server using the base filename.
#       * The IV is derived deterministically from SHA-256(filename) on the server.
#       * Decrypts the file to recover the original plaintext (output filename is
#         the original filename).
#       * Computes the SHA-256 hash of the decrypted file and compares it to the
#         embedded hash for integrity verification.
#
# IV Derivation:
#   The IV is derived from the filename (not file content) by the key server:
#       iv = sha256(filename)[:12]  # 96 bits (24 hex characters)
#   
#   This ensures consistency with BIP85KMS's core design principle: all 
#   cryptographic material is derivable from the filename alone.
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
         - Fetch the symmetric key and IV from the remote server (using the filename).
         - The IV is derived from SHA-256(filename) on the server.
         - Compute the SHA-256 hash of the file for integrity.
         - Encrypt the file using AES-256-CBC with -nosalt.
         - Save the output as: <file>.<sha256sum>.enc

  2) Decrypt:
       Provide a file with the format: <file>.<sha256sum>.enc
       The script will:
         - Extract the content SHA-256 hash from the filename.
         - Fetch the symmetric key and IV from the remote server (using the base filename).
         - The IV is derived from SHA-256(filename) on the server.
         - Decrypt the file, outputting the original <file>.
         - Compute and verify the SHA-256 hash of the decrypted file.

NOTE:
  The IV is derived from the filename (not file content) to maintain consistency
  with BIP85KMS's core design principle: all cryptographic material is derivable
  from the filename alone, without needing the file content.
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
# Fetch Key and IV from Remote Server
###############################################################################
fetch_key_and_iv() {
  local payload="{\"filename\":\"$BASE_FILE\",\"keyVersion\":$KEY_VERSION,\"appId\":\"$APP_ID\",\"getPrivateKey\":true}"
  debug "Fetching key and IV from server with payload: $payload"
  KEY_JSON=$(curl -s -X POST "$KEY_SERVER" \
    -H "Content-Type: application/json" \
    -d "$payload")
  debug "Server response JSON: $KEY_JSON"

  RAW_ENTROPY=$(echo "$KEY_JSON" | jq -r '.raw_entropy')
  if [ -z "$RAW_ENTROPY" ] || [ "$RAW_ENTROPY" == "null" ]; then
    echo "❌ raw_entropy not found in the server response."
    exit 1
  fi

  IV_FROM_API=$(echo "$KEY_JSON" | jq -r '.iv')
  if [ -z "$IV_FROM_API" ] || [ "$IV_FROM_API" == "null" ]; then
    echo "❌ iv not found in the server response."
    exit 1
  fi

  # Write the symmetric key to temporary file.
  echo "$RAW_ENTROPY" > "$KEY_FILE"
  
  debug "Fetched IV from API: $IV_FROM_API"
}

###############################################################################
# Encryption Function
###############################################################################
encrypt_file() {
  debug "Encrypting file: $INPUT_FILE"

  # Fetch symmetric key and IV from server using the base filename
  fetch_key_and_iv
  KEY_HEX=$(cat "$KEY_FILE")
  debug "Using key: $KEY_HEX"
  
  # Convert IV from 24 hex chars (96 bits) to 32 hex chars (128 bits) for OpenSSL
  # OpenSSL AES-256-CBC expects 128-bit (16 byte) IV
  # The API returns 96-bit IV, so we pad with zeros
  IV_HEX="${IV_FROM_API}0000000000000000"
  IV_HEX="${IV_HEX:0:32}"
  debug "Using IV (padded to 128 bits): $IV_HEX"

  # Compute SHA256 hash of the input file for integrity verification
  SHA256_FULL=$(sha256sum "$INPUT_FILE" | awk '{print $1}')
  debug "Computed content SHA256: $SHA256_FULL"

  # Construct output filename: basefilename.<sha256>.enc
  OUTPUT_FILE="${INPUT_FILE}.${SHA256_FULL}.enc"
  debug "Output file will be: $OUTPUT_FILE"

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

  # Fetch symmetric key and IV from server using the base filename
  fetch_key_and_iv
  KEY_HEX=$(cat "$KEY_FILE")
  debug "Using key: $KEY_HEX"

  # Convert IV from 24 hex chars (96 bits) to 32 hex chars (128 bits) for OpenSSL
  # OpenSSL AES-256-CBC expects 128-bit (16 byte) IV
  # The API returns 96-bit IV, so we pad with zeros
  IV_HEX="${IV_FROM_API}0000000000000000"
  IV_HEX="${IV_HEX:0:32}"
  debug "Using IV (padded to 128 bits): $IV_HEX"

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
