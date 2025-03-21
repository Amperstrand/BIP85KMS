#!/bin/bash
set -e

###############################################################################
# Age Utility - Single Script for Encryption and Decryption
#
# Overview:
#   - Automatically detects whether you want to encrypt or decrypt based on
#     the file extension (.age ⇒ decrypt).
#   - Fetches keys from a remote server (via HTTP POST + JSON).
#       * For encryption: fetches only the public key.
#       * For decryption: fetches both public & private keys.
#   - Avoids writing the private key to disk by using process substitution.
#   - Provides a single-line success log.
#   - Offers a verbose mode (-v / --verbose) to show debug messages.
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

Encrypt or decrypt a file using age, fetching keys from a remote key server.

OPTIONS:
  -v, --verbose   Enable verbose debug messages (shows server response, etc.)
  -h, --help      Display this help and exit

OPERATIONS:
  1) Encrypt:
       Provide a file WITHOUT ".age" extension. The script will:
         - Fetch only the public key from the server
         - Encrypt <file> to <file>.age
  2) Decrypt:
       Provide a file WITH ".age" extension. The script will:
         - Fetch both the public and private keys from the server
         - Decrypt <file>.age to <file> (removing .age extension)

HOW IT WORKS:
  - We derive whether to encrypt or decrypt by checking if the provided file ends in ".age".
  - The script uses 'age' under the hood to encrypt or decrypt.
  - The private key is never written to disk; it is piped directly via process substitution.

EXAMPLES:
  $0 secret.txt
      => Encrypts "secret.txt" into "secret.txt.age"

  $0 secret.txt.age
      => Decrypts "secret.txt.age" back into "secret.txt"

NOTES:
  - If no .age extension is detected, encryption occurs.
  - If .age extension is detected, decryption occurs.

EOF
}

###############################################################################
# Parse Arguments
###############################################################################
VERBOSE=0

# Check for options
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
# Verbose Debug Printing
###############################################################################
debug() {
  if [ "$VERBOSE" -eq 1 ]; then
    echo "[DEBUG] $*"
  fi
}

###############################################################################
# Determine Encrypt vs. Decrypt
###############################################################################
if [[ "$INPUT_FILE" == *.age ]]; then
  MODE="decrypt"
else
  MODE="encrypt"
fi
debug "Operation mode determined: $MODE"

###############################################################################
# Fetch Keys from Server
###############################################################################
fetch_keys() {
  local need_private="$1"  # "true" or "false"
  local payload

  if [ "$need_private" == "true" ]; then
    payload="{\"filename\":\"$INPUT_FILE\",\"keyVersion\":$KEY_VERSION,\"appId\":\"$APP_ID\",\"getPrivateKey\":true}"
  else
    payload="{\"filename\":\"$INPUT_FILE\",\"keyVersion\":$KEY_VERSION,\"appId\":\"$APP_ID\"}"
  fi

  debug "Fetching keys from server with payload: $payload"
  KEY_JSON=$(curl -s -X POST "$KEY_SERVER" \
    -H "Content-Type: application/json" \
    -d "$payload")

  debug "Server response JSON: $KEY_JSON"

  AGE_PRIVATE_KEY=$(echo "$KEY_JSON" | jq -r '.age_private_key')
  AGE_PUBLIC_KEY=$(echo "$KEY_JSON" | jq -r '.age_public_key')

  if [ -z "$AGE_PUBLIC_KEY" ] || [ "$AGE_PUBLIC_KEY" == "null" ]; then
    echo "❌ Public key not found in the response."
    exit 1
  fi

  # If we need private key, verify it
  if [ "$need_private" == "true" ]; then
    if [ -z "$AGE_PRIVATE_KEY" ] || [ "$AGE_PRIVATE_KEY" == "null" ]; then
      echo "❌ Private key not found in the response."
      exit 1
    fi

    # Verify that the derived public key matches what's returned by the server
    DERIVED_PUB=$(age-keygen -y <(echo "$AGE_PRIVATE_KEY") 2>/dev/null | grep '^age1')
    if [ "$DERIVED_PUB" != "$AGE_PUBLIC_KEY" ]; then
      echo "❌ Public key mismatch between derived key and server key!"
      exit 1
    fi
    debug "Verified: private key => public key matches the server's public key."
  fi
}

###############################################################################
# Encrypt File
###############################################################################
encrypt_file() {
  debug "Encrypting: $INPUT_FILE"

  # We only need the public key
  fetch_keys "false"

  local output_file="${INPUT_FILE}.age"
  debug "Encrypt output file: $output_file"

  # Perform encryption using the public key directly
  age -r "$AGE_PUBLIC_KEY" -o "$output_file" "$INPUT_FILE"

  echo "✅ Encrypted: $INPUT_FILE => $output_file"
}

###############################################################################
# Decrypt File
###############################################################################
decrypt_file() {
  debug "Decrypting: $INPUT_FILE"

  # We need both keys
  fetch_keys "true"

  # Strip .age extension to get the output filename
  local output_file="${INPUT_FILE%.age}"
  debug "Decrypt output file: $output_file"

  # Perform decryption using process substitution for the private key
  age -d -i <(echo "$AGE_PRIVATE_KEY") -o "$output_file" "$INPUT_FILE"

  echo "✅ Decrypted: $INPUT_FILE => $output_file"
}

###############################################################################
# Main Flow
###############################################################################
if [ "$MODE" == "encrypt" ]; then
  encrypt_file
else
  decrypt_file
fi
