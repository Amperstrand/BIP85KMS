#!/bin/bash
# run_bipsea.sh
#
# This script computes a custom BIP‑85 derivation path and derives the final xprv
# using bipsea CLI. The custom path is:
#
#   m/<BIP_CONST>'/<APP_CODE>'/<X>'/<Y>'/<Z>'
#
# Where:
#   - BIP_CONST is fixed for "bip-" (83696968).
#   - APP_CODE is fixed at 128169.
#   - X, Y, and Z are three hardened indexes computed from the SHA‑256 hash
#     of the identifier. We extract the top 93 bits (256-93 = 163 bits shift)
#     and split them into three 31-bit chunks.
#
# Then, to get the raw entropy (32 bytes) from the final derived node,
# we call bipsea with the hex application (using -a hex) to derive a 32-byte secret.
#
# Hardened indexes must be in the range 0 <= n <= 2^31 - 1.
#
# Requirements: bipsea, sha256sum, bc, python3.
#
# Usage:
#   ./run_bipsea.sh <identifier>
#
# Example:
#   ./run_bipsea.sh "docs:helloworld.txt"
#
# (Assumes MNEMONIC_SECRET is already exported.)

if [ $# -ne 1 ]; then
    echo "Usage: $0 <identifier>"
    exit 1
fi

IDENTIFIER=$1

# Fixed constants.
BIP_CONST=83696968
APP_CODE=128169

echo "Identifier: $IDENTIFIER"
echo "BIP constant (fixed for 'bip-'): $BIP_CONST"
echo "Application Code: $APP_CODE"

# Compute SHA-256 hash (hex) of the identifier.
HASH_HEX=$(echo -n "$IDENTIFIER" | sha256sum | awk '{print $1}')
echo "SHA256($IDENTIFIER): $HASH_HEX"

# Convert the hexadecimal hash to a decimal number using bc.
DEC=$(echo "ibase=16; $(echo $HASH_HEX | tr 'a-f' 'A-F')" | bc)

# Extract the top 93 bits from the 256-bit digest.
# (256 - 93 = 163 bits shift)
TOP93=$(echo "$DEC / (2^163)" | bc)
echo "Top93 bits (as integer): $TOP93"

# Split TOP93 into three 31-bit chunks:
# X: top 31 bits (shift right by 62 bits).
X=$(echo "$TOP93 / (2^62)" | bc)
# Y: next 31 bits: shift right by 31 bits then modulo 2^31.
Y=$(echo "($TOP93 / (2^31)) % (2^31)" | bc)
# Z: lowest 31 bits: TOP93 modulo 2^31.
Z=$(echo "$TOP93 % (2^31)" | bc)

echo "Identifier chunks:"
echo "X: $X"
echo "Y: $Y"
echo "Z: $Z"

# Build the custom derivation path:
#   m/<BIP_CONST>'/<APP_CODE>'/<X>'/<Y>'/<Z>'
DERIV_PATH="m/${BIP_CONST}'/${APP_CODE}'/${X}'/${Y}'/${Z}'"
echo "Custom derivation path will be:"
echo "$DERIV_PATH"

# Derive the master xprv from the mnemonic.
MASTER_XPRV=$(bipsea validate -m "$MNEMONIC_SECRET" | bipsea xprv)
echo "Master xprv: $MASTER_XPRV"

# Derive along the custom path by chaining bipsea commands.
XPRV_LEVEL1=$(bipsea derive -a xprv -i "$BIP_CONST" -x "$MASTER_XPRV")
echo "After bip constant level (m/${BIP_CONST}'): $XPRV_LEVEL1"

XPRV_LEVEL2=$(bipsea derive -a xprv -i "$APP_CODE" -x "$XPRV_LEVEL1")
echo "After application code level (m/${BIP_CONST}'/${APP_CODE}'): $XPRV_LEVEL2"

XPRV_LEVEL3=$(bipsea derive -a xprv -i "$X" -x "$XPRV_LEVEL2")
echo "After identifier chunk X (m/.../${X}'): $XPRV_LEVEL3"

XPRV_LEVEL4=$(bipsea derive -a xprv -i "$Y" -x "$XPRV_LEVEL3")
echo "After identifier chunk Y (m/.../${Y}'): $XPRV_LEVEL4"

FINAL_XPRV=$(bipsea derive -a xprv -i "$Z" -x "$XPRV_LEVEL4")
echo "Final derived xprv (m/${BIP_CONST}'/${APP_CODE}'/${X}'/${Y}'/${Z}'):"
echo "$FINAL_XPRV"

# Derive raw entropy from the final node.
# We use bipsea derive with the hex application to get 32 bytes of hex.
RAW_ENTROPY=$(bipsea derive -a hex -n 32 -i 1 -x "$FINAL_XPRV")
echo "Raw hex entropy (via bipsea hex): $RAW_ENTROPY"

# Output final JSON result (to stdout).
python3 - <<EOF
import json
result = {
  "derivationPath": "$DERIV_PATH",
  "xprv": "$FINAL_XPRV",
  "raw_entropy": "$RAW_ENTROPY"
}
print(json.dumps(result, indent=2))
EOF
