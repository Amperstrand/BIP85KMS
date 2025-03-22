#!/usr/bin/env python3
"""
CLI Tool for BIP85KMS in Python

Usage Example:
  export MNEMONIC_SECRET="bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon"
  python3 cli.py --filename "example.txt" --keyVersion 1 --appId "myApp" --getPrivateKey

This tool derives Age keys locally using a BIP85-like derivation.
It expects the following command-line flags:
  --filename      (required): The filename string.
  --keyVersion    (required): The key version (number).
  --appId         (required): The app ID string.
  --getPrivateKey (optional): If present, includes the private key in the output.

The environment variable MNEMONIC_SECRET must be set.
"""

import sys
import os
import json
import hashlib
import hmac

# Import the seed function and BIP32 functions from bipsea.
# Instead of Bip32, we use to_master_key() and derive_key() functions.
from bipsea.bip39 import to_master_seed
from bipsea.bip32 import to_master_key, derive_key

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# --- Minimal Bech32 implementation (based on BIP-0173) ---
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3][i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b < 0 or (b >> frombits):
            return None
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

# --- Helper Functions ---
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def derive_bip85_entropy(index: int, master_node) -> bytes:
    """
    Derive 32-byte entropy by hashing a derived child private key.
    Uses the derivation path: m/83696968'/index'
    """
    path = f"m/83696968'/{index}'"
    # Split path into segments (ignoring the first "m")
    segments = path.split('/')[1:]
    child = derive_key(master_node, segments, private=True)
    # For private keys, bipsea stores key bytes in the 'data' attribute.
    priv = child.data
    if not priv:
        raise Exception("Failed to derive child private key")
    return hashlib.sha256(priv).digest()

def derive_deterministic_age_key(master_key: bytes, index: int) -> str:
    """
    Generate a deterministic Age key.
    Computes HMAC-SHA256(master_key, index_bytes) and then Bech32-encodes it with HRP "AGE-SECRET-KEY-".
    """
    index_bytes = index.to_bytes(8, byteorder='big')
    hmac_digest = hmac.new(master_key, index_bytes, hashlib.sha256).digest()
    words = convertbits(list(hmac_digest), 8, 5)
    encoded = bech32_encode("AGE-SECRET-KEY-", words)
    return encoded.upper()

def derive_key_and_iv(master_node, key_version: int, app_id: str, filename: str):
    """
    Derive an Age-compatible key and IV.
    Also derives an X25519 public key from a raw secret.
    """
    # Hash the app_id and filename
    app_id_hash = hashlib.sha256(app_id.encode()).digest()
    filename_hash = hashlib.sha256(filename.encode()).digest()

    # Create indexes:
    idx0 = key_version & 0x7fffffff
    idx1 = bytes_to_int(app_id_hash[:4]) & 0x7fffffff
    idx2 = bytes_to_int(filename_hash[:4]) & 0x7fffffff

    derivation_path = f"m/83696968'/128169'/{idx0}'/{idx1}'/{idx2}'"

    # Derive entropy using the first index
    entropy = derive_bip85_entropy(idx0, master_node)
    age_private_key = derive_deterministic_age_key(entropy, idx0)
    iv_hex = filename_hash[:12].hex()

    # Compute raw secret for X25519 public key derivation
    index_bytes = idx0.to_bytes(8, byteorder='big')
    raw_secret = hmac.new(entropy, index_bytes, hashlib.sha256).digest()

    # Derive X25519 public key using cryptography
    private_key = x25519.X25519PrivateKey.from_private_bytes(raw_secret)
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    words_pub = convertbits(list(public_key_bytes), 8, 5)
    age_public_key = bech32_encode("age", words_pub).lower()

    return {
        "derivationPath": derivation_path,
        "age_private_key": age_private_key,
        "age_public_key": age_public_key,
        "raw_entropy": entropy.hex(),
        "iv": iv_hex
    }

def parse_args(argv):
    """
    Simple command-line argument parser.
    Expects flags of the form --flag value or boolean flags (without a value).
    """
    result = {}
    i = 0
    while i < len(argv):
        if argv[i].startswith("--"):
            key = argv[i][2:]
            if i + 1 < len(argv) and not argv[i+1].startswith("--"):
                result[key] = argv[i+1]
                i += 2
            else:
                result[key] = True
                i += 1
        else:
            i += 1
    return result

def main():
    args = parse_args(sys.argv[1:])
    filename = args.get("filename")
    key_version = args.get("keyVersion")
    app_id = args.get("appId")
    get_private_key = args.get("getPrivateKey") in [True, "true", "True"]

    if not filename or not key_version or not app_id:
        print("Error: Missing required argument(s).")
        print("Usage: python3 cli.py --filename <filename> --keyVersion <number> --appId <appId> [--getPrivateKey]")
        sys.exit(1)

    mnemonic = os.environ.get("MNEMONIC_SECRET")
    if not mnemonic:
        print("Error: MNEMONIC_SECRET environment variable is not set.")
        sys.exit(1)

    # Generate seed from mnemonic using bipsea.
    # Split the mnemonic string into words.
    seed = to_master_seed(mnemonic.split(), "")
    # Generate the master node. We use mainnet=True and private=True.
    master_node = to_master_key(seed, mainnet=True, private=True)

    try:
        result = derive_key_and_iv(master_node, int(key_version), app_id, filename)
        if get_private_key:
            print(json.dumps(result, indent=2))
        else:
            output = {
                "age_public_key": result["age_public_key"],
                "iv": result["iv"]
            }
            print(json.dumps(output, indent=2))
    except Exception as e:
        print("Error during key derivation:", str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
