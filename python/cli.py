#!/usr/bin/env python3
"""
Independent Python implementation of the BIP85KMS derivation scheme.

This deliberately duplicates the crypto logic in src/core.ts using a different
language and different crypto libraries (bipsea, cryptography) rather than
being a thin client of it. The point is NOT code reuse -- it's an independent
cross-check: if this and the TypeScript implementation (src/core.ts) agree on
the same test vectors, that's much stronger evidence the derivation is correct
than either implementation alone.

If you change the derivation logic in src/core.ts, mirror the change here too
and re-run tests/all_bip85_test_vectors.py against both.

Usage:
  export MNEMONIC_SECRET="bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon"
  python3 cli.py --filename "example.txt" --keyVersion 1 --appId "myApp" --getPrivateKey --verbose
  python3 cli.py --semantic-path '[{"@type":"Organization","name":"AcmeCorp"}]'
"""

import sys
import os
import json
import hashlib
import hmac

from bipsea.bip39 import to_master_seed
from bipsea.bip32 import to_master_key, derive_key

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

BIP85_PURPOSE = 83696968
KEYCHAIN_APP_CODE = 67797668
LEGACY_APP_CODE = 128169

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
    # BIP-173 checksums are computed over the lowercased hrp (matches the JS
    # `bech32` package's `prefix.toLowerCase()`); callers re-case the full result.
    hrp = hrp.lower()
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


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def u64be(value: int) -> bytes:
    return value.to_bytes(8, byteorder="big")


def derive_bip85_entropy(index: int, master_node, verbose: bool = False) -> bytes:
    """Derives BIP85 entropy from m/83696968'/{index}'."""
    path = f"m/{BIP85_PURPOSE}'/{index}'"
    if verbose:
        print(f"\n[Step 1] Deriving child node for path: {path}")
    # bipsea's derive_key() internally does path[1:], so the leading "m" must stay.
    segments = path.split("/")
    child = derive_key(master_node, segments, private=True)
    priv = child.data
    if priv is None:
        raise Exception("Failed to derive child private key")
    # bipsea prefixes private key data with a 0x00 sign byte (33 bytes); strip it
    # to get the raw 32-byte private key that other implementations hash.
    if len(priv) == 33:
        priv = priv[1:]
    entropy = hashlib.sha256(priv).digest()
    if verbose:
        print(f"[Step 1] SHA256(child private key): {entropy.hex()}")
    return entropy


def derive_deterministic_age_key(master_key: bytes, index: int, verbose: bool = False) -> str:
    """HMAC-SHA256(master_key, index) -> bech32 "AGE-SECRET-KEY-" encoding."""
    key = hmac.new(master_key, u64be(index), hashlib.sha256).digest()
    words = convertbits(list(key), 8, 5)
    encoded = bech32_encode("AGE-SECRET-KEY-", words)
    if verbose:
        print(f"[Step 2] Bech32 encoded Age private key: {encoded.upper()}")
    return encoded.upper()


def derive_public_key(raw_secret: bytes) -> str:
    private_key = x25519.X25519PrivateKey.from_private_bytes(raw_secret)
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    words = convertbits(list(public_key_bytes), 8, 5)
    return bech32_encode("age", words).lower()


def derive_indexes(key_version: int, app_id: str, filename: str):
    app_id_hash = hashlib.sha256(app_id.encode()).digest()
    filename_hash = hashlib.sha256(filename.encode()).digest()
    idx0 = key_version & 0x7fffffff
    idx1 = bytes_to_int(app_id_hash[:4]) & 0x7fffffff
    idx2 = bytes_to_int(filename_hash[:4]) & 0x7fffffff
    derivation_path = f"m/{BIP85_PURPOSE}'/{LEGACY_APP_CODE}'/{idx0}'/{idx1}'/{idx2}'"
    return (idx0, idx1, idx2), app_id_hash, filename_hash, derivation_path


def derive_key_and_iv(master_node, key_version: int, app_id: str, filename: str, verbose: bool = False):
    """
    Mirrors src/core.ts deriveKeyAndIV: entropy is derived from keyVersion via BIP85,
    then mixed (HMAC-SHA256) with the appId/filename hashes so distinct apps/files
    never collide to the same key material, even under the same keyVersion.
    """
    (idx0, idx1, idx2), app_id_hash, filename_hash, derivation_path = derive_indexes(
        key_version, app_id, filename
    )
    if verbose:
        print(f"\n[Step 3] Derived indexes: keyVersion={idx0}, appId={idx1}, filename={idx2}")
        print(f"[Step 3] Full derivation path: {derivation_path}")

    base_entropy = derive_bip85_entropy(idx0, master_node, verbose)
    context = app_id_hash[:16] + filename_hash[:16]
    entropy = hmac.new(base_entropy, context, hashlib.sha256).digest()
    if verbose:
        print(f"[Step 3] Context-bound entropy: {entropy.hex()}")

    age_private_key = derive_deterministic_age_key(entropy, idx0, verbose)
    raw_secret = hmac.new(entropy, u64be(idx0), hashlib.sha256).digest()
    age_public_key = derive_public_key(raw_secret)
    if verbose:
        print(f"[Step 4] Bech32 encoded Age public key: {age_public_key}")

    iv_hex = filename_hash[:12].hex()
    return {
        "derivationPath": derivation_path,
        "age_private_key": age_private_key,
        "age_public_key": age_public_key,
        "raw_entropy": entropy.hex(),
        "iv": iv_hex,
    }


# --- Semantic path (BIP-Keychain) derivation, mirrors src/core.ts ---

def jcs(obj) -> str:
    """JSON Canonicalization Scheme (RFC 8785): sorted keys, compact separators."""
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return json.dumps(obj)
    if isinstance(obj, str):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(jcs(item) for item in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
        return "{" + ",".join(f"{json.dumps(k)}:{jcs(obj[k])}" for k in keys) + "}"
    raise TypeError(f"Cannot canonicalize type: {type(obj)}")


def semantic_to_index(segment: dict, parent_entropy: bytes, hardened: bool = True) -> int:
    canonical = jcs(segment)
    digest = hmac.new(parent_entropy, canonical.encode(), hashlib.sha256).digest()
    value32 = bytes_to_int(digest[:4])
    index31 = (value32 >> 1) & 0xffffffff
    return (index31 | 0x80000000) if hardened else index31


def derive_from_semantic_path(master_node, semantic_path: list, verbose: bool = False):
    if not isinstance(semantic_path, list) or len(semantic_path) == 0:
        raise ValueError("Semantic path must be a non-empty array")
    for i, segment in enumerate(semantic_path):
        if not isinstance(segment, dict) or "@type" not in segment:
            raise ValueError(f"Invalid segment at index {i}: must be a JSON object with @type")

    current_path = f"m/{BIP85_PURPOSE}'/{KEYCHAIN_APP_CODE}'"
    current_entropy = derive_bip85_entropy(KEYCHAIN_APP_CODE, master_node, verbose)
    final_index = 0

    for segment in semantic_path:
        index_with_hardened = semantic_to_index(segment, current_entropy, True)
        unhardened_index = index_with_hardened & 0x7fffffff
        final_index = unhardened_index
        current_path = f"{current_path}/{unhardened_index}'"

        # bipsea's derive_key() internally does path[1:], so the leading "m" must stay.
        segments = current_path.split("/")
        child = derive_key(master_node, segments, private=True)
        if child.data is None:
            raise Exception(f"Failed to derive child node at {current_path}")
        # bipsea prefixes private key data with a 0x00 sign byte (33 bytes); strip it
        # to get the raw 32-byte private key that other implementations hash.
        child_priv = child.data[1:] if len(child.data) == 33 else child.data
        current_entropy = hashlib.sha256(child_priv).digest()
        if verbose:
            print(f"[Segment] path={current_path} entropy={current_entropy.hex()}")

    final_entropy = current_entropy
    age_private_key = derive_deterministic_age_key(final_entropy, final_index, verbose)
    raw_secret = hmac.new(final_entropy, u64be(final_index), hashlib.sha256).digest()
    age_public_key = derive_public_key(raw_secret)

    return {
        "derivationPath": current_path,
        "age_private_key": age_private_key,
        "age_public_key": age_public_key,
        "raw_entropy": final_entropy.hex(),
        "semanticPath": semantic_path,
    }


def parse_args(argv):
    result = {}
    i = 0
    while i < len(argv):
        if argv[i].startswith("--"):
            key = argv[i][2:]
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                result[key] = argv[i + 1]
                i += 2
            else:
                result[key] = True
                i += 1
        else:
            i += 1
    return result


def load_master_node(verbose: bool):
    mnemonic = os.environ.get("MNEMONIC_SECRET")
    if not mnemonic:
        print("Error: MNEMONIC_SECRET environment variable is not set.")
        sys.exit(1)
    seed = to_master_seed(mnemonic.split(), "")
    if verbose:
        print(f"[Step 0] Master seed: {seed.hex()}")
    return to_master_key(seed, mainnet=True, private=True)


def main():
    args = parse_args(sys.argv[1:])
    verbose = args.get("verbose") in [True, "true", "True"]
    get_private_key = args.get("getPrivateKey") in [True, "true", "True"]

    semantic_path_arg = args.get("semantic-path")
    if semantic_path_arg:
        master_node = load_master_node(verbose)
        try:
            semantic_path = json.loads(semantic_path_arg)
            result = derive_from_semantic_path(master_node, semantic_path, verbose)
        except Exception as e:
            print("Error during key derivation:", str(e))
            sys.exit(1)
    else:
        filename = args.get("filename")
        key_version = args.get("keyVersion")
        app_id = args.get("appId")
        if not filename or not key_version or not app_id:
            print("Error: Missing required argument(s).")
            print(
                "Usage: python3 cli.py --filename <filename> --keyVersion <number> --appId <appId> [--getPrivateKey] [--verbose]"
                "\n   or: python3 cli.py --semantic-path '<json array>' [--getPrivateKey] [--verbose]"
            )
            sys.exit(1)
        master_node = load_master_node(verbose)
        try:
            result = derive_key_and_iv(master_node, int(key_version), app_id, filename, verbose)
        except Exception as e:
            print("Error during key derivation:", str(e))
            sys.exit(1)

    if get_private_key:
        print("\nFinal Result (full details):")
        print(json.dumps(result, indent=2))
    else:
        output = {"age_public_key": result["age_public_key"]}
        if "iv" in result:
            output["iv"] = result["iv"]
        print("\nFinal Result:")
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
