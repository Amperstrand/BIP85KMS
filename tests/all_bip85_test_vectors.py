#!/usr/bin/env python3
"""
This file tests the BIP85 test vectors using bipsea.

IMPORTANT NOTES:
---------------
1. The raw entropy test vectors (Test Case 1 and Test Case 2 for raw entropy, and the DRNG output)
   require deriving secrets from specific arbitrary derivation paths (m/83696968'/0'/0' and m/83696968'/0'/1').
2. The bipsea CLI requires you to choose a predefined application (e.g. hex, mnemonic, wif, etc.) and
   uses a fixed derivation path corresponding to that application (for example, for hex output it uses the
   application code 128169'). Therefore, you cannot specify an arbitrary path (like m/83696968'/0'/0')
   using the CLI.
3. To derive the raw entropy exactly as specified in BIP85, we must manually derive the sub-xprv for the 
   desired path using bipsea's internal BIP-32 modules (which we import from bipsea.bip32types and bipsea.bip32)
   and then compute the HMAC-SHA512 on the derived private key.
4. The DRNG test vector is computed by seeding SHAKE256 with the raw entropy from Test Vector 1.
5. The remaining application test vectors (BIP39 mnemonics, HD-Seed WIF, XPRV, HEX output, Base64 and Base85
   passwords, and Dice) are derivable directly via the bipsea CLI.

This file uses verbose debugging to show the full derivation path and intermediate keys.
"""

import subprocess
import sys
import hmac, hashlib

# Import bipsea's internal modules.
from bipsea.bip32types import ExtendedKey, parse_ext_key
from bipsea.bip32 import derive_key

# Master BIP32 root key from the BIP85 specification.
MASTER_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

def assert_equal(test_name, output, expected):
    if output == expected:
        print(f"[PASS] {test_name}")
    else:
        print(f"[FAIL] {test_name}")
        print(f"  Expected: {expected}")
        print(f"  Got:      {output}")
        sys.exit(1)

def derive_sub_xprv(master_xprv: str, path: list) -> (str, str):
    """
    Derive a sub-xprv from the master_xprv using a list of integers (each representing a hardened segment).
    
    IMPORTANT:
    ----------
    The bipsea CLI always uses a predefined derivation path based on the chosen application.
    To derive the raw entropy exactly as specified in BIP85 (from m/83696968'/0'/0' for example),
    we need to manually derive the sub-xprv using bipsea's internal BIP32 functions.
    
    For example, for path m/83696968'/0'/0', pass path = [83696968, 0, 0].
    We then prepend "m" to the path so that the full derivation path becomes:
      ["m", "83696968'", "0'", "0'"]
    This ensures that derive_key processes all the intended segments.
    
    Returns:
      A tuple (sub_xprv_str, private_key_hex) where:
       - sub_xprv_str is the extended key for the derived node (as base58 string).
       - private_key_hex is the 32-byte private key (excluding the leading 0x00) as a hex string.
    """
    master = parse_ext_key(master_xprv)
    # Prepend "m" to indicate the master node, then each segment is a hardened index.
    path_strs = ["m"] + [f"{p}'" for p in path]
    print(f"Debug: Full derivation path: {path_strs}")
    sub = derive_key(master, path_strs, private=True)
    # sub.data is 33 bytes: first byte is 0x00, the rest is the 32-byte private key.
    privkey_hex = sub.data[1:].hex()
    return str(sub), privkey_hex

def run_bipsea(application: str, xprv: str, number: int or None, index: int, extra_args: list or None = None) -> str:
    """
    Run the bipsea CLI with the given parameters.
    
    Parameters:
      - application: one of [base64, base85, dice, drng, hex, mnemonic, wif, xprv]
      - xprv: extended private key (as base58 string)
      - number: length of output (in bytes/chars/words) or None if not required
      - index: child index (integer)
      - extra_args: additional CLI arguments (list), e.g., ["-t", "eng"] or ["-s", "6"]
    
    Returns the output string (stripped).
    """
    cmd = ["bipsea", "derive", "-a", application, "-x", xprv, "-i", str(index)]
    if number is not None:
        cmd.extend(["-n", str(number)])
    if extra_args:
        cmd.extend(extra_args)
    print("Debug: Running command:", " ".join(cmd))
    result = subprocess.check_output(cmd, encoding="utf-8").strip()
    return result

def compute_hmac_sha512(key_bytes_hex: str) -> str:
    """
    Compute HMAC-SHA512 using the ASCII key "bip-entropy-from-k" on the 32-byte private key (provided as hex).
    Returns the hex digest.
    """
    key_bytes = bytes.fromhex(key_bytes_hex)
    return hmac.new(b"bip-entropy-from-k", key_bytes, hashlib.sha512).hexdigest()

def compute_drng(seed_hex: str, output_bytes: int) -> str:
    """
    Compute BIP85-DRNG-SHAKE256: seed a SHAKE256 instance with the 64-byte seed (provided as hex)
    and return output_bytes bytes as a hex string.
    """
    seed = bytes.fromhex(seed_hex)
    shake = hashlib.shake_256(seed)
    return shake.hexdigest(output_bytes)

def main():
    print("=== Testing BIP85 Derivations ===")
    print("MASTER_XPRV:")
    print(MASTER_XPRV)
    print("")

    #############################################
    # Raw Entropy Test Vectors (Manual Calculation)
    #############################################
    # These test vectors require deriving from arbitrary paths (m/83696968'/0'/0' and m/83696968'/0'/1'),
    # which is not possible using only the bipsea CLI because it forces you to choose an application
    # (and uses a fixed derivation path for that application). Thus, we derive these manually.
    
    # Test Vector 1: from m/83696968'/0'/0'
    expected_raw_entropy1 = (
        "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
    )
    print("Deriving sub-xprv for m/83696968'/0'/0'")
    sub_xprv_tv1, privkey_hex_tv1 = derive_sub_xprv(MASTER_XPRV, [83696968, 0, 0])
    print("Sub-xprv:", sub_xprv_tv1)
    print("Intermediate private key (hex):", privkey_hex_tv1)
    
    manual_hmac1 = compute_hmac_sha512(privkey_hex_tv1)
    print("Manually computed HMAC-SHA512:", manual_hmac1)
    assert_equal("Raw Entropy Test Vector 1 (manual)", manual_hmac1, expected_raw_entropy1)
    
    # Test Vector 2: from m/83696968'/0'/1'
    expected_raw_entropy2 = (
        "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"
    )
    print("\nDeriving sub-xprv for m/83696968'/0'/1'")
    sub_xprv_tv2, privkey_hex_tv2 = derive_sub_xprv(MASTER_XPRV, [83696968, 0, 1])
    print("Sub-xprv:", sub_xprv_tv2)
    print("Intermediate private key (hex):", privkey_hex_tv2)
    
    manual_hmac2 = compute_hmac_sha512(privkey_hex_tv2)
    print("Manually computed HMAC-SHA512:", manual_hmac2)
    assert_equal("Raw Entropy Test Vector 2 (manual)", manual_hmac2, expected_raw_entropy2)
    
    # DRNG: use the raw entropy from Test Vector 1 as the seed to produce 80 bytes via SHAKE256.
    expected_drng = (
        "b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd883d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc8c7355b87a925a37ee405a7502991111"
    )
    drng_manual = compute_drng(manual_hmac1, 80)
    print("\nComputed DRNG (via SHAKE256):", drng_manual)
    assert_equal("DRNG Test Vector (manual)", drng_manual, expected_drng)
    
    #############################################
    # Application Test Vectors (Using bipsea CLI)
    #############################################
    
    # For these tests, we use the bipsea CLI directly, because they use predefined applications.
    
    # BIP39 mnemonic (Application 39') - 12 words
    expected_mnemonic12 = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
    mnemonic12 = run_bipsea("mnemonic", MASTER_XPRV, 12, 0, extra_args=["-t", "eng"])
    assert_equal("BIP39 12-word mnemonic", mnemonic12, expected_mnemonic12)
    
    # BIP39 mnemonic - 18 words
    expected_mnemonic18 = ("near account window bike charge season chef number sketch tomorrow excuse sniff circle "
                           "vital hockey outdoor supply token")
    mnemonic18 = run_bipsea("mnemonic", MASTER_XPRV, 18, 0, extra_args=["-t", "eng"])
    assert_equal("BIP39 18-word mnemonic", mnemonic18, expected_mnemonic18)
    
    # BIP39 mnemonic - 24 words
    expected_mnemonic24 = ("puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin "
                           "tonight reason outdoor destroy simple truth cigar social volcano")
    mnemonic24 = run_bipsea("mnemonic", MASTER_XPRV, 24, 0, extra_args=["-t", "eng"])
    assert_equal("BIP39 24-word mnemonic", mnemonic24, expected_mnemonic24)
    
    # HD-Seed WIF (Application 2'): (Do not pass -n)
    expected_wif = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
    wif_out = run_bipsea("wif", MASTER_XPRV, None, 0)
    assert_equal("HD-Seed WIF", wif_out, expected_wif)
    
    # XPRV (Application 32'): (Do not pass -n)
    expected_xprv = "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
    xprv_out = run_bipsea("xprv", MASTER_XPRV, None, 0)
    assert_equal("XPRV derivation", xprv_out, expected_xprv)
    
    # HEX (64 bytes, Application 128169')
    expected_hex = ("492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c")
    hex_out = run_bipsea("hex", MASTER_XPRV, 64, 0)
    assert_equal("HEX (64 bytes)", hex_out, expected_hex)
    
    # Password (Base64, length 21, Application 707764')
    expected_pwd_base64 = "dKLoepugzdVJvdL56ogNV"
    pwd_base64 = run_bipsea("base64", MASTER_XPRV, 21, 0)
    assert_equal("Password Base64", pwd_base64, expected_pwd_base64)
    
    # Password (Base85, length 12, Application 707785')
    expected_pwd_base85 = "_s`{TW89)i4`"
    pwd_base85 = run_bipsea("base85", MASTER_XPRV, 12, 0)
    assert_equal("Password Base85", pwd_base85, expected_pwd_base85)
    
    # Dice: 10 rolls of a 6-sided die (Application 89101')
    expected_dice = "1,0,0,2,0,1,5,5,2,4"
    dice_out = run_bipsea("dice", MASTER_XPRV, 10, 0, extra_args=["-s", "6"])
    assert_equal("Dice rolls", dice_out, expected_dice)
    
    print("All BIP85 test vectors passed.")

if __name__ == '__main__':
    main()
