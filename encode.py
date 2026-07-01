#!/usr/bin/env python3
"""
encode.py — Depths of Endor backup encoder
Usage: python3 encode.py <input.json> <output.dat>

Encodes a JSON file back into a .dat backup:
  JSON → PKCS7 pad → AES-256-SIC (CTR) encrypt → Base64 → .dat

Example workflow:
  python3 decode.py backup.dat save.json   # unpack
  # edit save.json (e.g. set "gold": 9999999)
  python3 encode.py save.json backup_new.dat  # repack
"""

import sys
import json
import base64

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("Install pycryptodome: pip install pycryptodome")

# ---------- Hardcoded key/IV (from libapp.so via blutter) ----------
_KEY_B64 = "a8m18KqdAtRhb1do3dhj8g1Bn+E/ytaCdpz/4aeZLPY="
_IV_B64  = "Y3NAi9xKmO/FxicwzV6PDw=="

KEY = base64.b64decode(_KEY_B64)  # 32 bytes — AES-256
IV  = base64.b64decode(_IV_B64)   # 16 bytes


def pkcs7_pad(data: bytes, block=16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad] * pad)


def encrypt(plaintext: bytes) -> bytes:
    """AES-256-CTR (SIC) encrypt with hardcoded key/IV."""
    iv_int = int.from_bytes(IV, "big")
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=b"", initial_value=iv_int)
    return cipher.encrypt(plaintext)


def encode_dat(data: dict) -> str:
    """JSON dict → Base64 .dat string."""
    plaintext  = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    padded     = pkcs7_pad(plaintext)
    ciphertext = encrypt(padded)
    return base64.b64encode(ciphertext).decode("ascii")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    json_path = sys.argv[1]
    dat_path  = sys.argv[2]

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    encoded = encode_dat(data)

    with open(dat_path, "w", encoding="ascii") as f:
        f.write(encoded)

    print(f"Saved → {dat_path}  ({len(encoded)} chars)")

    # Quick round-trip verification
    ct_bytes = base64.b64decode(encoded)
    iv_int   = int.from_bytes(IV, "big")
    cipher   = AES.new(KEY, AES.MODE_CTR, nonce=b"", initial_value=iv_int)
    pt       = cipher.decrypt(ct_bytes)
    pad      = pt[-1]
    pt       = pt[:-pad]
    check    = json.loads(pt)
    ok       = check == data
    print(f"Round-trip check: {'OK ✓' if ok else 'FAIL ✗'}")


if __name__ == "__main__":
    main()
