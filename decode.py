#!/usr/bin/env python3
"""
decode.py — Depths of Endor backup decoder
Usage: python3 decode.py <file.dat> [output.json]

Decodes a .dat backup file:
  Base64 → AES-256-SIC (CTR) decrypt → PKCS7 unpad → JSON
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


def decrypt(ciphertext: bytes) -> bytes:
    """AES-256-CTR (SIC) decrypt with hardcoded key/IV."""
    iv_int = int.from_bytes(IV, "big")
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=b"", initial_value=iv_int)
    return cipher.decrypt(ciphertext)


def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if 1 <= pad <= 16 and all(b == pad for b in data[-pad:]):
        return data[:-pad]
    return data


def decode_dat(path: str) -> dict:
    """Read .dat → Base64-decode → decrypt → JSON."""
    raw = open(path, "rb").read().strip()
    ciphertext = base64.b64decode(raw)
    plaintext  = pkcs7_unpad(decrypt(ciphertext))
    return json.loads(plaintext.decode("utf-8"))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    dat_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    data = decode_dat(dat_path)

    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"Saved → {out_path}")
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
