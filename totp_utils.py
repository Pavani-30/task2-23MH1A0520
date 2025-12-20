#!/usr/bin/env python3
"""
totp_utils.py

Functions:
- generate_totp_code(hex_seed: str) -> str
- verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool

Example usage (from repo root):
  python totp_utils.py generate
  python totp_utils.py verify 123456
"""

import base64
import pyotp
import sys
from typing import Optional


def _hex_to_base32(hex_seed: str) -> str:
    """
    Convert a 64-character hex seed string to Base32 string for TOTP libraries.

    Notes:
      - Input hex_seed may be lowercase or uppercase, with or without whitespace.
      - Output is an uppercase Base32 string with padding removed (common format).
    """
    if not isinstance(hex_seed, str):
        raise TypeError("hex_seed must be a string")
    s = hex_seed.strip().lower()
    if len(s) != 64:
        raise ValueError("hex_seed must be exactly 64 hex characters")
    # validate hex
    try:
        b = bytes.fromhex(s)
    except Exception as e:
        raise ValueError("hex_seed invalid hex") from e

    b32 = base64.b32encode(b).decode("utf-8")
    # Remove '=' padding (TOTP libraries accept both with/without, but removing is common)
    return b32.rstrip('=').upper()


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate a 6-digit TOTP code (SHA-1, 30s period) from a 64-character hex seed.
    Returns the 6-digit code as a string (e.g., "123456").
    """
    b32 = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)  # pyotp uses SHA-1 by default
    return totp.now()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code using a time window tolerance.
      - valid_window: number of 30s steps before/after to accept (default 1 -> ±30s).
    Returns True if the code is valid, False otherwise.
    """
    if not isinstance(code, str):
        code = str(code)
    b32 = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    # pyotp.verify accepts a window parameter (integer) for ± steps
    return totp.verify(code, valid_window=valid_window)


# ----- CLI demo: read hex seed from data/seed.txt or manually -----
def _read_local_seed(path: str = "data/seed.txt") -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            s = f.read().strip()
            return s
    except FileNotFoundError:
        return None


if __name__ == "__main__":
    # Usage:
    #  python totp_utils.py generate        -> prints current TOTP using data/seed.txt
    #  python totp_utils.py verify 123456  -> verifies code 123456 and prints result
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("generate", "verify"), help="generate or verify")
    ap.add_argument("code", nargs="?", help="code to verify (for verify command)")
    ap.add_argument("--seed", help="hex seed string (override file)", default=None)
    ap.add_argument("--window", type=int, default=1, help="valid window (± steps)")
    args = ap.parse_args()

    hex_seed = args.seed or _read_local_seed("data/seed.txt")
    if not hex_seed:
        print("ERROR: no seed found. Provide --seed HEX or ensure data/seed.txt exists.")
        sys.exit(2)

    if args.cmd == "generate":
        try:
            code = generate_totp_code(hex_seed)
            print(code)
        except Exception as e:
            print("ERROR generating TOTP:", e)
            sys.exit(1)
    else:  # verify
        if not args.code:
            print("ERROR: provide code to verify")
            sys.exit(2)
        ok = verify_totp_code(hex_seed, args.code, valid_window=args.window)
        print("VALID" if ok else "INVALID")
        sys.exit(0 if ok else 3)
