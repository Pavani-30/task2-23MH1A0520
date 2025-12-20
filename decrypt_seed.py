#!/usr/bin/env python3
import base64
import json
import os
import re
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

HEX64_RE = re.compile(r'^[0-9a-f]{64}$')  # validated lower-case hex (adjust if uppercase allowed)

def load_private_key_from_pem(pem_path: str, password: bytes = None) -> rsa.RSAPrivateKey:
    """
    Load an RSA private key object from a PEM file (unencrypted or encrypted).
    Args:
        pem_path: path to private key PEM (student_private.pem)
        password: bytes password if the PEM is encrypted (None if unencrypted)
    Returns:
        RSAPrivateKey object
    """
    with open(pem_path, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Loaded key is not an RSA private key")
    return private_key

def decrypt_seed(encrypted_seed_b64: str, private_key: rsa.RSAPrivateKey) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP with SHA-256 and MGF1(SHA-256).
    Args:
        encrypted_seed_b64: base64-encoded ciphertext string (from instructor API)
        private_key: RSAPrivateKey object
    Returns:
        64-character hex string (lowercase) - the decrypted seed
    Raises:
        ValueError on invalid input or validation failure
    """
    if not encrypted_seed_b64 or not isinstance(encrypted_seed_b64, str):
        raise ValueError("encrypted_seed_b64 must be a non-empty base64 string")

    # 1) Base64 decode
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError(f"Failed to base64-decode encrypted_seed: {e}")

    # 2) RSA/OAEP decrypt (OAEP with SHA-256 and MGF1(SHA-256), label=None)
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        # Decryption error (bad ciphertext or wrong key/parameters)
        raise ValueError(f"RSA decryption failed: {e}")

    # 3) Decode to UTF-8 string
    try:
        plaintext = plaintext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        # If the decrypted value is binary not UTF-8, you might instead hex-encode it
        # but instruction expects a 64-character hex string UTF-8 encoded.
        raise ValueError("Decrypted bytes are not valid UTF-8")

    # 4) Validate: must be 64-character hexadecimal string
    # Normalize to lowercase
    plaintext_norm = plaintext.strip().lower()
    if len(plaintext_norm) != 64:
        raise ValueError(f"Decrypted seed length is {len(plaintext_norm)}; expected 64 characters")
    if not HEX64_RE.match(plaintext_norm):
        raise ValueError("Decrypted seed contains invalid characters — must be hex 0-9a-f")

    # 5) Return the validated hex seed
    return plaintext_norm

if __name__ == "__main__":
    # --------- USER CONFIGURE THESE VALUES ----------
    PRIVATE_KEY_PATH = "student_private.pem"         # path to your private key file in repo root
    # If you already have encrypted_seed.txt produced earlier, set ENCRYPTED_SEED_SOURCE = 'file'
    # If you have api_response.json, set to 'api_json' and it will extract encrypted_seed.
    ENCRYPTED_SEED_SOURCE = 'file'                   # either 'file' or 'api_json'
    ENCRYPTED_SEED_FILE = "encrypted_seed.txt"       # if using the file produced earlier
    API_RESPONSE_FILE = "api_response.json"          # if using the JSON
    OUTPUT_PATH = "data/seed.txt"                   # where to save the final seed (create dir if needed)
    # -----------------------------------------------

    # Load private key
    try:
        priv = load_private_key_from_pem(PRIVATE_KEY_PATH, password=None)
    except Exception as e:
        print("ERROR: could not load private key:", e)
        raise SystemExit(1)

    # Read encrypted seed string
    if ENCRYPTED_SEED_SOURCE == 'file':
        if not os.path.exists(ENCRYPTED_SEED_FILE):
            print(f"ERROR: {ENCRYPTED_SEED_FILE} not found in current folder")
            raise SystemExit(1)
        with open(ENCRYPTED_SEED_FILE, 'r', encoding='utf-8') as f:
            enc_b64 = f.read().strip()
    else:
        if not os.path.exists(API_RESPONSE_FILE):
            print(f"ERROR: {API_RESPONSE_FILE} not found in current folder")
            raise SystemExit(1)
        with open(API_RESPONSE_FILE, 'r', encoding='utf-8') as f:
            j = json.load(f)
        enc_b64 = j.get('encrypted_seed')
        if not enc_b64:
            print("ERROR: 'encrypted_seed' field missing in api_response.json")
            raise SystemExit(1)

    # Decrypt and validate
    try:
        seed_hex = decrypt_seed(enc_b64, priv)
    except Exception as e:
        print("ERROR during decryption/validation:", e)
        raise SystemExit(1)

    # Ensure output directory exists and save
    outdir = os.path.dirname(OUTPUT_PATH)
    if outdir and not os.path.exists(outdir):
        os.makedirs(outdir, exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write(seed_hex + "\n")

    print("Decrypted seed saved to:", OUTPUT_PATH)
    print("Seed (first 8 chars):", seed_hex[:8], " ... length:", len(seed_hex))
