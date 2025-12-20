# app.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64, os, json, re
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from totp_utils import generate_totp_code, verify_totp_code

# Config
PRIVATE_KEY_PATH = "student_private.pem"   # ensure file present in repo root
SEED_PATH = "data/seed.txt"                # relative repo-local path
HEX64_RE = re.compile(r'^[0-9a-f]{64}$')

app = FastAPI(title="2FA helper API")

# Request bodies
class EncryptedSeedRequest(BaseModel):
    encrypted_seed: str

class VerifyRequest(BaseModel):
    code: str

# helper: load private key
def load_private_key(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key not found at {path}")
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_private_key(data, password=None, backend=default_backend())
    return key

# helper: decrypt RSA/OAEP-SHA256 ciphertext (ciphertext must be bytes)
def rsa_oaep_sha256_decrypt(private_key, ciphertext_bytes):
    try:
        plaintext = private_key.decrypt(
            ciphertext_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext  # bytes
    except Exception as e:
        raise ValueError("RSA decryption failed") from e

# Endpoint 1: POST /decrypt-seed
@app.post("/decrypt-seed")
def post_decrypt_seed(body: EncryptedSeedRequest):
    # 1) decode base64
    try:
        cipher_bytes = base64.b64decode(body.encrypted_seed, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encrypted_seed")

    # 2) load private key
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Private key not found on server")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to load private key")

    # 3) decrypt using OAEP-SHA256
    try:
        pt = rsa_oaep_sha256_decrypt(priv, cipher_bytes)
    except ValueError:
        raise HTTPException(status_code=500, detail="Decryption failed")

    # 4) decode plaintext to utf-8 and validate 64 hex chars
    try:
        seed_text = pt.decode("utf-8").strip().lower()
    except Exception:
        raise HTTPException(status_code=500, detail="Decrypted seed not valid UTF-8")

    if not HEX64_RE.match(seed_text):
        raise HTTPException(status_code=500, detail="Decrypted seed invalid format")

    # 5) ensure output dir exists and save
    outdir = os.path.dirname(SEED_PATH)
    if outdir and not os.path.exists(outdir):
        os.makedirs(outdir, exist_ok=True)
    with open(SEED_PATH, "w", encoding="utf-8") as f:
        f.write(seed_text + "\n")

    return {"status": "ok"}

# Endpoint 2: GET /generate-2fa
@app.get("/generate-2fa")
def get_generate_2fa():
    # check seed
    if not os.path.exists(SEED_PATH):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    seed = open(SEED_PATH, "r", encoding="utf-8").read().strip()
    if not HEX64_RE.match(seed):
        raise HTTPException(status_code=500, detail="Invalid seed format")

    # generate code
    try:
        code = generate_totp_code(seed)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to generate TOTP")

    # compute seconds remaining in current 30s window
    import time
    period = 30
    epoch = int(time.time())
    seconds_into_step = epoch % period
    valid_for = period - seconds_into_step

    return {"code": code, "valid_for": valid_for}

# Endpoint 3: POST /verify-2fa
@app.post("/verify-2fa")
def post_verify_2fa(req: VerifyRequest):
    if not req.code:
        raise HTTPException(status_code=400, detail="Missing code")
    if not os.path.exists(SEED_PATH):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    seed = open(SEED_PATH, "r", encoding="utf-8").read().strip()
    if not HEX64_RE.match(seed):
        raise HTTPException(status_code=500, detail="Invalid seed format")

    # verify with default ±1 window
    try:
        valid = verify_totp_code(seed, req.code, valid_window=1)
    except Exception:
        raise HTTPException(status_code=500, detail="Verification error")

    return {"valid": bool(valid)}
