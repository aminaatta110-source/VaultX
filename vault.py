"""
vault.py — Core encryption engine for VaultX
----------------------------------------------
How it works (read this before your interview):

1. MASTER PASSWORD → PBKDF2 → ENCRYPTION KEY
   Your master password is never stored. Instead, PBKDF2 (Password-Based
   Key Derivation Function 2) runs it through 390,000 rounds of SHA-256
   hashing mixed with a random "salt". The output is a 256-bit key.
   Why so many rounds? Slows down brute-force attackers massively.

2. ENCRYPTION KEY + DATA → AES-256-CBC → CIPHERTEXT
   AES-256 (Advanced Encryption Standard) is the gold standard symmetric
   cipher. CBC mode chains each block to the previous one so identical
   passwords encrypt differently every time (via a random IV).

3. STORAGE FORMAT (JSON):
   { "salt": <hex>, "entries": { "site": { "iv": <hex>, "ct": <hex> } } }
   Salt and IV are not secret — they just need to be unique and random.
"""

import os
import json
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


VAULT_FILE = "vault.json"
ITERATIONS = 390_000   # PBKDF2 rounds — NIST recommended minimum (2023)
KEY_LENGTH = 32         # 32 bytes = 256 bits (AES-256)
BLOCK_SIZE = 128        # AES block size in bits


# ── Key derivation ────────────────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Turn a human password into a cryptographic key using PBKDF2-HMAC-SHA256.
    Same password + same salt → same key (deterministic).
    Different salt → completely different key (why salt is stored in vault).
    """
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=master_password.encode("utf-8"),
        salt=salt,
        iterations=ITERATIONS,
        dklen=KEY_LENGTH,
    )


# ── Encryption / Decryption ───────────────────────────────────────────────

def encrypt(plaintext: str, key: bytes) -> dict:
    """
    Encrypt a string with AES-256-CBC.
    Returns a dict with the IV and ciphertext (both hex-encoded for storage).

    IV (Initialisation Vector): random 16 bytes generated fresh per entry.
    Without a unique IV, two identical passwords would produce identical
    ciphertext — leaking information to an attacker.
    """
    iv = os.urandom(16)  # fresh random IV every time

    # PKCS7 padding: AES requires input to be a multiple of 16 bytes
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {
        "iv": iv.hex(),
        "ct": ciphertext.hex(),
    }


def decrypt(entry: dict, key: bytes) -> str:
    """
    Reverse of encrypt(). Needs the same key (derived from same master password).
    If the wrong master password is used, decryption produces garbage/raises error.
    """
    iv = bytes.fromhex(entry["iv"])
    ciphertext = bytes.fromhex(entry["ct"])

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding to recover original plaintext
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode("utf-8")


# ── Vault I/O ─────────────────────────────────────────────────────────────

def load_vault() -> dict:
    """Load vault from disk. Returns empty structure if no vault exists yet."""
    if not os.path.exists(VAULT_FILE):
        return {"salt": None, "entries": {}}
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault(vault: dict) -> None:
    """Persist vault to disk as JSON."""
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=2)


# ── High-level vault operations ───────────────────────────────────────────

def initialise_vault(master_password: str) -> bytes:
    """
    First-time setup: generate a random salt, derive the key, save vault.
    The salt is stored in plaintext — it's not secret, just unique.
    """
    vault = load_vault()
    if vault["salt"] is None:
        salt = os.urandom(32)  # 256-bit random salt
        vault["salt"] = salt.hex()
        save_vault(vault)
    else:
        salt = bytes.fromhex(vault["salt"])
    return derive_key(master_password, salt)


def unlock_vault(master_password: str) -> bytes:
    """
    Return the derived key for an existing vault.
    Raises FileNotFoundError if no vault exists yet.
    """
    vault = load_vault()
    if vault["salt"] is None:
        raise ValueError("No vault found. Create one first.")
    salt = bytes.fromhex(vault["salt"])
    return derive_key(master_password, salt)


def add_entry(site: str, username: str, password: str, key: bytes) -> None:
    """Encrypt and store credentials for a site."""
    vault = load_vault()
    vault["entries"][site] = {
        "username": username,               # username stored in plaintext
        "password": encrypt(password, key), # password AES-256 encrypted
    }
    save_vault(vault)


def get_entry(site: str, key: bytes) -> dict | None:
    """Retrieve and decrypt credentials for a site."""
    vault = load_vault()
    entry = vault["entries"].get(site)
    if entry is None:
        return None
    return {
        "site": site,
        "username": entry["username"],
        "password": decrypt(entry["password"], key),
    }


def list_sites() -> list:
    """Return all stored site names (no passwords exposed)."""
    return list(load_vault()["entries"].keys())


def delete_entry(site: str) -> bool:
    """Remove a site's credentials. Returns True if deleted, False if not found."""
    vault = load_vault()
    if site not in vault["entries"]:
        return False
    del vault["entries"][site]
    save_vault(vault)
    return True
