"""
crypto_engine.py — Layer 3: Encryption Engine
==============================================
Secure-Doc · Phase 3 · A.N.T. Architecture

Provides two cipher modes under a single unified KDF:

  XOR_encrypt / XOR_decrypt
    → Honey Vault (vault/decoy/)
    → Key: PBKDF2-HMAC-SHA256(password, user_salt, 200_000)
    → Property: any honeyword decrypts decoy files to plausible content

  AES_encrypt / AES_decrypt
    → Real Vault  (vault/real/)
    → Cipher: AES-256-GCM (pycryptodome)
    → Key: PBKDF2-HMAC-SHA256(password, vault_salt, 200_000)
    → Nonce: 16-byte random, prepended to ciphertext
    → Tag:   16-byte GCM auth tag, appended after ciphertext

Wire format for AES ciphertext on disk:
  [ 16-byte nonce ][ variable-length ciphertext ][ 16-byte GCM tag ]

No external deps beyond pycryptodome + stdlib.
"""

import os
import hashlib
from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 200_000
PBKDF2_DKLEN      = 32          # 256-bit key for both XOR and AES-256
AES_NONCE_SIZE    = 16          # bytes
AES_TAG_SIZE      = 16          # bytes


# ---------------------------------------------------------------------------
# Shared KDF
# ---------------------------------------------------------------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Unified key derivation for both cipher modes.
    Returns a 256-bit key via PBKDF2-HMAC-SHA256.
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_DKLEN
    )


# ---------------------------------------------------------------------------
# XOR Cipher — Honey Vault
# ---------------------------------------------------------------------------
def xor_encrypt(plaintext: bytes, password: str, salt: bytes) -> bytes:
    """
    Encrypts plaintext for the decoy vault using a repeating XOR keystream.
    Any honeyword + its corresponding salt produces a plausible-looking result.

    Args:
        plaintext : raw file bytes to encrypt
        password  : the honeyword (or real password — same interface)
        salt      : per-user salt (stored in users table)

    Returns:
        XOR-encrypted ciphertext (same length as plaintext)
    """
    key = _derive_key(password, salt)
    # Extend key to plaintext length via repeating keystream
    keystream = (key * (len(plaintext) // PBKDF2_DKLEN + 1))[:len(plaintext)]
    return bytes(p ^ k for p, k in zip(plaintext, keystream))


def xor_decrypt(ciphertext: bytes, password: str, salt: bytes) -> bytes:
    """
    Decrypts XOR ciphertext. XOR is its own inverse — identical to encrypt.
    Any password produces output (no authentication); plausibility is by design.
    """
    return xor_encrypt(ciphertext, password, salt)


# ---------------------------------------------------------------------------
# AES-256-GCM Cipher — Real Vault
# ---------------------------------------------------------------------------
def aes_encrypt(plaintext: bytes, password: str, salt: bytes) -> bytes:
    """
    Encrypts plaintext for the real vault using AES-256-GCM.

    Wire format: [ 16-byte nonce || ciphertext || 16-byte GCM tag ]

    Args:
        plaintext : raw file bytes
        password  : the user's real password
        salt      : per-vault salt (distinct from the honeyset salt)

    Returns:
        Authenticated ciphertext blob
    """
    key    = _derive_key(password, salt)
    nonce  = os.urandom(AES_NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag


def aes_decrypt(blob: bytes, password: str, salt: bytes) -> bytes:
    """
    Decrypts and authenticates an AES-256-GCM blob.

    Raises ValueError on authentication failure (tampered ciphertext or wrong key).

    Args:
        blob     : nonce || ciphertext || tag (as returned by aes_encrypt)
        password : the user's real password
        salt     : same vault salt used during encryption

    Returns:
        Verified plaintext bytes
    """
    if len(blob) < AES_NONCE_SIZE + AES_TAG_SIZE:
        raise ValueError("Ciphertext blob is too short to contain nonce + tag.")

    nonce      = blob[:AES_NONCE_SIZE]
    tag        = blob[-AES_TAG_SIZE:]
    ciphertext = blob[AES_NONCE_SIZE:-AES_TAG_SIZE]

    key    = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("AES-GCM authentication failed — ciphertext may be tampered or password is incorrect.")


# ---------------------------------------------------------------------------
# File-level helpers
# ---------------------------------------------------------------------------
def encrypt_file_to_vault(src_path: str, dest_path: str, password: str,
                           salt: bytes, mode: str = 'aes') -> None:
    """
    Reads a plaintext file, encrypts it, writes to dest_path.

    Args:
        src_path  : path to plaintext source file
        dest_path : path to encrypted output file (in vault/real/ or vault/decoy/)
        password  : encryption password
        salt      : derived salt (honeyset salt for XOR, vault salt for AES)
        mode      : 'aes' for Real Vault, 'xor' for Honey Vault
    """
    with open(src_path, 'rb') as f:
        plaintext = f.read()

    if mode == 'aes':
        blob = aes_encrypt(plaintext, password, salt)
    elif mode == 'xor':
        blob = xor_encrypt(plaintext, password, salt)
    else:
        raise ValueError(f"Unknown mode '{mode}'. Use 'aes' or 'xor'.")

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, 'wb') as f:
        f.write(blob)


def decrypt_file_from_vault(src_path: str, password: str,
                             salt: bytes, mode: str = 'aes') -> bytes:
    """
    Reads an encrypted vault file and returns decrypted bytes.

    Args:
        src_path : path to encrypted file in vault
        password : decryption password
        salt     : matching salt used at encryption time
        mode     : 'aes' for Real Vault, 'xor' for Honey Vault

    Returns:
        Decrypted file bytes
    """
    with open(src_path, 'rb') as f:
        blob = f.read()

    if mode == 'aes':
        return aes_decrypt(blob, password, salt)
    elif mode == 'xor':
        return xor_decrypt(blob, password, salt)
    else:
        raise ValueError(f"Unknown mode '{mode}'. Use 'aes' or 'xor'.")
