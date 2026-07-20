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
    → Cipher: AES-256-CBC, hand-implemented from FIPS-197 (see aes256.py) —
      no third-party crypto library. Authenticated Encrypt-then-MAC with
      HMAC-SHA256 (stdlib hmac) stands in for AES-GCM's built-in tag.
    → Keys: PBKDF2-HMAC-SHA256(password, vault_salt, 200_000, dklen=64),
      split into a 32-byte AES key and a distinct 32-byte HMAC key.
    → IV:  16-byte random, prepended to ciphertext.
    → Tag: 32-byte HMAC-SHA256 over (iv || ciphertext), appended.

Wire format for AES ciphertext on disk:
  [ 16-byte IV ][ variable-length CBC ciphertext ][ 32-byte HMAC tag ]

No external deps beyond the Python standard library (hashlib, hmac, os)
plus this project's own aes256.py — no pycryptodome / cryptography.
"""

import os
import hmac
import hashlib
from aes256 import cbc_encrypt, cbc_decrypt

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS  = 200_000
PBKDF2_DKLEN       = 32          # 256-bit key for XOR
AES_KDF_DKLEN      = 64          # AES key (32B) + HMAC key (32B)
AES_IV_SIZE        = 16          # bytes
HMAC_TAG_SIZE      = 32          # bytes (SHA-256 digest)


# ---------------------------------------------------------------------------
# Shared KDF
# ---------------------------------------------------------------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Key derivation used by the XOR honey-vault path.
    Returns a 256-bit key via PBKDF2-HMAC-SHA256.
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_DKLEN
    )


def _derive_aes_keys(password: str, salt: bytes):
    """
    Derives independent AES-encryption and HMAC-authentication keys from
    a single PBKDF2 call (Encrypt-then-MAC requires the two keys to be
    cryptographically separate).

    Returns (aes_key: 32 bytes, mac_key: 32 bytes).
    """
    material = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=AES_KDF_DKLEN
    )
    return material[:32], material[32:]


def derive_vault_key(password: str, salt: bytes) -> bytes:
    """Public wrapper for deriving a 256-bit real-vault key from password+salt."""
    return _derive_key(password, salt)


def _mac_key_from_vault_key(vault_key: bytes) -> bytes:
    """Derive a deterministic HMAC key from a pre-derived 32-byte vault key."""
    return hashlib.sha256(vault_key + b':mac').digest()


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
# AES-256-CBC + HMAC-SHA256 Cipher (Encrypt-then-MAC) — Real Vault
# ---------------------------------------------------------------------------
def aes_encrypt(plaintext: bytes, password: str, salt: bytes) -> bytes:
    """
    Encrypts plaintext for the real vault using hand-implemented AES-256-CBC,
    then authenticates it with HMAC-SHA256 (Encrypt-then-MAC).

    Wire format: [ 16-byte IV || CBC ciphertext || 32-byte HMAC tag ]

    Args:
        plaintext : raw file bytes
        password  : the user's real password
        salt      : per-vault salt (distinct from the honeyset salt)

    Returns:
        Authenticated ciphertext blob
    """
    aes_key, mac_key = _derive_aes_keys(password, salt)
    iv_and_ciphertext = cbc_encrypt(plaintext, aes_key)
    tag = hmac.new(mac_key, iv_and_ciphertext, hashlib.sha256).digest()
    return iv_and_ciphertext + tag


def aes_decrypt(blob: bytes, password: str, salt: bytes) -> bytes:
    """
    Verifies and decrypts an AES-256-CBC + HMAC-SHA256 blob.

    Raises ValueError on authentication failure (tampered ciphertext or wrong key).

    Args:
        blob     : iv || ciphertext || tag (as returned by aes_encrypt)
        password : the user's real password
        salt     : same vault salt used during encryption

    Returns:
        Verified plaintext bytes
    """
    if len(blob) < AES_IV_SIZE + HMAC_TAG_SIZE:
        raise ValueError("Ciphertext blob is too short to contain IV + tag.")

    iv_and_ciphertext = blob[:-HMAC_TAG_SIZE]
    tag               = blob[-HMAC_TAG_SIZE:]

    aes_key, mac_key = _derive_aes_keys(password, salt)
    expected_tag = hmac.new(mac_key, iv_and_ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("HMAC authentication failed — ciphertext may be tampered or password is incorrect.")

    return cbc_decrypt(iv_and_ciphertext, aes_key)


def aes_decrypt_with_key(blob: bytes, key: bytes) -> bytes:
    """Decrypts and authenticates a CBC+HMAC blob with a pre-derived 32-byte key."""
    if len(blob) < AES_IV_SIZE + HMAC_TAG_SIZE:
        raise ValueError("Ciphertext blob is too short to contain IV + tag.")

    iv_and_ciphertext = blob[:-HMAC_TAG_SIZE]
    tag = blob[-HMAC_TAG_SIZE:]
    mac_key = _mac_key_from_vault_key(key)
    expected_tag = hmac.new(mac_key, iv_and_ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("HMAC authentication failed — ciphertext may be tampered or key is incorrect.")

    return cbc_decrypt(iv_and_ciphertext, key)


def aes_encrypt_with_key(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts plaintext into a CBC+HMAC blob using a pre-derived 32-byte key."""
    iv_and_ciphertext = cbc_encrypt(plaintext, key)
    mac_key = _mac_key_from_vault_key(key)
    tag = hmac.new(mac_key, iv_and_ciphertext, hashlib.sha256).digest()
    return iv_and_ciphertext + tag


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
