"""
aes256.py — Hand-rolled AES-256 block cipher (FIPS-197), CBC mode.
====================================================================
Secure-Doc · Layer 3 · Encryption Engine (from-scratch primitive)

Written from the FIPS-197 specification without any third-party crypto
library (no pycryptodome / cryptography). Only the Python standard
library (`os` for CSPRNG randomness) is used.

Implements:
  - AES-256 key expansion (Nk=8, Nr=14 rounds)
  - Single 16-byte block encryption / decryption (SubBytes, ShiftRows,
    MixColumns, AddRoundKey and their inverses)
  - CBC mode with PKCS7 padding on top of the block primitive

CBC provides confidentiality only — no authentication. Callers that need
tamper detection (see crypto_engine.py) must wrap this with a MAC
(Encrypt-then-MAC), which is what this project does.

Note: this is a straightforward, textbook byte-oriented implementation
chosen for clarity/auditability over raw speed. Pure-Python AES is
orders of magnitude slower than a hardware-accelerated C library —
expect kilobytes/sec-to-low-MB/sec throughput, not GB/sec.
"""

import os

# ---------------------------------------------------------------------------
# AES S-box and inverse S-box (FIPS-197, Figure 7)
# ---------------------------------------------------------------------------
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D]

BLOCK_SIZE = 16   # bytes
NK = 8            # 256-bit key = 8 words
NR = 14           # rounds for AES-256
NB = 4            # words per state (fixed for AES)


# ---------------------------------------------------------------------------
# GF(2^8) multiplication (used by MixColumns / InvMixColumns)
# ---------------------------------------------------------------------------
def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with the AES reduction polynomial x^8+x^4+x^3+x+1 (0x11B)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p

# Precomputed multiplication tables for the fixed constants MixColumns needs.
_GMUL2  = [_gmul(x, 2)  for x in range(256)]
_GMUL3  = [_gmul(x, 3)  for x in range(256)]
_GMUL9  = [_gmul(x, 9)  for x in range(256)]
_GMUL11 = [_gmul(x, 11) for x in range(256)]
_GMUL13 = [_gmul(x, 13) for x in range(256)]
_GMUL14 = [_gmul(x, 14) for x in range(256)]


# ---------------------------------------------------------------------------
# Key expansion (FIPS-197, Section 5.2)
# ---------------------------------------------------------------------------
def _key_expansion(key: bytes):
    """Expand a 32-byte AES-256 key into 15 round keys of 16 bytes each."""
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    w = [list(key[4 * i:4 * i + 4]) for i in range(NK)]

    for i in range(NK, NB * (NR + 1)):
        temp = list(w[i - 1])
        if i % NK == 0:
            temp = temp[1:] + temp[:1]                # RotWord
            temp = [SBOX[b] for b in temp]             # SubWord
            temp[0] ^= RCON[i // NK - 1]
        elif NK > 6 and i % NK == 4:
            temp = [SBOX[b] for b in temp]             # extra SubWord for 256-bit keys
        w.append([a ^ b for a, b in zip(w[i - NK], temp)])

    round_keys = []
    for r in range(NR + 1):
        rk = bytearray()
        for c in range(4):
            rk += bytes(w[r * 4 + c])
        round_keys.append(bytes(rk))
    return round_keys


# ---------------------------------------------------------------------------
# Round transformations. State is a 16-byte column-major array:
# state[row + 4*col] == FIPS-197 s[row][col]
# ---------------------------------------------------------------------------
def _sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]

def _inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_SBOX[state[i]]

def _shift_rows(state):
    orig = state[:]
    for r in range(4):
        for c in range(4):
            state[r + 4 * c] = orig[r + 4 * ((c + r) % 4)]

def _inv_shift_rows(state):
    orig = state[:]
    for r in range(4):
        for c in range(4):
            state[r + 4 * c] = orig[r + 4 * ((c - r) % 4)]

def _mix_columns(state):
    for c in range(4):
        i = 4 * c
        s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i]     = _GMUL2[s0] ^ _GMUL3[s1] ^ s2 ^ s3
        state[i + 1] = s0 ^ _GMUL2[s1] ^ _GMUL3[s2] ^ s3
        state[i + 2] = s0 ^ s1 ^ _GMUL2[s2] ^ _GMUL3[s3]
        state[i + 3] = _GMUL3[s0] ^ s1 ^ s2 ^ _GMUL2[s3]

def _inv_mix_columns(state):
    for c in range(4):
        i = 4 * c
        s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i]     = _GMUL14[s0] ^ _GMUL11[s1] ^ _GMUL13[s2] ^ _GMUL9[s3]
        state[i + 1] = _GMUL9[s0]  ^ _GMUL14[s1] ^ _GMUL11[s2] ^ _GMUL13[s3]
        state[i + 2] = _GMUL13[s0] ^ _GMUL9[s1]  ^ _GMUL14[s2] ^ _GMUL11[s3]
        state[i + 3] = _GMUL11[s0] ^ _GMUL13[s1] ^ _GMUL9[s2]  ^ _GMUL14[s3]

def _add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]


# ---------------------------------------------------------------------------
# Single-block encrypt / decrypt
# ---------------------------------------------------------------------------
def _encrypt_block(block: bytes, round_keys) -> bytes:
    state = bytearray(block)
    _add_round_key(state, round_keys[0])
    for r in range(1, NR):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[NR])
    return bytes(state)

def _decrypt_block(block: bytes, round_keys) -> bytes:
    state = bytearray(block)
    _add_round_key(state, round_keys[NR])
    for r in range(NR - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)


# ---------------------------------------------------------------------------
# PKCS7 padding
# ---------------------------------------------------------------------------
def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded ciphertext length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding.")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# Public CBC mode API
# ---------------------------------------------------------------------------
def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
    """
    Encrypts plaintext with AES-256-CBC. Returns iv || ciphertext.
    A random 16-byte IV is generated per call unless one is supplied.
    """
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    elif len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes.")

    round_keys = _key_expansion(key)
    padded = _pkcs7_pad(plaintext)

    out = bytearray()
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(padded[i:i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, round_keys)
        out += enc
        prev = enc
    return iv + bytes(out)

def cbc_decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypts an iv || ciphertext blob produced by cbc_encrypt."""
    if len(blob) < BLOCK_SIZE or (len(blob) - BLOCK_SIZE) % BLOCK_SIZE != 0:
        raise ValueError("Invalid AES-CBC blob length.")

    iv = blob[:BLOCK_SIZE]
    ciphertext = blob[BLOCK_SIZE:]
    round_keys = _key_expansion(key)

    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = _decrypt_block(block, round_keys)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return _pkcs7_unpad(bytes(out))
