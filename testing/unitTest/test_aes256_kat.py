"""
test_aes256_kat.py — Proof that our from-scratch AES-256 is real AES
=====================================================================
Known-Answer Tests (KAT) for tools/aes256.py and tools/crypto_engine.py.

The important tests here are NOT round-trips (any reversible scramble
round-trips). They are the OFFICIAL standardized vectors:

  * FIPS-197  Appendix C.3  — AES-256 single-block encrypt/decrypt.
  * NIST SP 800-38A F.2.5/6 — AES-256-CBC multi-block encrypt/decrypt.

A conformant AES implementation MUST reproduce these exact ciphertexts.
If ours does, it is genuine AES-256, not a homemade cipher that merely
looks encrypted. The remaining tests prove diffusion (it actually
scrambles), the random-IV property, and the authenticated crypto_engine
wrapper (tamper / wrong-password rejection).

Run:
    python testing/unitTest/test_aes256_kat.py            # verbose proof
    python -m unittest testing.unitTest.test_aes256_kat   # quiet
"""

import os
import sys
import unittest

# Make tools/ importable regardless of where the test is launched from.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_REPO_ROOT, 'tools'))

from aes256 import (
    _key_expansion, _encrypt_block, _decrypt_block,
    cbc_encrypt, cbc_decrypt, BLOCK_SIZE,
)
from crypto_engine import aes_encrypt, aes_decrypt


def _h(b: bytes) -> str:
    return b.hex()


# ---------------------------------------------------------------------------
# Official test vectors (copied verbatim from the standards documents)
# ---------------------------------------------------------------------------

# FIPS-197, Appendix C.3 — AES-256
FIPS_KEY = bytes.fromhex('000102030405060708090a0b0c0d0e0f'
                         '101112131415161718191a1b1c1d1e1f')
FIPS_PT  = bytes.fromhex('00112233445566778899aabbccddeeff')
FIPS_CT  = bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')

# NIST SP 800-38A, Section F.2.5 (encrypt) / F.2.6 (decrypt) — CBC-AES256
NIST_KEY = bytes.fromhex('603deb1015ca71be2b73aef0857d7781'
                         '1f352c073b6108d72d9810a30914dff4')
NIST_IV  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
NIST_PT_BLOCKS = [
    bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'),
    bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51'),
    bytes.fromhex('30c81c46a35ce411e5fbc1191a0a52ef'),
    bytes.fromhex('f69f2445df4f9b17ad2b417be66c3710'),
]
NIST_CT_BLOCKS = [
    bytes.fromhex('f58c4c04d6e5f1ba779eabfb5f7bfbd6'),
    bytes.fromhex('9cfc4e967edb808d679f777bc6702c7d'),
    bytes.fromhex('39f23369a9d9bacfa530e26304231461'),
    bytes.fromhex('b2eb05e2c39be9fcda6c19078c6a9d1b'),
]
NIST_PT = b''.join(NIST_PT_BLOCKS)
NIST_CT = b''.join(NIST_CT_BLOCKS)


class FIPS197SingleBlock(unittest.TestCase):
    """The canonical AES-256 known-answer test."""

    def test_encrypt_matches_fips197_c3(self):
        rk = _key_expansion(FIPS_KEY)
        ct = _encrypt_block(FIPS_PT, rk)
        self.assertEqual(
            ct, FIPS_CT,
            f"\n  expected {_h(FIPS_CT)}\n  got      {_h(ct)}"
        )

    def test_decrypt_matches_fips197_c3(self):
        rk = _key_expansion(FIPS_KEY)
        pt = _decrypt_block(FIPS_CT, rk)
        self.assertEqual(pt, FIPS_PT, f"\n  expected {_h(FIPS_PT)}\n  got {_h(pt)}")

    def test_key_expansion_shape(self):
        rk = _key_expansion(FIPS_KEY)
        self.assertEqual(len(rk), 15)                 # 14 rounds + 1
        self.assertTrue(all(len(k) == 16 for k in rk))
        self.assertEqual(rk[0], FIPS_KEY[:16])        # round key 0 == first half of key


class NISTCBC256(unittest.TestCase):
    """Official CBC-mode multi-block vectors — proves chaining is standard."""

    def test_cbc_encrypt_matches_nist(self):
        # cbc_encrypt returns iv || ciphertext, and PKCS7-pads (adds one block).
        # The first 4 ciphertext blocks must equal the NIST vector exactly.
        blob = cbc_encrypt(NIST_PT, NIST_KEY, iv=NIST_IV)
        self.assertEqual(blob[:BLOCK_SIZE], NIST_IV)
        produced = blob[BLOCK_SIZE:BLOCK_SIZE + len(NIST_CT)]
        self.assertEqual(
            produced, NIST_CT,
            f"\n  expected {_h(NIST_CT)}\n  got      {_h(produced)}"
        )

    def test_cbc_decrypt_matches_nist(self):
        # Inverse cipher against the standard: recover each PT block from the
        # known CT blocks using the documented CBC decrypt relation.
        rk = _key_expansion(NIST_KEY)
        prev = NIST_IV
        for pt_expected, ct in zip(NIST_PT_BLOCKS, NIST_CT_BLOCKS):
            dec = _decrypt_block(ct, rk)
            pt = bytes(a ^ b for a, b in zip(dec, prev))
            self.assertEqual(pt, pt_expected)
            prev = ct


class DiffusionAndRandomness(unittest.TestCase):
    """Evidence that it genuinely encrypts, not just reorders bytes."""

    def test_ciphertext_differs_from_plaintext(self):
        key = os.urandom(32)
        pt = b"attack at dawn -- top secret orders" * 4
        blob = cbc_encrypt(pt, key)
        self.assertNotIn(pt, blob)

    def test_constant_input_yields_random_looking_output(self):
        # 4 KB of identical bytes. A weak cipher (e.g. plain XOR) would leave
        # a visible repeating pattern; real AES-CBC produces ~uniform bytes.
        key = os.urandom(32)
        blob = cbc_encrypt(b'\x00' * 4096, key)
        body = blob[BLOCK_SIZE:]                      # drop the IV
        self.assertGreater(len(set(body)), 240,       # near all 256 values seen
                           "ciphertext of constant input is not diffuse enough")

    def test_avalanche_one_bit_flip(self):
        # Fixed IV so the only change is the single plaintext bit.
        key = os.urandom(32)
        iv = os.urandom(16)
        pt = bytearray(b'A' * 64)
        c1 = cbc_encrypt(bytes(pt), key, iv=iv)[BLOCK_SIZE:]
        pt[0] ^= 0x01                                 # flip one bit
        c2 = cbc_encrypt(bytes(pt), key, iv=iv)[BLOCK_SIZE:]
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(c1, c2))
        frac = diff_bits / (len(c1) * 8)
        self.assertTrue(0.40 < frac < 0.60,
                        f"avalanche fraction {frac:.3f} outside [0.40, 0.60]")

    def test_random_iv_makes_each_encryption_unique(self):
        key = os.urandom(32)
        pt = b"same message every time"
        self.assertNotEqual(cbc_encrypt(pt, key), cbc_encrypt(pt, key))


class RoundTrips(unittest.TestCase):
    """Correctness across sizes, including PKCS7 padding edge cases."""

    def test_various_lengths_roundtrip(self):
        key = os.urandom(32)
        for n in [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000]:
            pt = os.urandom(n)
            self.assertEqual(cbc_decrypt(cbc_encrypt(pt, key), key), pt,
                             f"round-trip failed at length {n}")

    def test_exact_block_multiple_adds_full_pad_block(self):
        key = os.urandom(32)
        pt = os.urandom(48)                           # exact 3 blocks
        blob = cbc_encrypt(pt, key)
        # iv(16) + 3 data blocks + 1 full PKCS7 pad block = 16 + 64
        self.assertEqual(len(blob), 16 + 64)
        self.assertEqual(cbc_decrypt(blob, key), pt)


class AuthenticatedEngine(unittest.TestCase):
    """crypto_engine wrapper: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)."""

    PW = "S0me-Real-Vault-Password!"
    SALT = b'\x11' * 16

    def test_engine_roundtrip(self):
        pt = b"quarterly financials, board-eyes only"
        blob = aes_encrypt(pt, self.PW, self.SALT)
        self.assertEqual(aes_decrypt(blob, self.PW, self.SALT), pt)

    def test_tampered_ciphertext_is_rejected(self):
        blob = bytearray(aes_encrypt(b"integrity matters", self.PW, self.SALT))
        blob[20] ^= 0x01                              # flip one byte mid-ciphertext
        with self.assertRaises(ValueError):
            aes_decrypt(bytes(blob), self.PW, self.SALT)

    def test_wrong_password_is_rejected(self):
        blob = aes_encrypt(b"confidential", self.PW, self.SALT)
        with self.assertRaises(ValueError):
            aes_decrypt(blob, "wrong-password", self.SALT)


def _proof_banner():
    """Print the headline KAT comparison so the match is visible to a human."""
    rk = _key_expansion(FIPS_KEY)
    ct = _encrypt_block(FIPS_PT, rk)
    print("\n" + "=" * 68)
    print("  FIPS-197 Appendix C.3  —  AES-256 known-answer test")
    print("=" * 68)
    print(f"  key        : {_h(FIPS_KEY)}")
    print(f"  plaintext  : {_h(FIPS_PT)}")
    print(f"  expected CT: {_h(FIPS_CT)}   (from the standard)")
    print(f"  our CT     : {_h(ct)}")
    print(f"  MATCH      : {ct == FIPS_CT}")
    print("-" * 68)
    blob = cbc_encrypt(NIST_PT, NIST_KEY, iv=NIST_IV)
    produced = blob[BLOCK_SIZE:BLOCK_SIZE + len(NIST_CT)]
    print("  NIST SP 800-38A F.2.5  —  AES-256-CBC (4 blocks)")
    print(f"  expected CT: {_h(NIST_CT)}")
    print(f"  our CT     : {_h(produced)}")
    print(f"  MATCH      : {produced == NIST_CT}")
    print("=" * 68 + "\n")


if __name__ == '__main__':
    _proof_banner()
    unittest.main(verbosity=2)
