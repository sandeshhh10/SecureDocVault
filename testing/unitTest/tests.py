"""
Unit Tests for Secure-Doc
==========================
Comprehensive test suite for core security components.

Coverage:
  - crypto_engine.py : XOR & AES encryption/decryption
  - honey_checker.py : PBKDF2 hashing, honeyword generation, login logic
  - Basic Flask routes
"""

import unittest
import sqlite3
import os
import sys
import tempfile
import json
import secrets
import uuid
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

# Add tools directory to path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(ROOT_DIR, 'tools'))

from crypto_engine import (
    xor_encrypt, xor_decrypt,
    aes_encrypt, aes_decrypt,
    derive_vault_key,
    _derive_key,
    PBKDF2_ITERATIONS, PBKDF2_DKLEN
)
from honey_checker import (
    _derive_hash, check_login, register_user, get_user_salts,
    _generate_decoy_passwords,
    PBKDF2_ITERATIONS as HC_PBKDF2_ITERATIONS,
    PBKDF2_DKLEN as HC_PBKDF2_DKLEN,
    HONEY_N
)


# =============================================================================
# Test Suite 1: Cryptographic Functions
# =============================================================================
class TestCryptoEngine(unittest.TestCase):
    """Test suite for crypto_engine.py"""

    def setUp(self):
        """Initialize test fixtures."""
        self.password = "TestPassword123!"
        self.salt = os.urandom(32)
        self.plaintext = b"This is a secret message."
        self.key = _derive_key(self.password, self.salt)

    def test_derive_key_deterministic(self):
        """Key derivation should be deterministic."""
        key1 = _derive_key(self.password, self.salt)
        key2 = _derive_key(self.password, self.salt)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), PBKDF2_DKLEN)

    def test_derive_key_different_passwords(self):
        """Different passwords should produce different keys."""
        key1 = _derive_key("password1", self.salt)
        key2 = _derive_key("password2", self.salt)
        self.assertNotEqual(key1, key2)

    def test_derive_key_different_salts(self):
        """Different salts should produce different keys."""
        salt2 = os.urandom(32)
        key1 = _derive_key(self.password, self.salt)
        key2 = _derive_key(self.password, salt2)
        self.assertNotEqual(key1, key2)

    def test_xor_encrypt_decrypt_roundtrip(self):
        """XOR encryption should be reversible."""
        ciphertext = xor_encrypt(self.plaintext, self.password, self.salt)
        decrypted = xor_decrypt(ciphertext, self.password, self.salt)
        self.assertEqual(self.plaintext, decrypted)

    def test_xor_ciphertext_length(self):
        """XOR ciphertext should be same length as plaintext."""
        ciphertext = xor_encrypt(self.plaintext, self.password, self.salt)
        self.assertEqual(len(ciphertext), len(self.plaintext))

    def test_xor_different_passwords_different_ciphertext(self):
        """Same plaintext with different passwords → different ciphertext."""
        cipher1 = xor_encrypt(self.plaintext, "pass1", self.salt)
        cipher2 = xor_encrypt(self.plaintext, "pass2", self.salt)
        self.assertNotEqual(cipher1, cipher2)

    def test_xor_empty_plaintext(self):
        """XOR should handle empty plaintext."""
        plaintext = b""
        ciphertext = xor_encrypt(plaintext, self.password, self.salt)
        decrypted = xor_decrypt(ciphertext, self.password, self.salt)
        self.assertEqual(plaintext, decrypted)

    def test_xor_large_plaintext(self):
        """XOR should handle large plaintext (1 MB)."""
        large_plaintext = os.urandom(1024 * 1024)
        ciphertext = xor_encrypt(large_plaintext, self.password, self.salt)
        decrypted = xor_decrypt(ciphertext, self.password, self.salt)
        self.assertEqual(large_plaintext, decrypted)

    def test_aes_encrypt_decrypt_roundtrip(self):
        """AES encryption should be reversible."""
        ciphertext = aes_encrypt(self.plaintext, self.password, self.salt)
        decrypted = aes_decrypt(ciphertext, self.password, self.salt)
        self.assertEqual(self.plaintext, decrypted)

    def test_aes_ciphertext_includes_nonce_and_tag(self):
        """AES ciphertext should include 16-byte IV and 32-byte HMAC tag."""
        ciphertext = aes_encrypt(self.plaintext, self.password, self.salt)
        # Format: [16-byte IV][CBC ciphertext, PKCS7-padded][32-byte HMAC-SHA256 tag]
        self.assertGreaterEqual(len(ciphertext), 16 + len(self.plaintext) + 32)

    def test_aes_different_encryptions_different_ciphertext(self):
        """Two AES encryptions should produce different ciphertexts (random nonce)."""
        cipher1 = aes_encrypt(self.plaintext, self.password, self.salt)
        cipher2 = aes_encrypt(self.plaintext, self.password, self.salt)
        self.assertNotEqual(cipher1, cipher2)

    def test_aes_wrong_password_fails(self):
        """Decryption with wrong password should fail (HMAC auth)."""
        ciphertext = aes_encrypt(self.plaintext, self.password, self.salt)
        with self.assertRaises(ValueError):
            aes_decrypt(ciphertext, "wrongpassword", self.salt)

    def test_aes_tampered_ciphertext_fails(self):
        """Tampering with ciphertext should be detected (HMAC auth)."""
        ciphertext = aes_encrypt(self.plaintext, self.password, self.salt)
        tampered = bytearray(ciphertext)
        # Flip a bit in the middle
        tampered[len(tampered) // 2] ^= 0xFF
        with self.assertRaises(ValueError):
            aes_decrypt(bytes(tampered), self.password, self.salt)

    def test_aes_empty_plaintext(self):
        """AES should handle empty plaintext."""
        plaintext = b""
        ciphertext = aes_encrypt(plaintext, self.password, self.salt)
        decrypted = aes_decrypt(ciphertext, self.password, self.salt)
        self.assertEqual(plaintext, decrypted)

    def test_aes_large_plaintext(self):
        """AES should handle larger plaintext (256 KB).

        Sized down from 10 MB: AES is now a hand-rolled, pure-Python
        block cipher (tools/aes256.py) instead of a hardware-accelerated
        C library, so throughput is orders of magnitude lower. 256 KB is
        still enough to exercise many CBC blocks without making the
        suite slow.
        """
        large_plaintext = os.urandom(256 * 1024)
        ciphertext = aes_encrypt(large_plaintext, self.password, self.salt)
        decrypted = aes_decrypt(ciphertext, self.password, self.salt)
        self.assertEqual(large_plaintext, decrypted)


# =============================================================================
# Test Suite 2: Password & Honeyword Functions
# =============================================================================
class TestHoneyChecker(unittest.TestCase):
    """Test suite for honey_checker.py"""

    def setUp(self):
        """Set up test database."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self._init_test_db()

    def tearDown(self):
        """Clean up test database."""
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def _init_test_db(self):
        """Initialize minimal test database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                honeyset_salt TEXT NOT NULL,
                vault_salt TEXT NOT NULL,
                alert_level TEXT DEFAULT 'LOW'
            )
        ''')
        
        # Create honeysets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeysets (
                user_id TEXT NOT NULL,
                hash_index INTEGER NOT NULL,
                hash_value TEXT NOT NULL,
                PRIMARY KEY (user_id, hash_index),
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        # Create real_index table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS real_index (
                user_id TEXT PRIMARY KEY,
                real_idx INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def test_derive_hash_deterministic(self):
        """Hash derivation should be deterministic."""
        password = "TestPassword"
        salt = os.urandom(32)
        hash1 = _derive_hash(password, salt)
        hash2 = _derive_hash(password, salt)
        self.assertEqual(hash1, hash2)

    def test_derive_hash_format(self):
        """Hash should be valid hex string of correct length."""
        password = "TestPassword"
        salt = os.urandom(32)
        hash_val = _derive_hash(password, salt)
        # Hex string should be 2 chars per byte
        self.assertEqual(len(hash_val), PBKDF2_DKLEN * 2)
        # Should be valid hex
        bytes.fromhex(hash_val)

    def test_generate_honeyset_creates_n_hashes(self):
        """_generate_decoy_passwords should create HONEY_N-1 unique passwords."""
        decoys = _generate_decoy_passwords(HONEY_N - 1)
        self.assertEqual(len(decoys), HONEY_N - 1)
        # All decoys should be unique
        self.assertEqual(len(set(decoys)), HONEY_N - 1)

    def test_decoy_passwords_are_strings(self):
        """Generated decoy passwords should be non-empty strings."""
        decoys = _generate_decoy_passwords(10)
        self.assertTrue(all(isinstance(d, str) and len(d) > 0 for d in decoys))

    def test_decoy_passwords_variety(self):
        """Decoy passwords should show variety across calls."""
        set1 = _generate_decoy_passwords(10)
        set2 = _generate_decoy_passwords(10)
        # Sets should be different due to randomness
        self.assertNotEqual(set1, set2)


# =============================================================================
# Test Suite 3: Flask Integration Tests
# =============================================================================
class TestFlaskRoutes(unittest.TestCase):
    """Test suite for Flask app routes."""

    def setUp(self):
        """Set up Flask test client."""
        # Import app here to avoid issues if dependencies aren't loaded
        try:
            import app as app_module
            self.app_module = app_module
            self.app = app_module.app
            self.client = self.app.test_client()
            self.app.config['TESTING'] = True
            self.app_module._clear_all_real_vault_sessions()
        except ImportError:
            self.skipTest("Flask app not importable")

    def tearDown(self):
        if hasattr(self, 'app_module'):
            self.app_module._clear_all_real_vault_sessions()

    def _set_honey_session(self, user_id, honey_pw='HoneyPw!23'):
        with self.client.session_transaction() as sess:
            sess['user_id'] = user_id
            sess['username'] = 'tester'
            sess['vault_mode'] = 'decoy'
            sess['honey_pw'] = honey_pw
            sess['phantom_hidden'] = []
            sess['phantom_uploaded'] = []

    def _set_real_session(self, user_id, vault_salt, real_pw='RealPw!23'):
        session_token = self.app_module._create_real_vault_session(user_id, derive_vault_key(real_pw, vault_salt))
        with self.client.session_transaction() as sess:
            sess['user_id'] = user_id
            sess['username'] = 'tester'
            sess['vault_mode'] = 'real'
            sess['session_token'] = session_token
        return session_token

    def _make_decoy_file(self, user_id, filename, plaintext, honey_pw, salt):
        vault_dir = os.path.join(self.app_module.BASE_DIR, 'vault', 'decoy', user_id)
        os.makedirs(vault_dir, exist_ok=True)
        file_path = os.path.join(vault_dir, filename)
        with open(file_path, 'wb') as f:
            f.write(xor_encrypt(plaintext, honey_pw, salt))
        return vault_dir, file_path

    def test_login_page_loads(self):
        """GET /login should render login form."""
        response = self.client.get('/login')
        self.assertIn(response.status_code, [200, 302])  # 302 if redirects to login

    def test_root_redirects(self):
        """GET / should redirect to login."""
        response = self.client.get('/')
        self.assertIn(response.status_code, [301, 302, 307, 308])

    def test_invalid_route_404(self):
        """GET /nonexistent should return 404."""
        response = self.client.get('/nonexistent-route')
        self.assertEqual(response.status_code, 404)

    def test_logout_clears_session(self):
        """POST /logout should clear session."""
        with self.client:
            response = self.client.post('/logout')
            # Should redirect
            self.assertIn(response.status_code, [301, 302, 307, 308])

    def test_honey_download_returns_decrypted_decoy_file(self):
        """GET /download/<filename> should decrypt and return the decoy file."""
        user_id = uuid.uuid4().hex
        filename = 'example.txt'
        honey_pw = 'HoneyPw!23'
        salt = os.urandom(32)
        plaintext = b'example decoy content'
        vault_dir, file_path = self._make_decoy_file(user_id, filename, plaintext, honey_pw, salt)

        try:
            with patch('app.get_user_salts', return_value={'honeyset_salt': salt}), \
                 patch('app.check_and_heal', return_value=None):
                self._set_honey_session(user_id, honey_pw)
                response = self.client.get(f'/download/{filename}')

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, plaintext)
            self.assertIn('attachment', response.headers.get('Content-Disposition', '').lower())
            self.assertIn(filename, response.headers.get('Content-Disposition', ''))
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.isdir(vault_dir):
                try:
                    os.rmdir(vault_dir)
                except OSError:
                    pass

    def test_honey_delete_hides_file_without_removing_it(self):
        """Honey delete should hide the file from the dashboard but keep it on disk."""
        user_id = uuid.uuid4().hex
        filename = 'hidden.txt'
        honey_pw = 'HoneyPw!23'
        salt = os.urandom(32)
        vault_dir, file_path = self._make_decoy_file(user_id, filename, b'hidden content', honey_pw, salt)

        try:
            with patch('app.get_user_salts', return_value={'honeyset_salt': salt}), \
                 patch('app.check_and_heal', return_value=None):
                self._set_honey_session(user_id, honey_pw)
                response = self.client.post(f'/delete/{filename}', follow_redirects=True)

            self.assertTrue(os.path.exists(file_path))
            self.assertEqual(response.status_code, 200)

            with self.client.session_transaction() as sess:
                self.assertIn(filename, sess.get('phantom_hidden', []))

            dashboard = self.client.get('/dashboard')
            self.assertEqual(dashboard.status_code, 200)
            self.assertNotIn(filename, dashboard.get_data(as_text=True))
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.isdir(vault_dir):
                try:
                    os.rmdir(vault_dir)
                except OSError:
                    pass

    def test_honey_upload_discards_stream_and_lists_phantom_file(self):
        """Honey upload should not write to disk but should appear in the dashboard."""
        user_id = uuid.uuid4().hex
        filename = 'uploaded.txt'
        honey_pw = 'HoneyPw!23'
        salt = os.urandom(32)
        vault_dir = os.path.join(self.app_module.BASE_DIR, 'vault', 'decoy', user_id)
        os.makedirs(vault_dir, exist_ok=True)
        file_path = os.path.join(vault_dir, filename)

        try:
            with patch('app.get_user_salts', return_value={'honeyset_salt': salt}), \
                 patch('app.check_and_heal', return_value=None):
                self._set_honey_session(user_id, honey_pw)
                response = self.client.post(
                    '/upload',
                    data={'file': (BytesIO(b'uploaded phantom content'), filename)},
                    content_type='multipart/form-data',
                    follow_redirects=True,
                )

            self.assertFalse(os.path.exists(file_path))
            self.assertEqual(response.status_code, 200)
            self.assertIn(filename, response.get_data(as_text=True))

            with self.client.session_transaction() as sess:
                phantom_uploaded = sess.get('phantom_uploaded', [])
                self.assertEqual(len(phantom_uploaded), 1)
                self.assertEqual(phantom_uploaded[0]['filename'], filename)
                self.assertGreater(phantom_uploaded[0]['size'], 0)
        finally:
            if os.path.isdir(vault_dir):
                try:
                    os.rmdir(vault_dir)
                except OSError:
                    pass

    def test_real_upload_encrypts_file_at_rest_and_downloads_plaintext(self):
        """Real upload should store AES-encrypted bytes and download the original plaintext."""
        user_id = uuid.uuid4().hex
        filename = 'secret.txt'
        real_pw = 'RealPw!23'
        vault_salt = os.urandom(32)
        plaintext = b'real file content'
        vault_dir = os.path.join(self.app_module.BASE_DIR, 'vault', 'real', user_id)
        os.makedirs(vault_dir, exist_ok=True)
        file_path = os.path.join(vault_dir, filename)

        try:
            with patch('app.get_user_salts', return_value={'vault_salt': vault_salt, 'honeyset_salt': os.urandom(32)}):
                session_token = self._set_real_session(user_id, vault_salt, real_pw)
                upload_response = self.client.post(
                    '/upload',
                    data={'file': (BytesIO(plaintext), filename)},
                    content_type='multipart/form-data',
                    follow_redirects=True,
                )

            self.assertEqual(upload_response.status_code, 200)
            self.assertTrue(os.path.exists(file_path))

            conn = sqlite3.connect(self.app_module.DB_PATH)
            row = conn.execute(
                f'SELECT vault_key FROM {self.app_module.REAL_SESSION_TABLE} WHERE session_token=?',
                (session_token,)
            ).fetchone()
            conn.close()
            self.assertIsNotNone(row)

            with open(file_path, 'rb') as f:
                on_disk = f.read()

            self.assertNotEqual(on_disk, plaintext)
            self.assertEqual(aes_decrypt(on_disk, real_pw, vault_salt), plaintext)

            with patch('app.get_user_salts', return_value={'vault_salt': vault_salt, 'honeyset_salt': os.urandom(32)}):
                download_response = self.client.get(f'/download/{filename}')

            self.assertEqual(download_response.status_code, 200)
            self.assertEqual(download_response.data, plaintext)

            self.client.post('/logout')
            conn = sqlite3.connect(self.app_module.DB_PATH)
            row = conn.execute(
                f'SELECT 1 FROM {self.app_module.REAL_SESSION_TABLE} WHERE session_token=?',
                (session_token,)
            ).fetchone()
            conn.close()
            self.assertIsNone(row)
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.isdir(vault_dir):
                try:
                    os.rmdir(vault_dir)
                except OSError:
                    pass

    def test_logout_and_relogin_reset_phantom_state(self):
        """Logout should clear phantom state so a fresh honey session starts clean."""
        user_id = uuid.uuid4().hex
        filename = 'reset.txt'
        honey_pw = 'HoneyPw!23'
        salt = os.urandom(32)
        vault_dir, file_path = self._make_decoy_file(user_id, filename, b'reset content', honey_pw, salt)

        try:
            with patch('app.get_user_salts', return_value={'honeyset_salt': salt}), \
                 patch('app.check_and_heal', return_value=None):
                self._set_honey_session(user_id, honey_pw)

                with self.client.session_transaction() as sess:
                    sess['phantom_hidden'] = [filename]
                    sess['phantom_uploaded'] = [{'filename': 'old.txt', 'size': 3, 'uploaded_at': '2026-06-30T00:00:00+00:00'}]

                self.client.post('/logout')

                self._set_honey_session(user_id, honey_pw)
                response = self.client.get('/dashboard')

            self.assertEqual(response.status_code, 200)
            self.assertIn(filename, response.get_data(as_text=True))

            with self.client.session_transaction() as sess:
                self.assertEqual(sess.get('phantom_hidden', []), [])
                self.assertEqual(sess.get('phantom_uploaded', []), [])
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.isdir(vault_dir):
                try:
                    os.rmdir(vault_dir)
                except OSError:
                    pass


# =============================================================================
# Test Suite 4: Edge Cases & Security Properties
# =============================================================================
class TestSecurityProperties(unittest.TestCase):
    """Test security invariants and edge cases."""

    def setUp(self):
        self.password = "TestPassword123!"
        self.salt = os.urandom(32)

    def test_xor_is_symmetric(self):
        """XOR encryption and decryption should be symmetric."""
        plaintext = b"Hello"
        encrypted = xor_encrypt(plaintext, self.password, self.salt)
        # XOR with same key again should give plaintext
        decrypted = xor_decrypt(encrypted, self.password, self.salt)
        self.assertEqual(plaintext, decrypted)

    def test_pbkdf2_iterations_configured(self):
        """PBKDF2 should use configured iteration count."""
        # This is more of a documentation test
        self.assertEqual(HC_PBKDF2_ITERATIONS, 200_000)

    def test_honeyword_set_includes_decoys(self):
        """Decoy password generation should work correctly."""
        honeyset = _generate_decoy_passwords(HONEY_N - 1)
        # At least 19 decoys
        self.assertEqual(len(honeyset), HONEY_N - 1)

    def test_encryption_all_bytes(self):
        """Encryption should handle all byte values (0-255)."""
        plaintext = bytes(range(256))
        ciphertext_xor = xor_encrypt(plaintext, self.password, self.salt)
        decrypted_xor = xor_decrypt(ciphertext_xor, self.password, self.salt)
        self.assertEqual(plaintext, decrypted_xor)

        ciphertext_aes = aes_encrypt(plaintext, self.password, self.salt)
        decrypted_aes = aes_decrypt(ciphertext_aes, self.password, self.salt)
        self.assertEqual(plaintext, decrypted_aes)

    def test_unicode_password_support(self):
        """Passwords with Unicode characters should work."""
        unicode_password = "Pässwörd_你好_🔐"
        plaintext = b"Secret data"
        
        ciphertext_xor = xor_encrypt(plaintext, unicode_password, self.salt)
        decrypted_xor = xor_decrypt(ciphertext_xor, unicode_password, self.salt)
        self.assertEqual(plaintext, decrypted_xor)

        ciphertext_aes = aes_encrypt(plaintext, unicode_password, self.salt)
        decrypted_aes = aes_decrypt(ciphertext_aes, unicode_password, self.salt)
        self.assertEqual(plaintext, decrypted_aes)

    def test_no_information_leakage_in_key(self):
        """Changing one bit of password should avalanche the key."""
        password1 = "password"
        password2 = "passwore"  # One char different
        
        key1 = _derive_key(password1, self.salt)
        key2 = _derive_key(password2, self.salt)
        
        # Keys should be completely different
        self.assertNotEqual(key1, key2)
        # Most bits should differ (avalanche effect)
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(key1, key2))
        self.assertGreater(diff_bits, 50)  # Should have high Hamming distance


# =============================================================================
# Test Suite 5: Integration & Workflow Tests
# =============================================================================
class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows."""

    def setUp(self):
        """Set up test fixtures."""
        self.password = "UserPassword123!"
        self.salt = os.urandom(32)
        self.test_file = b"This is a test document content."

    def test_xor_vault_workflow(self):
        """Test complete XOR (honey vault) encryption workflow."""
        # Simulate multiple honeywords for same user
        honeyword1 = "honey_word_1"
        honeyword2 = "honey_word_2"
        
        # Both honeywords encrypt the same file with same salt
        cipher1 = xor_encrypt(self.test_file, honeyword1, self.salt)
        cipher2 = xor_encrypt(self.test_file, honeyword2, self.salt)
        
        # Ciphertexts should be different
        self.assertNotEqual(cipher1, cipher2)
        
        # Each should decrypt with its own honeyword
        self.assertEqual(xor_decrypt(cipher1, honeyword1, self.salt), self.test_file)
        self.assertEqual(xor_decrypt(cipher2, honeyword2, self.salt), self.test_file)
        
        # Cross-decryption produces garbage (as designed for plausibility)
        garbage = xor_decrypt(cipher1, honeyword2, self.salt)
        self.assertNotEqual(garbage, self.test_file)

    def test_aes_vault_security_workflow(self):
        """Test complete AES (real vault) encryption security workflow."""
        real_password = "RealPassword123!"
        
        # Encrypt file
        ciphertext = aes_encrypt(self.test_file, real_password, self.salt)
        
        # Verify it decrypts correctly
        plaintext = aes_decrypt(ciphertext, real_password, self.salt)
        self.assertEqual(plaintext, self.test_file)
        
        # Verify other passwords fail
        for wrong_password in ["WrongPassword", "wrong", "", "real_PASSWORD123!"]:
            with self.assertRaises(ValueError):
                aes_decrypt(ciphertext, wrong_password, self.salt)

    def test_multi_file_encryption_same_key(self):
        """Test encrypting multiple files with same key."""
        files = [
            b"File 1 content",
            b"File 2 with different content",
            b"",
            os.urandom(256),
            b"x" * 10000
        ]
        
        ciphertexts = []
        for file_content in files:
            ct = aes_encrypt(file_content, self.password, self.salt)
            ciphertexts.append(ct)
            
            # Verify decryption
            pt = aes_decrypt(ct, self.password, self.salt)
            self.assertEqual(pt, file_content)
        
        # All ciphertexts should be different (random nonces)
        self.assertEqual(len(set(ciphertexts)), len(ciphertexts))

    def test_salt_isolation(self):
        """Test that different salts produce different results."""
        salt1 = os.urandom(32)
        salt2 = os.urandom(32)
        
        # Same password + different salts = different keys
        cipher1 = aes_encrypt(self.test_file, self.password, salt1)
        cipher2 = aes_encrypt(self.test_file, self.password, salt2)
        
        self.assertNotEqual(cipher1, cipher2)
        
        # Cross-decryption fails
        with self.assertRaises(ValueError):
            aes_decrypt(cipher1, self.password, salt2)


# =============================================================================
# Test Suite 6: Regression Tests
# =============================================================================
class TestRegressions(unittest.TestCase):
    """Regression tests for known issues."""

    def test_xor_maintains_length_exactly(self):
        """Verify XOR output is exactly plaintext length (no padding)."""
        for length in [0, 1, 31, 32, 33, 100, 255, 256, 1000]:
            plaintext = os.urandom(length)
            ciphertext = xor_encrypt(plaintext, "test", os.urandom(32))
            self.assertEqual(len(ciphertext), length, 
                           f"XOR failed for length {length}")

    def test_aes_nonce_prepended_correctly(self):
        """Verify AES nonce is at the beginning of ciphertext."""
        plaintext = b"test"
        salt = os.urandom(32)
        ciphertext = aes_encrypt(plaintext, "password", salt)
        
        # Should be: [16-byte nonce][CT][16-byte tag]
        self.assertGreaterEqual(len(ciphertext), 32)  # nonce + tag
        
        # Extract nonce and verify it's 16 bytes
        nonce = ciphertext[:16]
        self.assertEqual(len(nonce), 16)

    def test_pbkdf2_minimum_iterations(self):
        """Verify PBKDF2 uses strong iteration count."""
        # Should use at least 100,000 iterations (industry standard 2023)
        self.assertGreaterEqual(HC_PBKDF2_ITERATIONS, 100_000)
        # Should use exactly 200,000 as configured
        self.assertEqual(HC_PBKDF2_ITERATIONS, 200_000)

    def test_concurrent_different_salts(self):
        """Test different salts don't interfere with each other."""
        password = "password"
        salt1 = os.urandom(32)
        salt2 = os.urandom(32)
        
        plaintext = b"test data"
        
        # Encrypt with both salts
        ct1_a = aes_encrypt(plaintext, password, salt1)
        ct2_a = aes_encrypt(plaintext, password, salt2)
        ct1_b = aes_encrypt(plaintext, password, salt1)
        
        # Decrypt with correct salt
        self.assertEqual(aes_decrypt(ct1_a, password, salt1), plaintext)
        self.assertEqual(aes_decrypt(ct2_a, password, salt2), plaintext)
        self.assertEqual(aes_decrypt(ct1_b, password, salt1), plaintext)
        
        # Fail with wrong salt
        with self.assertRaises(ValueError):
            aes_decrypt(ct1_a, password, salt2)
        with self.assertRaises(ValueError):
            aes_decrypt(ct2_a, password, salt1)


# =============================================================================
# Main Test Runner
# =============================================================================
if __name__ == '__main__':
    # Run tests with verbosity
    unittest.main(verbosity=2)
