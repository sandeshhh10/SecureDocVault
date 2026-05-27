# Quick Start: Running Tests

## Windows

### Option 1: Batch Script (Recommended)
```cmd
# Run all tests
run_tests.bat

# Run with verbose output
run_tests.bat -v

# Run with coverage report
run_tests.bat -c
```

### Option 2: Direct Python
```cmd
# Run all tests
python tests.py

# Run specific test class
python tests.py TestCryptoEngine

# Run specific test
python tests.py TestCryptoEngine.test_aes_encrypt_decrypt_roundtrip
```

### Option 3: pytest (if installed)
```cmd
pip install -r requirements.txt
pytest tests.py -v
pytest tests.py --cov=tools --cov-report=html
```

---

## Linux / macOS

### Option 1: Shell Script (Recommended)
```bash
# Make executable (first time only)
chmod +x run_tests.sh

# Run all tests
./run_tests.sh

# Run with verbose output
./run_tests.sh -v

# Run with coverage report
./run_tests.sh -c
```

### Option 2: Direct Python
```bash
python tests.py          # Run all tests
python tests.py -v       # Verbose
python tests.py TestCryptoEngine  # Specific class
```

### Option 3: pytest
```bash
pip install -r requirements.txt
pytest tests.py -v
pytest tests.py --cov=tools --cov-report=html
```

---

## Expected Output

```
test_aes_encrypt_decrypt_roundtrip (...) AES encryption should be reversible. ... ok
test_aes_large_plaintext (...) AES should handle large plaintext (10 MB). ... ok
test_xor_encrypt_decrypt_roundtrip (...) XOR encryption should be reversible. ... ok
...

----------------------------------------------------------------------
Ran 38 tests in 8.186s

OK
```

---

## Test Structure

```
tests.py
├── TestCryptoEngine (15 tests)
│   ├── Key derivation (3 tests)
│   ├── XOR encryption (5 tests)
│   └── AES-GCM encryption (7 tests)
│
├── TestHoneyChecker (5 tests)
│   ├── Hash functions (2 tests)
│   └── Decoy generation (3 tests)
│
├── TestFlaskRoutes (4 tests)
│   └── Route availability & redirects
│
├── TestSecurityProperties (6 tests)
│   └── Security invariants & edge cases
│
├── TestIntegration (4 tests)
│   └── End-to-end workflows
│
└── TestRegressions (4 tests)
    └── Regression prevention
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Run all tests | `python tests.py` |
| Verbose output | `python tests.py -v` |
| Specific class | `python tests.py TestCryptoEngine` |
| Specific test | `python tests.py TestCryptoEngine.test_aes_encrypt_decrypt_roundtrip` |
| Coverage (pytest) | `pytest tests.py --cov=tools --cov-report=html` |
| Pattern match | `pytest tests.py -k "aes"` |

---

## Test Statistics

- **Total Tests**: 38
- **Pass Rate**: 100%
- **Execution Time**: ~8 seconds
- **Coverage**: Core security modules (85%+)

---

## Key Tests to Know

**Cryptography**
- ✓ AES-256-GCM encryption/decryption
- ✓ XOR honeyword encryption
- ✓ PBKDF2 key derivation (200,000 iterations)

**Security**
- ✓ Tamper detection (GCM authentication)
- ✓ Wrong password handling
- ✓ Key isolation (different salts)

**Robustness**
- ✓ Large files (up to 10MB)
- ✓ Empty files (0 bytes)
- ✓ All byte values (0x00-0xFF)

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'Crypto'"
```bash
pip install pycryptodome
```

### "ModuleNotFoundError: No module named 'flask'"
```bash
pip install -r requirements.txt
```

### Tests hang or timeout
- Kill the process (Ctrl+C)
- Check for large file test (10MB encryption is slow on some systems)
- Run individual test to isolate issue

### "No tests were found"
- Ensure you're in the project root directory
- Check that `tests.py` exists
- Check file permissions (especially on Linux/macOS)

---

## Further Reading

- [TESTING.md](TESTING.md) — Complete testing documentation
- [TEST_SUMMARY.md](TEST_SUMMARY.md) — Implementation summary
- [requirements.txt](requirements.txt) — Dependencies

---

**Last Updated**: May 14, 2026
