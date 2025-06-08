import unittest
import os
import sys
from unittest.mock import patch

# Add project root to sys.path to allow importing crypto_tools
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
# In a real scenario, if tests were in a subfolder 'tests', it might be os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, project_root)

try:
    from crypto_tools import (
        generate_symmetric_key_from_input,
        load_symmetric_key,
        symmetric_encrypt_file,
        symmetric_decrypt_file,
        check_password_strength,
        ZXCVBN_AVAILABLE # To check if zxcvbn is actually available in test env
    )
except ImportError as e:
    print(f"Failed to import from crypto_tools: {e}")
    # Define dummy functions if import fails, so tests can be defined (they will likely fail with meaningful messages)
    def generate_symmetric_key_from_input(): pass
    def load_symmetric_key(): return b"dummykey"
    def symmetric_encrypt_file(a,b): pass
    def symmetric_decrypt_file(a,b): pass
    def check_password_strength(p): return -1
    ZXCVBN_AVAILABLE = False


# Helper to create a dummy symmetric key for tests
def create_dummy_symmetric_key(filepath="symmetric.key"):
    # This is a simplified key generation for testing purposes.
    # The actual generate_symmetric_key_from_input() requires user input.
    # We'll write a fixed dummy key.
    # A real Fernet key needs to be 32 url-safe base64-encoded bytes.
    dummy_key = b"T0xEQktLNXN1ZkJ1eFRqRzZHQklWbVdZREFQLW1hZ0U=" # Dummy Fernet key
    with open(filepath, "wb") as key_file:
        key_file.write(dummy_key)
    return dummy_key

class TestFileEncryptionDecryption(unittest.TestCase):
    def setUp(self):
        self.key_file = "test_symmetric.key"
        self.sample_file = "sample.txt"
        self.encrypted_file = "encrypted.dat"
        self.decrypted_file = "decrypted.txt"

        create_dummy_symmetric_key(self.key_file)

        with open(self.sample_file, "w") as f:
            f.write("This is a test message for file encryption and decryption.")

        # Mock load_symmetric_key to use our test key file
        with open(self.key_file, "rb") as f_key:
            key_content = f_key.read()
        self.patcher = patch('crypto_tools.load_symmetric_key', return_value=key_content)
        self.mock_load_key = self.patcher.start()

    def test_encrypt_decrypt_valid(self):
        # Encrypt
        symmetric_encrypt_file(self.sample_file, self.encrypted_file)
        self.assertTrue(os.path.exists(self.encrypted_file))

        # Decrypt
        symmetric_decrypt_file(self.encrypted_file, self.decrypted_file)
        self.assertTrue(os.path.exists(self.decrypted_file))

        with open(self.sample_file, "r") as f_orig:
            original_content = f_orig.read()
        with open(self.decrypted_file, "r") as f_dec:
            decrypted_content = f_dec.read()

        self.assertEqual(original_content, decrypted_content)

        # Ensure encrypted content is different
        if os.path.exists(self.encrypted_file) and os.path.exists(self.sample_file):
            with open(self.sample_file, "rb") as f_orig_b:
                original_bytes = f_orig_b.read()
            with open(self.encrypted_file, "rb") as f_enc_b:
                encrypted_bytes = f_enc_b.read()
            self.assertNotEqual(original_bytes, encrypted_bytes)

    @patch('builtins.print') # Mock print to check console output
    def test_encrypt_file_not_found(self, mock_print):
        symmetric_encrypt_file("non_existent_sample.txt", self.encrypted_file)
        # Check if an error message was printed (actual message might vary)
        self.assertTrue(any("tidak ditemukan" in call.args[0] for call in mock_print.call_args_list))
        self.assertFalse(os.path.exists(self.encrypted_file))

    @patch('builtins.print')
    def test_decrypt_file_not_found(self, mock_print):
        symmetric_decrypt_file("non_existent_encrypted.dat", self.decrypted_file)
        self.assertTrue(any("tidak ditemukan" in call.args[0] for call in mock_print.call_args_list))
        self.assertFalse(os.path.exists(self.decrypted_file))

    # test_decrypt_invalid_key is hard to implement reliably without more control over Fernet object
    # or being able to easily generate a *different valid* key for the test.
    # For now, we'll skip it as per the plan.

    def tearDown(self):
        self.patcher.stop()
        for f in [self.key_file, self.sample_file, self.encrypted_file, self.decrypted_file]:
            if os.path.exists(f):
                os.remove(f)

class TestPasswordStrengthMeter(unittest.TestCase):
    @unittest.skipUnless(ZXCVBN_AVAILABLE, "zxcvbn library not available, skipping strength tests")
    @patch('builtins.print') # To suppress actual printing during tests
    def test_check_password_strength_various_inputs(self, mock_print):
        # Test with a very weak password
        score_weak = check_password_strength("123")
        self.assertIn(score_weak, [0, 1]) # Typically 0 or 1

        # Test with a moderately weak password
        score_moderate = check_password_strength("password")
        self.assertIn(score_moderate, [0, 1, 2]) # Can vary

        # Test with a reasonably strong password
        score_strong = check_password_strength("Tr0ub4dor&3")
        self.assertIn(score_strong, [2, 3, 4]) # Should be higher

        # Test with a very strong password
        score_very_strong = check_password_strength("ThisIsAVeryLongAndComplexPassword!@#$")
        self.assertEqual(score_very_strong, 4)

    @patch('crypto_tools.ZXCVBN_AVAILABLE', False) # Simulate zxcvbn not being available
    @patch('builtins.print')
    def test_check_password_strength_fallback(self, mock_print):
        score = check_password_strength("anypassword")
        self.assertEqual(score, -1) # Expected fallback score
        self.assertTrue(any("Pustaka zxcvbn tidak tersedia" in call.args[0] for call in mock_print.call_args_list))

if __name__ == '__main__':
    unittest.main()
