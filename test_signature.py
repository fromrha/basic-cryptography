import unittest
import os
import sys
from unittest.mock import patch, mock_open

# Add project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
sys.path.insert(0, project_root)

try:
    from signature import (
        generate_ecdsa_keys,
        sign_message_ecdsa,
        verify_signature_ecdsa,
        # For testing wrong key, we need a way to load/use different keys
        # The current generate_ecdsa_keys saves with fixed names.
        # We will allow it to run and then rename files for the "wrong key" test.
        # Or, modify generate_ecdsa_keys to accept paths (outside scope of this subtask)
    )
    SIGNATURE_MODULE_AVAILABLE = True
except ImportError as e:
    print(f"Failed to import from signature: {e}")
    def generate_ecdsa_keys(): pass
    def sign_message_ecdsa(a,b): return None
    def verify_signature_ecdsa(a,b,c): return False
    SIGNATURE_MODULE_AVAILABLE = False


@unittest.skipUnless(SIGNATURE_MODULE_AVAILABLE, "Signature module not available")
class TestECDSASignatures(unittest.TestCase):
    def setUp(self):
        self.priv_key_path = "ecdsa_private_key.pem" # Default path used by generate_ecdsa_keys
        self.pub_key_path = "ecdsa_public_key.pem"   # Default path used by generate_ecdsa_keys

        self.priv_key_path_alt = "ecdsa_private_key_alt.pem"
        self.pub_key_path_alt = "ecdsa_public_key_alt.pem"

        self.test_message = "This is a test message for ECDSA."

        # Clean up any pre-existing key files from previous runs
        self._cleanup_files()

        # Generate main keys for most tests
        generate_ecdsa_keys()


    def _cleanup_files(self):
        files_to_remove = [
            self.priv_key_path, self.pub_key_path,
            self.priv_key_path_alt, self.pub_key_path_alt,
            "signed_document_ecdsa.txt" # if created by other tests/manually
        ]
        for f_path in files_to_remove:
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_01_generate_ecdsa_keys_creates_files(self):
        # setUp already calls generate_ecdsa_keys()
        self.assertTrue(os.path.exists(self.priv_key_path), "ECDSA private key file was not created.")
        self.assertTrue(os.path.exists(self.pub_key_path), "ECDSA public key file was not created.")

    def test_02_sign_verify_ecdsa_valid(self):
        self.assertTrue(os.path.exists(self.priv_key_path), "Prerequisite: Private key missing for sign/verify test.")
        signature = sign_message_ecdsa(self.priv_key_path, self.test_message)
        self.assertIsNotNone(signature, "Signing failed, signature is None.")

        is_valid = verify_signature_ecdsa(self.pub_key_path, self.test_message, signature)
        self.assertTrue(is_valid, "ECDSA signature verification failed for a valid signature.")

    def test_03_verify_ecdsa_tampered_message(self):
        self.assertTrue(os.path.exists(self.priv_key_path), "Prerequisite: Private key missing for tampered message test.")
        signature = sign_message_ecdsa(self.priv_key_path, self.test_message)
        self.assertIsNotNone(signature)

        tampered_message = self.test_message + " (tampered)"
        is_valid = verify_signature_ecdsa(self.pub_key_path, tampered_message, signature)
        self.assertFalse(is_valid, "ECDSA signature verification succeeded for a tampered message.")

    def test_04_verify_ecdsa_wrong_key(self):
        # 1. Ensure original keys are present
        self.assertTrue(os.path.exists(self.priv_key_path))
        self.assertTrue(os.path.exists(self.pub_key_path))

        # 2. Sign message with original private key
        original_signature = sign_message_ecdsa(self.priv_key_path, self.test_message)
        self.assertIsNotNone(original_signature)

        # 3. Generate a *second* (alternative) pair of keys
        # To do this without modifying generate_ecdsa_keys to take paths,
        # we rename the first set, generate new ones (which will use default names),
        # then use the new public key for verification, and finally restore names.

        os.rename(self.priv_key_path, self.priv_key_path_alt)
        os.rename(self.pub_key_path, self.pub_key_path_alt)

        # Generate new keys (will be ecdsa_private_key.pem, ecdsa_public_key.pem)
        generate_ecdsa_keys()
        self.assertTrue(os.path.exists(self.priv_key_path), "Failed to generate the second private key.")
        self.assertTrue(os.path.exists(self.pub_key_path), "Failed to generate the second public key.")

        # 4. Attempt to verify original_signature with the NEW (wrong) public key
        is_valid_wrong_key = verify_signature_ecdsa(self.pub_key_path, self.test_message, original_signature)
        self.assertFalse(is_valid_wrong_key, "ECDSA verification succeeded with a wrong public key.")

        # 5. Clean up: remove the second set of keys and rename the original set back
        os.remove(self.priv_key_path)
        os.remove(self.pub_key_path)
        os.rename(self.priv_key_path_alt, self.priv_key_path)
        os.rename(self.pub_key_path_alt, self.pub_key_path)


    def test_05_sign_file_not_found(self):
        # Test sign_message_ecdsa with a non-existent private key file
        signature = sign_message_ecdsa("non_existent_private_key.pem", self.test_message)
        self.assertIsNone(signature) # Expecting None due to error handling

    def test_06_verify_file_not_found(self):
        # Test verify_signature_ecdsa with a non-existent public key file
        # Need a dummy signature for this test
        dummy_signature = b"dummysig"
        with self.assertRaises(FileNotFoundError): # Expecting FileNotFoundError as per implementation
            verify_signature_ecdsa("non_existent_public_key.pem", self.test_message, dummy_signature)


    def tearDown(self):
        self._cleanup_files()

if __name__ == '__main__':
    # Running tests in a defined order for key generation dependency
    suite = unittest.TestSuite()
    suite.addTest(TestECDSASignatures('test_01_generate_ecdsa_keys_creates_files'))
    suite.addTest(TestECDSASignatures('test_02_sign_verify_ecdsa_valid'))
    suite.addTest(TestECDSASignatures('test_03_verify_ecdsa_tampered_message'))
    suite.addTest(TestECDSASignatures('test_04_verify_ecdsa_wrong_key'))
    suite.addTest(TestECDSASignatures('test_05_sign_file_not_found'))
    suite.addTest(TestECDSASignatures('test_06_verify_file_not_found'))
    runner = unittest.TextTestRunner()
    runner.run(suite)
    # unittest.main() # This would run tests alphabetically by default
