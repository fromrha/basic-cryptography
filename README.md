# Python Cryptography Tools

This project provides a suite of command-line tools for various cryptographic operations, including symmetric encryption, asymmetric signatures, and hashing. It also includes features like file encryption/decryption and password strength assessment.

## Features

### 1. `crypto_tools.py` - Symmetric & Asymmetric Cryptography, Hashing, File Operations

This script offers a menu-driven interface for:

*   **Symmetric Cryptography (AES - Fernet):**
    *   **Key Generation:** Generate a symmetric key from a user-provided password or passphrase. The key is saved to `symmetric.key`.
    *   **Password Strength Meter:** When generating keys, the strength of the input password/passphrase is assessed using the `zxcvbn` library. Users receive feedback (e.g., "Very weak", "Strong") and suggestions for improvement.
    *   **Message Encryption/Decryption:** Encrypt and decrypt text messages.
    *   **File Encryption/Decryption:**
        *   Encrypt an entire file using the generated symmetric key.
        *   Decrypt a previously encrypted file.
        *   Accessible via options "5. Encrypt File (Symmetric)" and "6. Decrypt File (Symmetric)" in the main menu. The symmetric key must exist (`symmetric.key`) or be generated first.

*   **Asymmetric Cryptography (RSA):**
    *   **Key Generation:** Generate RSA public/private key pairs from a user-provided passphrase. Keys are saved to `public_key.pem` and `private_key.pem`.
    *   **Password Strength Meter:** The passphrase used for RSA key generation is also checked for strength.
    *   **Message Encryption/Decryption:** Encrypt messages with a public key and decrypt with a private key.

*   **Hashing:**
    *   Generate SHA-256 hashes of messages.
    *   Generate MD5 hashes of messages.

### 2. `signature.py` - Digital Signatures (RSA & ECDSA)

This script allows for creating and verifying digital signatures using both RSA and ECDSA algorithms.

*   **RSA Signatures:**
    *   Generate RSA key pairs (saved to `private_key.pem`, `public_key.pem` - uses PyCryptodome).
    *   Sign messages using the RSA private key.
    *   Verify signatures using the RSA public key.

*   **ECDSA Signatures (Elliptic Curve Digital Signature Algorithm):**
    *   **Key Generation:** Generate ECDSA key pairs using the SECP256R1 curve. Keys are saved to `ecdsa_private_key.pem` and `ecdsa_public_key.pem` (uses `cryptography` library).
    *   **Signing:** Sign messages using the ECDSA private key (SHA-256 hash).
    *   **Verification:** Verify signatures using the ECDSA public key.
    *   Accessible via dedicated options in the script's menu.

### 3. `fix_crypto_tools.py` - RSA Signing (Alternative Implementation)

This script provides an alternative implementation for RSA signing and verification, primarily for demonstration or specific use cases.
*   **Password Strength Meter:** Passphrases used for generating RSA private keys are checked for strength.

## General Usage

1.  **Ensure Dependencies:** Make sure you have the required Python libraries installed. You can install them using pip:
    ```bash
    pip install cryptography pycryptodome zxcvbn
    ```

2.  **Run the Scripts:**
    Execute the scripts from your terminal:
    ```bash
    python crypto_tools.py
    python signature.py
    python fix_crypto_tools.py
    ```
    The scripts will present interactive menus to guide you through the available operations.

## Key Files

*   `symmetric.key`: Default symmetric key for `crypto_tools.py`.
*   `private_key.pem`, `public_key.pem`: Default RSA keys. (`crypto_tools.py` uses `cryptography` library for RSA, `signature.py` and `fix_crypto_tools.py` use `PyCryptodome` for RSA).
*   `ecdsa_private_key.pem`, `ecdsa_public_key.pem`: Default ECDSA keys for `signature.py`.
*   `signed_document.txt`, `signed_document_ecdsa.txt`: Default output files for signed messages.

Keep your private keys and symmetric keys secure. Loss of these keys can result in inability to decrypt data or verify/create signatures.
