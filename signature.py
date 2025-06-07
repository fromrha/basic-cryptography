from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os # Moved import os to the top

# Imports for ECDSA
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature # For verify_signature_ecdsa

# Fungsi untuk membuat kunci RSA (public dan private) dan menyimpannya ke dalam file
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Simpan kunci privat dan publik ke dalam file
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key)
        
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key)
        
    return private_key, public_key

# Fungsi untuk menandatangani pesan menggunakan kunci privat
def sign_message(private_key, message):
    # Membaca kunci privat dari bytes
    key = RSA.import_key(private_key)
    
    # Hash dari pesan menggunakan SHA-256
    h = SHA256.new(message.encode())
    
    # Menandatangani hash pesan dengan kunci privat
    signer = pkcs1_15.new(key)
    signature = signer.sign(h)
    return signature

# Fungsi untuk memverifikasi tanda tangan menggunakan kunci publik
def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    
    try:
        # Memverifikasi tanda tangan dengan kunci publik
        verifier = pkcs1_15.new(key)
        verifier.verify(h, signature)
        print("Tanda tangan valid!")
    except (ValueError, TypeError):
        print("Tanda tangan tidak valid!")

# ======== ECDSA Functions ========

def generate_ecdsa_keys():
    """Generates ECDSA private and public keys and saves them to PEM files."""
    try:
        # Generate private key
        private_key = ec.generate_private_key(ec.SECP256R1())
        # Derive public key
        public_key = private_key.public_key()

        # Serialize private key
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("ecdsa_private_key.pem", "wb") as f:
            f.write(pem_private_key)
        print("Kunci privat ECDSA berhasil dibuat dan disimpan di ecdsa_private_key.pem")

        # Serialize public key
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("ecdsa_public_key.pem", "wb") as f:
            f.write(pem_public_key)
        print("Kunci publik ECDSA berhasil dibuat dan disimpan di ecdsa_public_key.pem")

        return pem_private_key, pem_public_key
    except Exception as e:
        print(f"Error saat membuat kunci ECDSA: {e}")
        return None, None

def sign_message_ecdsa(private_key_path, message):
    """Signs a message using an ECDSA private key."""
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        # Message is already a string, needs to be encoded to bytes for signing
        signature = private_key.sign(
            message.encode('utf-8'),  # Ensure message is bytes
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    except FileNotFoundError:
        print(f"Error: File kunci privat '{private_key_path}' tidak ditemukan.")
        return None
    except Exception as e:
        print(f"Error saat menandatangani pesan dengan ECDSA: {e}")
        return None

def verify_signature_ecdsa(public_key_path, message, signature):
    """Verifies a signature using an ECDSA public key."""
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )

        # Message is already a string, needs to be encoded to bytes for verification
        public_key.verify(
            signature,
            message.encode('utf-8'), # Ensure message is bytes
            ec.ECDSA(hashes.SHA256())
        )
        print("Tanda tangan ECDSA valid!") # Keep print for user feedback
        return True
    except InvalidSignature:
        print("Tanda tangan ECDSA tidak valid!") # Keep print for user feedback
        return False
    except FileNotFoundError:
        # print(f"Error: File kunci publik '{public_key_path}' tidak ditemukan.") # Keep print for user feedback
        # No, for testing, we want to distinguish this from InvalidSignature
        raise # Re-raise FileNotFoundError to be caught by test if needed
    except Exception as e:
        print(f"Error saat memverifikasi tanda tangan ECDSA: {e}") # Keep print for user feedback
        return False # Or re-raise depending on desired test behavior for unexpected errors

# Fungsi untuk menulis pesan dan tanda tangan ke file
def save_to_file(filename, message, signature):
    with open(filename, 'w') as file:
        file.write("Pesan:\n")
        file.write(message + "\n\n")
        file.write("Tanda Tangan:\n")
        file.write(signature.hex())

# Fungsi untuk membaca file dan mengekstrak pesan dan tanda tangan
def read_from_file(filename):
    with open(filename, 'r') as file:
        content = file.read().split("\n\n")
        message = content[0].split("Pesan:\n")[1]
        signature_hex = content[1].split("Tanda Tangan:\n")[1]
        signature = bytes.fromhex(signature_hex)
        return message, signature

# Proses Penandatanganan
def sign_process():
    # Step 1: Input pesan dari pengguna
    message = input("Masukkan pesan yang ingin ditandatangani: ")
    
    # Step 2: Generate RSA keys (public and private)
    private_key, public_key = generate_rsa_keys()
    
    # Step 3: Simulasikan dokumen pesan dalam file .txt
    signature = sign_message(private_key, message)
    
    # Step 4: Simpan pesan dan tanda tangan ke file .txt
    filename = "signed_document.txt"
    save_to_file(filename, message, signature)
    
    print(f"\nPesan dan tanda tangan disimpan di {filename}")
    print("Kunci publik pengirim disimpan di public_key.pem")
    print("Kunci privat pengirim disimpan di private_key.pem")
    
    return private_key, public_key, filename

# Proses Verifikasi
def verify_process():
    # Step 1: Meminta file input dari pengguna
    filename = input("Masukkan nama file untuk verifikasi tanda tangan (misalnya signed_document.txt): ")
    
    # Step 2: Memasukkan kunci publik untuk verifikasi
    with open("public_key.pem", "rb") as public_file:
        public_key = public_file.read()

    # Step 3: Membaca pesan dan tanda tangan dari file
    message, signature = read_from_file(filename)
    
    # Step 4: Verifikasi tanda tangan dengan kunci publik
    print("\nVerifikasi tanda tangan dengan kunci publik:")
    verify_signature(public_key, message, signature)

# Fungsi utama dengan opsi penandatanganan dan verifikasi
def main():
    while True:
        print("\n--- Menu ---")
        print("1. Penandatanganan Pesan (RSA)")
        print("2. Verifikasi Tanda Tangan (RSA)")
        print("3. Penandatanganan Pesan (ECDSA)")
        print("4. Verifikasi Tanda Tangan (ECDSA)")
        print("5. Generate Kunci ECDSA Baru") # Added option to generate ECDSA keys separately
        print("6. Keluar")
        
        option = input("Pilih opsi (1/2/3/4/5/6): ")
        
        if option == "1":
            # RSA Signing process (existing)
            private_key_rsa, public_key_rsa, filename_rsa = sign_process() # Assuming sign_process generates RSA keys if not present
            if filename_rsa: # Check if process was successful
                 print(f"Proses penandatanganan RSA selesai. File disimpan sebagai {filename_rsa}")
        
        elif option == "2":
            # RSA Verification process (existing)
            verify_process()

        elif option == "3":
            # ECDSA Signing process
            print("\n--- Penandatanganan Pesan (ECDSA) ---")
            # Ensure keys exist or guide user
            if not (os.path.exists("ecdsa_private_key.pem") and os.path.exists("ecdsa_public_key.pem")):
                print("Kunci ECDSA tidak ditemukan. Silakan generate kunci terlebih dahulu (Opsi 5).")
                continue # Back to menu

            message_ecdsa = input("Masukkan pesan yang ingin ditandatangani dengan ECDSA: ")
            signature_ecdsa = sign_message_ecdsa("ecdsa_private_key.pem", message_ecdsa)

            if signature_ecdsa:
                filename_ecdsa = "signed_document_ecdsa.txt"
                save_to_file(filename_ecdsa, message_ecdsa, signature_ecdsa)
                print(f"Pesan dan tanda tangan ECDSA disimpan di {filename_ecdsa}")
            else:
                print("Gagal menandatangani pesan dengan ECDSA.")

        elif option == "4":
            # ECDSA Verification process
            print("\n--- Verifikasi Tanda Tangan (ECDSA) ---")
            if not os.path.exists("ecdsa_public_key.pem"):
                print("Kunci publik ECDSA (ecdsa_public_key.pem) tidak ditemukan.")
                continue

            filename_ecdsa_verify = input("Masukkan nama file untuk verifikasi tanda tangan ECDSA (misalnya signed_document_ecdsa.txt): ")
            if not os.path.exists(filename_ecdsa_verify):
                print(f"File '{filename_ecdsa_verify}' tidak ditemukan.")
                continue

            try:
                message_to_verify, signature_to_verify = read_from_file(filename_ecdsa_verify)
                verify_signature_ecdsa("ecdsa_public_key.pem", message_to_verify, signature_to_verify)
            except Exception as e:
                print(f"Gagal membaca atau memverifikasi file: {e}")

        elif option == "5":
            print("\n--- Generate Kunci ECDSA Baru ---")
            generate_ecdsa_keys()

        elif option == "6":
            print("Keluar dari program.")
            break
        
        else:
            print("Pilihan tidak valid, silakan pilih opsi yang valid.")

if __name__ == "__main__":
    main()
