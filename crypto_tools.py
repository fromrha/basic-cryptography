from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import os
import base64

try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

# ======== 0. FUNGSI UTILITAS ========
def check_password_strength(password):
    if not ZXCVBN_AVAILABLE:
        print("Pustaka zxcvbn tidak tersedia, pengecekan kekuatan kata sandi dilewati.")
        return -1 # Mengembalikan nilai yang menunjukkan pengecekan tidak dilakukan

    results = zxcvbn(password)
    score = results['score']
    feedback = results['feedback']['suggestions']
    warnings = results['feedback']['warning']

    strength_map = {
        0: "Sangat Lemah",
        1: "Lemah",
        2: "Cukup",
        3: "Kuat",
        4: "Sangat Kuat"
    }

    print(f"Kekuatan Kata Sandi: {strength_map.get(score, 'Tidak Diketahui')}")
    if warnings:
        print(f"Peringatan: {warnings}")
    if feedback:
        print("Saran:")
        for suggestion in feedback:
            print(f"- {suggestion}")

    return score # Already returns score, no change needed here actually.

# ======== 1. KRIPTOGRAFI SIMETRIS (Fernet/AES) ========
# Generate symmetric key from user input (password or phrase)
def generate_symmetric_key_from_input():
    # Meminta input dari pengguna untuk kunci
    key_input = input("Masukkan kata sandi atau frasa untuk membuat kunci simetris: ")

    # Cek kekuatan kata sandi
    strength_score = check_password_strength(key_input)
    if ZXCVBN_AVAILABLE and strength_score < 2: # Skor 0 (Sangat Lemah) atau 1 (Lemah)
        print("Peringatan: Kata sandi yang Anda masukkan lemah. Pertimbangkan untuk menggunakan kata sandi yang lebih kuat.")
        # Anda bisa menambahkan logika untuk meminta konfirmasi atau input ulang di sini jika diperlukan

    key = hashlib.sha256(key_input.encode()).digest()  # Membuat kunci simetris dengan hash SHA-256
    key_fernet = base64.urlsafe_b64encode(key[:32])  # Membatasi panjang kunci menjadi 32 byte
    with open("symmetric.key", "wb") as key_file:
        key_file.write(key_fernet)
    return key_fernet


# Load symmetric key
def load_symmetric_key():
    return open("symmetric.key", "rb").read()


# Encrypt a message using symmetric key
def symmetric_encrypt(message):
    key = load_symmetric_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message


# Decrypt a message using symmetric key
def symmetric_decrypt(encrypted_message):
    key = load_symmetric_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()


# Encrypt a file using symmetric key
def symmetric_encrypt_file(input_filepath, output_filepath):
    try:
        key = load_symmetric_key()
        f = Fernet(key)
        with open(input_filepath, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        with open(output_filepath, "wb") as file:
            file.write(encrypted_data)
        print(f"File '{input_filepath}' berhasil dienkripsi ke '{output_filepath}'.")
    except FileNotFoundError:
        print(f"Error: File '{input_filepath}' tidak ditemukan.")
    except Exception as e:
        print(f"Error selama enkripsi file: {e}")


# Decrypt a file using symmetric key
def symmetric_decrypt_file(input_filepath, output_filepath):
    try:
        key = load_symmetric_key()
        f = Fernet(key)
        with open(input_filepath, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)
        with open(output_filepath, "wb") as file:
            file.write(decrypted_data)
        print(f"File '{input_filepath}' berhasil didekripsi ke '{output_filepath}'.")
    except FileNotFoundError:
        print(f"Error: File '{input_filepath}' tidak ditemukan.")
    except Exception as e:
        print(f"Error selama dekripsi file: {e}")


# ======== 2. KRIPTOGRAFI ASIMETRIS (RSA) ========
# Generate RSA keys based on user input (password or string)
def generate_rsa_keys_from_input():
    passphrase = input("Masukkan passphrase untuk membuat kunci RSA: ")

    # Cek kekuatan passphrase
    strength_score = check_password_strength(passphrase)
    if ZXCVBN_AVAILABLE and strength_score < 2: # Skor 0 (Sangat Lemah) atau 1 (Lemah)
        print("Peringatan: Passphrase yang Anda masukkan lemah. Pertimbangkan untuk menggunakan passphrase yang lebih kuat.")
        # Anda bisa menambahkan logika untuk meminta konfirmasi atau input ulang di sini jika diperlukan

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),  # Encrypt private key with passphrase
            )
        )

    # Save public key
    with open("public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return private_key, public_key


# Load RSA keys
def load_rsa_keys():
    with open("private_key.pem", "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(), password=None
        )
    with open("public_key.pem", "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())
    return private_key, public_key


# Encrypt a message using public key
def rsa_encrypt(message):
    _, public_key = load_rsa_keys()
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return encrypted_message


# Decrypt a message using private key
def rsa_decrypt(encrypted_message):
    private_key, _ = load_rsa_keys()
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return decrypted_message.decode()


# ======== 3. HASHING ========
# Generate a SHA-256 hash of a message
def generate_sha256_hash(message):
    hash_object = hashlib.sha256(message.encode())
    return hash_object.hexdigest()


# Generate an MD5 hash of a message
def generate_md5_hash(message):
    hash_object = hashlib.md5(message.encode())
    return hash_object.hexdigest()


# ======== MAIN PROGRAM ========
if __name__ == "__main__":
    print("=== Pilih Jenis Kriptografi ===")
    print("1. Kriptografi Simetris (AES)")
    print("2. Kriptografi Asimetris (RSA)")
    print("3. Hashing SHA-256")
    print("4. Hashing MD5")
    print("5. Encrypt File (Symmetric)")
    print("6. Decrypt File (Symmetric)")
    choice = input("Masukkan pilihan (1/2/3/4/5/6): ")

    if choice == "1":
        print("\n=== KRIPTOGRAFI SIMETRIS (Operasi Pesan) ===")
        # Tambahkan pengecekan kunci simetris sebelum enkripsi/dekripsi pesan
        if not os.path.exists("symmetric.key"):
            print("Kunci simetris (symmetric.key) tidak ditemukan.")
            generate_key_choice = input("Apakah Anda ingin membuat kunci simetris sekarang? (y/n): ")
            if generate_key_choice.lower() == 'y':
                generate_symmetric_key_from_input()
                print("Kunci simetris berhasil dibuat.")
            else:
                print("Operasi enkripsi/dekripsi pesan dibatalkan karena kunci tidak ada.")
                exit() # Keluar jika pengguna tidak ingin membuat kunci

        action = input("(1) Generate Key dari input (akan menimpa yang ada), (2) Encrypt Pesan, atau (3) Decrypt Pesan? ")
        if action == "1":
            generate_symmetric_key_from_input()
            print("Kunci simetris berhasil dibuat dari input!")
        elif action == "2":
            message = input("Masukkan pesan untuk dienkripsi: ")
            encrypted = symmetric_encrypt(message)
            print("Pesan terenkripsi:", encrypted)
        elif action == "3":
            encrypted_message = input("Masukkan pesan terenkripsi: ").encode()
            try:
                decrypted = symmetric_decrypt(encrypted_message)
                print("Pesan terdekripsi:", decrypted)
            except Exception as e:
                print(f"Error dekripsi: {e}. Pastikan kunci yang digunakan benar dan pesan tidak rusak.")
        else:
            print("Pilihan tidak valid!")

    elif choice == "2":
        print("\n=== KRIPTOGRAFI ASIMETRIS ===")
        action = input("(1) Generate Keys dari input, (2) Encrypt, atau (3) Decrypt ")
        if action == "1":
            generate_rsa_keys_from_input()
            print("Kunci RSA (public/private) berhasil dibuat dari input!")
        elif action == "2":
            message = input("Masukkan pesan untuk dienkripsi: ")
            encrypted = rsa_encrypt(message)
            print("Pesan terenkripsi:", encrypted)
        elif action == "3":
            # Pastikan input pesan terenkripsi adalah bytes
            encrypted_message_str = input("Masukkan pesan terenkripsi (representasi string dari bytes, contoh: b'...'): ")
            try:
                # Evaluasi string menjadi bytes, hati-hati dengan penggunaan eval
                encrypted_message_bytes = eval(encrypted_message_str)
                if not isinstance(encrypted_message_bytes, bytes):
                    raise ValueError("Input bukan merupakan bytes.")
                decrypted = rsa_decrypt(encrypted_message_bytes)
                print("Pesan terdekripsi:", decrypted)
            except (SyntaxError, ValueError, TypeError) as e:
                print(f"Error: Input pesan terenkripsi tidak valid atau bukan format bytes yang benar. Detail: {e}")
            except Exception as e:
                print(f"Error dekripsi RSA: {e}")
        else:
            print("Pilihan tidak valid!")

    elif choice == "3":
        print("\n=== HASHING SHA-256 ===")
        message = input("Masukkan pesan untuk di-hash: ")
        hashed = generate_sha256_hash(message)
        print("Hash SHA-256:", hashed)

    elif choice == "4":
        print("\n=== HASHING MD5 ===")
        message = input("Masukkan pesan untuk di-hash: ")
        hashed_md5 = generate_md5_hash(message)
        print("Hash MD5:", hashed_md5)

    elif choice == "5":
        print("\n=== ENKRIPSI FILE (SIMETRIS) ===")
        if not os.path.exists("symmetric.key"):
            print("Kunci simetris (symmetric.key) tidak ditemukan.")
            generate_key_choice = input("Apakah Anda ingin membuat kunci simetris sekarang? (y/n): ")
            if generate_key_choice.lower() == 'y':
                generate_symmetric_key_from_input()
                print("Kunci simetris berhasil dibuat.")
            else:
                print("Operasi enkripsi file dibatalkan karena kunci tidak ada.")
                exit()

        input_file = input("Masukkan path file yang akan dienkripsi: ")
        output_file = input("Masukkan path untuk menyimpan file terenkripsi: ")
        symmetric_encrypt_file(input_file, output_file)

    elif choice == "6":
        print("\n=== DEKRIPSI FILE (SIMETRIS) ===")
        if not os.path.exists("symmetric.key"):
            print("Kunci simetris (symmetric.key) tidak ditemukan.")
            # Tidak perlu menawarkan pembuatan kunci di sini karena dekripsi memerlukan kunci yang sudah ada
            print("Pastikan file 'symmetric.key' ada di direktori yang sama atau buat kunci yang sesuai.")
            print("Operasi dekripsi file dibatalkan.")
            exit()

        input_file = input("Masukkan path file yang akan didekripsi: ")
        output_file = input("Masukkan path untuk menyimpan file terdekripsi: ")
        symmetric_decrypt_file(input_file, output_file)

    else:
        print("Pilihan tidak valid!")
