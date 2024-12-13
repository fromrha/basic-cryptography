from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import os
import base64

# ======== 1. KRIPTOGRAFI SIMETRIS (Fernet/AES) ========
# Generate symmetric key from user input (password or phrase)
def generate_symmetric_key_from_input():
    # Meminta input dari pengguna untuk kunci
    key_input = input("Masukkan kata sandi atau frasa untuk membuat kunci simetris: ")
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


# ======== 2. KRIPTOGRAFI ASIMETRIS (RSA) ========
# Generate RSA keys based on user input (password or string)
def generate_rsa_keys_from_input():
    passphrase = input("Masukkan passphrase untuk membuat kunci RSA: ")
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
    choice = input("Masukkan pilihan (1/2/3/4): ")

    if choice == "1":
        print("\n=== KRIPTOGRAFI SIMETRIS ===")
        action = input("(1) Generate Key dari input, (2) Encrypt, atau (3) Decrypt? ")
        if action == "1":
            generate_symmetric_key_from_input()
            print("Kunci simetris berhasil dibuat dari input!")
        elif action == "2":
            message = input("Masukkan pesan untuk dienkripsi: ")
            encrypted = symmetric_encrypt(message)
            print("Pesan terenkripsi:", encrypted)
        elif action == "3":
            encrypted_message = input("Masukkan pesan terenkripsi: ").encode()
            decrypted = symmetric_decrypt(encrypted_message)
            print("Pesan terdekripsi:", decrypted)
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
            encrypted_message = input("Masukkan pesan terenkripsi (dalam byte): ").encode()
            decrypted = rsa_decrypt(eval(encrypted_message))
            print("Pesan terdekripsi:", decrypted)
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

    else:
        print("Pilihan tidak valid!")
