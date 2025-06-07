from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

# Fungsi utilitas untuk mengecek kekuatan kata sandi
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

    print(f"Kekuatan Kata Sandi/Passphrase: {strength_map.get(score, 'Tidak Diketahui')}")
    if warnings:
        print(f"Peringatan: {warnings}")
    if feedback:
        print("Saran:")
        for suggestion in feedback:
            print(f"- {suggestion}")

    return score

# Fungsi untuk membuat kunci RSA (public dan private) dan menyimpannya ke dalam file
def generate_rsa_keys(password=None):
    if password and ZXCVBN_AVAILABLE:
        strength_score = check_password_strength(password)
        if strength_score < 2: # Skor 0 (Sangat Lemah) atau 1 (Lemah)
            print("Peringatan: Passphrase yang Anda masukkan untuk kunci privat lemah. Pertimbangkan untuk menggunakan passphrase yang lebih kuat.")
            # Di dunia nyata, Anda mungkin ingin menambahkan logika untuk mengulang input atau konfirmasi.

    key = RSA.generate(2048)
    private_key = key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")
    public_key = key.publickey().export_key()
    
    # Simpan kunci privat dan publik ke dalam file
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key)
        
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key)
        
    return private_key, public_key

# Fungsi untuk menandatangani pesan menggunakan kunci privat
def sign_message(private_key, message, password=None):
    # Membaca kunci privat dari bytes dengan password jika ada
    key = RSA.import_key(private_key, passphrase=password)
    
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
    password = input("Masukkan kata sandi untuk kunci privat (jika ada): ")
    
    # Step 2: Generate RSA keys (public and private)
    private_key, public_key = generate_rsa_keys(password)
    
    # Step 3: Simulasikan dokumen pesan dalam file .txt
    signature = sign_message(private_key, message, password)
    
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
