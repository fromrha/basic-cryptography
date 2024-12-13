from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

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
        print("1. Penandatanganan Pesan")
        print("2. Verifikasi Tanda Tangan")
        print("3. Keluar")
        
        option = input("Pilih opsi (1/2/3): ")
        
        if option == "1":
            private_key, public_key, filename = sign_process()
            print(f"Proses penandatanganan selesai. File disimpan sebagai {filename}")
        
        elif option == "2":
            verify_process()
        
        elif option == "3":
            print("Keluar dari program.")
            break
        
        else:
            print("Pilihan tidak valid, silakan pilih opsi yang valid.")
        
if __name__ == "__main__":
    main()
