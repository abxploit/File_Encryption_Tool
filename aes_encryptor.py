import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants
KEY_LENGTH = 32           # 256 bits for AES-256
SALT_LENGTH = 16          # For PBKDF2
IV_LENGTH = 16            # AES block size
ITERATIONS = 100_000      # PBKDF2 iterations
BACKEND = default_backend()

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a secure AES-256 key using PBKDF2 with salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=BACKEND
    )
    return kdf.derive(password)

def encrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    key = derive_key(password.encode(), salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + encrypted_data)

    print(f"[✔] Encrypted file saved as: {file_path}.enc")

def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        encrypted = f.read()

    salt = encrypted[:SALT_LENGTH]
    iv = encrypted[SALT_LENGTH:SALT_LENGTH+IV_LENGTH]
    ciphertext = encrypted[SALT_LENGTH+IV_LENGTH:]

    key = derive_key(password.encode(), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError:
        print("[-] Incorrect password or corrupted file.")
        return

    output_file = file_path.replace('.enc', '.dec')
    with open(output_file, 'wb') as f:
        f.write(data)

    print(f"[✔] Decrypted file saved as: {output_file}")

def main():
    print("🔐 AES-256 File Encryptor/Decryptor CLI")
    print("=======================================")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Select (1 or 2): ").strip()

    file_path = input("Enter full path to the file: ").strip()
    if not os.path.exists(file_path):
        print("[-] File not found.")
        return

    password = getpass("Enter password: ")

    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)
    else:
        print("[-] Invalid option.")

if __name__ == '__main__':
        main()
