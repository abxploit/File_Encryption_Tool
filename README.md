## 🔐 AES-256 File Encryptor/Decryptor (CLI)
A secure and simple command-line tool to encrypt and decrypt files using the AES-256 encryption algorithm.
Built with Python and the powerful cryptography library.

## 🛡 Features
🔒 AES-256 encryption (strong symmetric encryption)

🔑 Password-based key derivation (PBKDF2 + SHA-256 + Salt)

🧂 Random IV and salt generation

🧼 Automatic padding and unpadding

✅ Easy-to-use command-line interface

🧪 Supports all file types (text, PDF, images, etc.)

## 📦 Requirements
Python 3.6+

cryptography library

Install requirements:
```
pip install cryptography
```
## 🚀 Usage
Run the script:
```
python aes_file_crypto.py
```
Choose one of the options:

1. Encrypt a file
2. Decrypt a file
Enter the full path to the file and your password. That’s it!

## 🔐 Encryption Flow
User inputs a file and password.

Salt and IV are randomly generated.

AES key is derived from the password using PBKDF2HMAC.

File data is padded and encrypted using AES-256 in CBC mode.

Output: filename.ext.enc (includes salt + IV + ciphertext).

## 🔓 Decryption Flow
Reads salt, IV, and ciphertext from .enc file.

Derives AES key from the entered password.

Decrypts and unpads the content.

Output: filename.ext.dec

## 📁 Example
Encrypt a file:

Select (1 or 2): 1
Enter full path to the file: secret.txt
Enter password:
[✔] Encrypted file saved as: secret.txt.enc

Decrypt a file:

Select (1 or 2): 2
Enter full path to the file: secret.txt.enc
Enter password:
[✔] Decrypted file saved as: secret.txt.dec

## 🔐 Notes
DO NOT forget your password. It is not stored anywhere.

File encryption uses strong AES-256 (CBC) with PKCS7 padding.

Salt and IV are embedded in the encrypted file for decryption.
