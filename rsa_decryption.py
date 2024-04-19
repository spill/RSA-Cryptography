# RSA Decryption Program with File Input and Key File
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def load_private_key(file_path):
    """Loads an RSA private key from a key file."""
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Replace None with a bytes object containing the password if the key is encrypted
            backend=default_backend()
        )
    return private_key

def rsa_decrypt(ciphertext, private_key):
    """Decrypts a given ciphertext using the RSA private key."""
    try:
        # Attempt to decrypt using OAEP padding first
        plain_text = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        # If decryption fails, try using PKCS1v15 padding
        plain_text = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
    return plain_text

def read_cipher_text(file_path):
    """Reads a cipher text from a binary file."""
    with open(file_path, "rb") as file:
        return file.read()

def main():
    # Load the private key from a key file
    private_key = load_private_key("prv.key")

    # File paths for cipher texts
    cipher_files = ["cipher1.bin", "cipher2.bin"]

    # Decrypt each cipher text file and print the result
    for cipher_file in cipher_files:
        cipher_text = read_cipher_text(cipher_file)
        plain_text = rsa_decrypt(cipher_text, private_key)
        print(f"Plain text from {cipher_file}: {plain_text.decode('utf-8')}")

        # Optionally, save the plain text to a file
        with open(os.path.splitext(cipher_file)[0] + "_plaintext.txt", "w") as file:
            file.write(plain_text.decode('utf-8'))

if __name__ == "__main__":
    main()
