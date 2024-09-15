#!/usr/bin/env python3

import sys
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Function to load the private key from a file
def load_private_key(private_key_pem):

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )
    return private_key

# Function to load the encrypted code from a file
def load_encrypted_code(file_path):
    with open(file_path, 'r') as file:
        encrypted_code_base64 = file.read()
    return base64.b64decode(encrypted_code_base64)


def rsa_decrypt(private_key, encrypted_code):
    # Decrypt the code snippet
    decrypted_code = private_key.decrypt(
        encrypted_code,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_code.decode('utf-8')


# Main method
if __name__ == '__main__':

    if len(sys.argv) != 3:
        print("Usage: ./decryption_rsa.py <private_key_path> <enc_path> ")
        sys.exit(0)

    private_key_path = sys.argv[1]
    enc_path = sys.argv[2]


    # Read the private key
    with open(private_key_path, 'rb') as file:
        private_key_pem = file.read()

    # Load the private key and encrypted code
    private_key = load_private_key(private_key_pem)
    encrypted_code = load_encrypted_code(enc_path)

    decrypted_code = rsa_decrypt(private_key, encrypted_code)


    # Print the decrypted code
    print("[!] Decrypted content:")
    print("'")
    print(decrypted_code)
    print("'")
    print("[!] Decryption complete.")
