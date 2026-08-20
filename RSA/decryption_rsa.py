#!/usr/bin/env python3

import os
import sys
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Load environment variables from .env file
load_dotenv()

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

    if len(sys.argv) != 2:
        print("Usage: python RSA/decryption_rsa.py <enc_path>")
        sys.exit(0)

    enc_path = sys.argv[1]

    # Load private key path from environment variable and expand '~'
    private_key_env = os.getenv("RSA_KEY_PATH")
    if not private_key_env:
        print("[!] Error: RSA_KEY_PATH is not set in the .env file.")
        sys.exit(1)

    private_key_path = os.path.expanduser(private_key_env)

    if not os.path.exists(private_key_path):
        print(f"[!] Private key path not found: {private_key_path}")
        sys.exit(1)

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
