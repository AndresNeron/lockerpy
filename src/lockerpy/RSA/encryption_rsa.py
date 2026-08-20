#!/usr/init/env python3
# This code implements rsa encryption methods.

import os
import sys
import time
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Load environment variables from .env file
load_dotenv()

# Function to read the plaintext code from a file
def read_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist.")
        sys.exit(1)
    
    if not os.path.isfile(file_path):
        print(f"Error: {file_path} is not a file.")
        sys.exit(1)

    with open(file_path, 'rb') as file:
        return file.read()


# Function to save the encrypted code to a file
def save_encrypted_code(encrypted_code, file_path):
    encrypted_code_base64 = base64.b64encode(encrypted_code).decode('utf-8')
    with open(file_path, 'w') as file:
        file.write(encrypted_code_base64)


# Encrypt using only public key
def rsa_encrypt_path(public_key, file_path, enc_path):
    code_snippet = read_file(file_path)

    # Get RSA key size in bits
    key_size_bits = public_key.key_size

    max_data_size = (key_size_bits // 8 ) - 2 * hashes.SHA256().digest_size - 2 

    if len(code_snippet) > max_data_size:
        print(f"\n[!] Data size:\t{len(code_snippet)} bytes")
        print(f"[!] Max size:\t{max_data_size} bytes")
        print("\n[x] Error: Data size exceeds maximum allowable size for RSA encryption.")
        sys.exit(0)

    # Encrypt the code snippet
    try:
        encrypted_code = public_key.encrypt(
            code_snippet,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"[*] Error: Encryption failed:\n{e}")
        print("FLAG")
        sys.exit(1)

    save_encrypted_code(encrypted_code, enc_path)

    print("[!] Encryption complete." )
    print("\n[!] Public Key:\n%s" % (public_key))
    print("\n[!] Encrypted path:\n%s " % (enc_path))


# Function to generate RSA key pair
def rsa_generate_keys(basename):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save private key to file
    private_key_path = f"{basename}.pem"
    with open(private_key_path, 'wb') as private_file:
        private_file.write(private_pem)

    # Save public key to file
    public_key_path = f"{basename}_pem.pub"
    with open(public_key_path, 'wb') as public_file:
        public_file.write(public_pem)

    print(f"RSA key pair generated successfully:")
    print(f"Private key saved to: {private_key_path}")
    print(f"Public key saved to: {public_key_path}")


def main():
    # Parse arguments (Public key path is now retrieved from .env via RSA_KEY_PATH)
    if len(sys.argv) != 3:
        print("Usage: python RSA/encryption_rsa.py <payload_path> <enc_path>")
        sys.exit(0)

    payload_path = sys.argv[1]
    enc_path = sys.argv[2]

    # Load and expand public key path from .env
    public_key_env = os.getenv("RSA_KEY_PATH")
    if not public_key_env:
        print("[!] Error: RSA_KEY_PATH is not set in the .env file.")
        sys.exit(1)
    
    public_key_path = os.path.expanduser(public_key_env)

    if not os.path.exists(public_key_path):
        print(f"[!] Correct path for public key is needed: {public_key_path}")
        sys.exit(0)
    if not os.path.exists(payload_path):
        print("[!] Correct path for payload is needed.")
        sys.exit(0)

    # Read the public key
    with open(public_key_path, 'rb') as file:
        pem_key = file.read()

    # Serialize to get the public key
    public_key = serialization.load_pem_public_key(pem_key)
    
    # Encrypt using RSA
    rsa_encrypt_path(public_key, payload_path, enc_path)


if __name__ == "__main__":
    main()
