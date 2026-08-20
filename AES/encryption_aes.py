#!/usr/bin/env python3

import os
import sys
import gzip
import shutil
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# Load environment variables from .env file
load_dotenv()

# Personal packages
from utils.colors import Colors

# Function to generate a random AES key
def aes_generate_key():
    return os.urandom(32)  # 256-bit key


# Compress a file using gzip
def compress_gzip(input_file):
    output_file = input_file + ".gz"

    with open(input_file, 'rb') as f_in:
        with gzip.open(output_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    print(f"\n[!] File compresses using gzip:\n{output_file}\n")
    return output_file


# Function to encrypt a message using AES
def encrypt_message(key, plaintext):
    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Pad the plaintext to ensure it is a multiple of the block size
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Return the IV and ciphertext
    return iv + ciphertext


# Function to save the AES key and encrypted message to files
def save_to_files(key, encrypted_message, key_path, enc_message_path):
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
    with open(enc_message_path, 'wb') as enc_file:
        enc_file.write(encrypted_message)


# Method for encrypting a complete file using AES
def aes_encrypt_file(key, file_path):

    if os.path.exists(file_path):
        # Read the plaintext message from a file
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        # Convert base64 to bytes object
        key = base64.b64decode(key)

        # Encrypt the message
        print(Colors.ORANGE + f"[!] Encrypting with AES:\t{file_path}\n" + Colors.R)
        encrypted_content = encrypt_message(key, plaintext)

        # Encode the encrypted content again
        encrypted_content = base64.b64encode(encrypted_content).decode('utf-8')

        # Save the encrypted file
        encrypted_file = file_path + ".enc"
        with open(encrypted_file, 'w') as file:
            file.write(encrypted_content)
            print(Colors.GREEN + f"\n[!] Encrypted result saved into:\t{encrypted_file}\n" + Colors.R)


# Main script
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./encryption_aes.py <payload_path>")
        sys.exit(1)

    input_file_path = sys.argv[1]

    if not os.path.exists(input_file_path):
        print(f"[!] Error: Payload path does not exist: {input_file_path}")
        sys.exit(1)

    # Load AES key path from environment variable and expand '~'
    key_env = os.getenv("AES_KEY_PATH")
    if not key_env:
        print("[!] Error: AES_KEY_PATH is not set in the .env file.")
        sys.exit(1)
    
    key_file_path = os.path.expanduser(key_env)
    key_dir = os.path.dirname(key_file_path)

    if key_dir and not os.path.exists(key_dir):
        os.makedirs(key_dir, exist_ok=True)

    encrypted_message_file_path = input_file_path + ".enc"

    # Read the plaintext message from a file
    with open(input_file_path, 'rb') as file:
        plaintext = file.read()

    # Generate a random AES key
    key = aes_generate_key()

    # Encrypt the message
    print(f"[!] Encrypting:\t\t{input_file_path}")
    encrypted_message = encrypt_message(key, plaintext)

    # Save the AES key and encrypted message to files
    save_to_files(key, encrypted_message, key_file_path, encrypted_message_file_path)

    print("[!] Encryption complete.\n")
    print(f"[!] key : {key_file_path}")
    print(f"[!] enc : {encrypted_message_file_path}")
