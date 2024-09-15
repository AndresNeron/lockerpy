#!/usr/bin/env python3

import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# Personal packages
from utils.colors import Colors

# Function to load the AES key and encrypted message from files
def load_from_files(key_path, enc_message_path):
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
    with open(enc_message_path, 'rb') as enc_file:
        encrypted_message = enc_file.read()
    return key, encrypted_message


# Function to decrypt a message using AES
def decrypt_message(key, encrypted_message):
    # Extract the IV from the beginning of the encrypted message
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]

    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


# Method for decrypting a complete file using AES
# Assuming the encrypted content was compressed with gzip before encryption
def aes_decrypt_file(key, encrypted_file):
    if os.path.exists(encrypted_file):
        # Read the base64 encoded encrypted from a file
        with open(encrypted_file, 'r') as file:
            encrypted_content = file.read()

        # Convert encrypted content from base64 to bytes
        encrypted_content = base64.b64decode(encrypted_content)
        key = base64.b64decode(key)

        # Decrypt the bytes encrypted content
        decrypted_content = decrypt_message(key, encrypted_content)
        
        ## This lines are not necessary when the file was decompressed
        #decrypted_content = decrypted_content.decode()

        # Save the decrypted file without the '.bin' termination
        #decrypted_file = encrypted_file[:-4]
        #with open(decrypted_file, 'w') as file:
        #    file.write(decrypted_content)
        #    print(Colors.GREEN + f"\n[!] Decrypted result saved into:\t{decrypted_file}\n" + Colors.R)
            #print(decrypted_content)

        return decrypted_content


# Main script
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 decrypt_aes.py <key_file_path> <encrypted_message_file_path>")
        sys.exit(1)

    key_file_path = sys.argv[1]
    encrypted_message_file_path = sys.argv[2]

    if os.path.exists(encrypted_message_file_path) is False:
        os.mkdir(encrypted_message_file_path)

    # Load the AES key and encrypted message from files
    key, encrypted_message = load_from_files(key_file_path, encrypted_message_file_path)

    # Decrypt the message
    decrypted_message = decrypt_message(key, encrypted_message)

    # Print the decrypted message
    print("[!] Decrypted code: \n")
    decoded_code = decrypted_message.decode('utf-8')
    print(decoded_code)
    #exec(decoded)
