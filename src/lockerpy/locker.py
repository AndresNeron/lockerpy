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
from pathlib import Path
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

# Load environment variables from .env file
script_dir = Path(__file__).resolve().parent
env_path = script_dir / "../../.env"

# Load environment variables from the calculated relative path
load_dotenv(dotenv_path=env_path)

# Personal packages
from lockerpy.utils.colors import Colors
from lockerpy.RSA.encryption_rsa import rsa_generate_keys, rsa_encrypt_path
from lockerpy.RSA.decryption_rsa import load_private_key, load_encrypted_code, rsa_decrypt
from lockerpy.AES.encryption_aes import aes_generate_key, aes_encrypt_file
from lockerpy.AES.decryption_aes import aes_decrypt_file

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="[!] Locker - A Python-based tool for encryption operations.")
    parser.add_argument("-p",   "--path",        help="\t\tPath to file for encryption or decryption.")
    parser.add_argument("-l",   "--list",        help="\t\tPath to file with list for encryption or decryption.")
    parser.add_argument("-ag",  "--aes_gen",     help="\t\tPath to new AES key.")
    parser.add_argument("-rg",  "--rsa_gen",     help="\t\tPath to new RSA key pair.")
    
    parser.add_argument("-re",  "--rsa_encrypt",    help="\t\tPath to plain text symmetric key.")
    parser.add_argument("-rpub","--rsa_public",     help="\t\tPath to public key path for RSA encryption.")

    parser.add_argument("-rd",  "--rsa_decrypt",    nargs="?", const="ENV", help="\t\tPath to encrypted symmetric key (or uses .env if omitted).")
    parser.add_argument("-rpem","--rsa_private",    nargs="?", const="ENV", help="\t\tPath to private key for RSA decryption (or uses .env if omitted).")

    parser.add_argument("-ae",  "--aes_encrypt", action="store_true", help="\t\tFile to encrypt using AES algorithm and decrypted symmetric key.")
    parser.add_argument("-ad",  "--aes_decrypt", action="store_true", help="\t\tFile to decrypt using AES algorithm.")
    parser.add_argument("-s",   "--save",        action="store_true", help="\t\tSave decrypted content to disk, delete encrypted file, instead of printing to stdout.")
    parser.add_argument("-v",   "--verbose",     action="store_true", help="\t\tEnable verbose logging output to stdout.")

    return parser.parse_args()


# Delete old path for preserving the encrypted o decrypted version
def delete_file(path, verbose=True):
    if os.path.exists(path):
        try:
            os.remove(path)
            if verbose:
                print(Colors.ORANGE + f"[!] File has been deleted successfully:\t{path}" + Colors.R)
        except Exception as e:
            if verbose:
                print(Colors.RED + f"[x] An error ocurred while removing {path}:\n{e}" + Colors.R)


# Compress a file using gzip
def compress_gzip(input_file, verbose=True):
    output_file = input_file + ".gz"

    with open(input_file, 'rb') as f_in:
        with gzip.open(output_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    if verbose:
        print(Colors.BOLD_WHITE + f"\n[!] File compresses using gzip:\n{output_file}\n" + Colors.R)
    return output_file


# Workflow for encrypting or decrypting with AES based in args
def aes_treat_file(args, symmetric_key, path, enc_path):
    verbose = args.verbose
    
    if path and not os.path.exists(path):
        if verbose:
            print(Colors.RED + f"[-] Skipping (path not found): {path}" + Colors.R)
        return

    ## Case for encrypting using AES and decrypted symmetric key.
    if args.aes_encrypt and path:
        path_gz = compress_gzip(path, verbose=verbose)
        aes_encrypt_file(symmetric_key, path_gz)
        delete_file(path, verbose=verbose)
        delete_file(path_gz, verbose=verbose)

    ## Case for decryption using AES and decrypted symmetric key. 
    elif args.aes_decrypt and path:
        decrypted_content = aes_decrypt_file(symmetric_key, path)

        if decrypted_content is None:
            return

        try:
            # Decompress the gzip layer inside the decrypted content
            with gzip.GzipFile(fileobj=BytesIO(decrypted_content)) as gz:
                decompressed_content = gz.read()
            
            # If the save flag (-s) is enabled, write to disk and remove encrypted source
            if args.save:
                if path.endswith(".enc"):
                    output_file_path = path[:-4]  # removes .enc -> filename.json.gz (or filename.json)
                elif path.endswith(".bin"):
                    output_file_path = path[:-4]
                else:
                    output_file_path = path + ".decrypted"

                if output_file_path.endswith(".gz"):
                    output_file_path = output_file_path[:-3]

                with open(output_file_path, 'wb') as out_f:
                    out_f.write(decompressed_content)

                if verbose:
                    print(Colors.GREEN + f"[!] Decrypted and saved: {path} -> {output_file_path}" + Colors.R)
                
                # Delete the encrypted source file after successful save
                delete_file(path, verbose=verbose)
            
            # Default behavior: print to stdout
            else:
                if verbose:
                    print(Colors.GREEN + f"\n[!] Decrypted content from {path}:\n{Colors.R}" + decompressed_content.decode('utf-8'))
                else:
                    print(decompressed_content.decode('utf-8'), end="")
        
        except Exception as e:
            if verbose:
                print(Colors.RED + f"[-] Error processing {path}: {e}" + Colors.R)


def main():
    args = parse_arguments()
    verbose = args.verbose

    # Generate a new symmetric AES key
    if args.aes_gen:
        key = aes_generate_key()
        key_base64 = base64.b64encode(key).decode('utf-8')
        with open(args.aes_gen, 'w') as file:
            file.write(key_base64)
            if verbose:
                print(Colors.GREEN + f"[!] Key created successfully and saved into:\n{args.aes_gen}" + Colors.R)
        sys.exit(0)

    # Generate a new RSA key pair
    if args.rsa_gen:
        rsa_generate_keys(args.rsa_gen)
        sys.exit(0)

    # Case for RSA encryption
    if args.rsa_encrypt and args.rsa_public:
        enc_path = args.rsa_encrypt + ".enc"
        public_key_path = args.rsa_public

        if not os.path.exists(public_key_path):
            sys.exit(0)

        with open(public_key_path, 'rb') as file:
            public_key = file.read()

        public_key = serialization.load_pem_public_key(public_key)
        rsa_encrypt_path(public_key, args.rsa_encrypt, enc_path)
        delete_file(args.rsa_encrypt, verbose=verbose)
        sys.exit(0)

    # Case for RSA decryption & AES Operations
    if (args.rsa_decrypt is not None or args.aes_decrypt or args.aes_encrypt) and not args.rsa_encrypt:
        
        # Resolve Encrypted Symmetric Key path
        if args.rsa_decrypt == "ENV" or args.rsa_decrypt is None:
            enc_path_env = os.getenv("AES_KEY_PATH")
            if not enc_path_env:
                if verbose:
                    print(Colors.RED + "[x] Error: AES_KEY_PATH not found in environment." + Colors.R)
                sys.exit(1)
            enc_path = os.path.expanduser(enc_path_env)
        else:
            enc_path = args.rsa_decrypt

        # Resolve Private RSA Key path
        if args.rsa_private == "ENV" or args.rsa_private is None:
            private_key_env = os.getenv("RSA_KEY_PATH")
            if not private_key_env:
                if verbose:
                    print(Colors.RED + "[x] Error: RSA_KEY_PATH not found in environment." + Colors.R)
                sys.exit(1)
            private_key_path = os.path.expanduser(private_key_env)
        else:
            private_key_path = args.rsa_private

        if not os.path.exists(enc_path) or not os.path.exists(private_key_path):
            if verbose:
                print(Colors.RED + f"[x] Invalid input paths for RSA decryption.\nEncrypted Key: {enc_path}\nPrivate Key: {private_key_path}" + Colors.R)
            sys.exit(1)

        # Read the private key
        with open(private_key_path, 'rb') as file:
            private_key_pem = file.read()

        private_key = load_private_key(private_key_pem)
        encrypted_code = load_encrypted_code(enc_path)

        # Decrypt symmetric key using RSA
        symmetric_key = rsa_decrypt(private_key, encrypted_code)
        if verbose:
            print(f"{Colors.GREEN}[!] RSA decryption success!{Colors.R}")

        # When -p is provided apply workflow for a single file (resolve relative to original invocation directory)
        if args.path:
            base_dir = os.getenv("ORIGINAL_PWD", os.getcwd())
            resolved_path = os.path.abspath(os.path.expanduser(os.path.join(base_dir, args.path)))
            aes_treat_file(args, symmetric_key, resolved_path, enc_path)

        # When -l is provided apply workflow to each file in args.list
        elif args.list is not None:
            base_dir = os.getenv("ORIGINAL_PWD", os.getcwd())
            list_path = os.path.abspath(os.path.expanduser(os.path.join(base_dir, args.list)))
            if os.path.exists(list_path):
                with open(list_path, 'r') as file:
                    for path in file:
                        path = path.strip()
                        if path:
                            resolved_list_item = os.path.abspath(os.path.join(os.path.dirname(list_path), path))
                            aes_treat_file(args, symmetric_key, resolved_list_item, enc_path)


if __name__ == "__main__":
    main()
