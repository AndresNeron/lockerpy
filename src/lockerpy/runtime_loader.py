#!/usr/bin/env python3

import os
import base64
import gzip
from io import BytesIO
from pathlib import Path
from dotenv import load_dotenv


# Forcefully point to your absolute project sync directory
env_path = Path("/home/ainode/Sync/lockerpy/.env")
load_dotenv(dotenv_path=env_path)

# Internal lockerpy modules
from lockerpy.RSA.decryption_rsa import load_private_key, load_encrypted_code, rsa_decrypt
from lockerpy.AES.decryption_aes import aes_decrypt_file

def runtime_decrypt_secret(enc_file_path: str = ".env.gz.enc") -> str:
    """
    Decrypts an encrypted/gzipped secret file at runtime into memory, 
    without leaving plaintext files on disk.
    
    :param enc_file_path: Path to the encrypted file (defaults to '.env.gz.enc')
    :return: Decrypted plaintext content as a string
    """
    # 1. Resolve and expand file paths
    resolved_file_path = os.path.abspath(os.path.expanduser(enc_file_path))
    if not os.path.exists(resolved_file_path):
        raise FileNotFoundError(f"[x] Encrypted secret file not found: {resolved_file_path}")

    rsa_path_env = os.getenv("RSA_KEY_PATH")
    aes_key_path_env = os.getenv("AES_KEY_PATH")

    if not rsa_path_env or not aes_key_path_env:
        raise ValueError("[x] Error: RSA_KEY_PATH or AES_KEY_PATH not set in environment.")

    private_key_path = os.path.expanduser(rsa_path_env)
    enc_sym_key_path = os.path.expanduser(aes_key_path_env)

    if not os.path.exists(private_key_path) or not os.path.exists(enc_sym_key_path):
        raise FileNotFoundError("[x] Invalid key paths for runtime decryption configuration.")

    # 2. Load RSA private key & decrypt the symmetric AES key
    with open(private_key_path, 'rb') as f:
        private_key_pem = f.read()
    
    private_key = load_private_key(private_key_pem)
    encrypted_symmetric_code = load_encrypted_code(enc_sym_key_path)
    symmetric_key = rsa_decrypt(private_key, encrypted_symmetric_code)

    # 3. Decrypt the target secret file using the decrypted AES key
    decrypted_bytes = aes_decrypt_file(symmetric_key, resolved_file_path)
    if decrypted_bytes is None:
        raise RuntimeError(f"[x] Failed to decrypt the file content for: {resolved_file_path}")

    # 4. Un-gzip the payload layer into final plaintext string
    with gzip.GzipFile(fileobj=BytesIO(decrypted_bytes)) as gz:
        decompressed_content = gz.read()

    return decompressed_content.decode('utf-8')


def load_secret(enc_file_path: str = ".env.gz.enc") -> None:
    """
    Decrypts the secret file and loads its key-value pairs directly 
    into os.environ at runtime.
    
    :param enc_file_path: Path to the encrypted file (defaults to '.env.gz.enc')
    """
    try:
        env_data = runtime_decrypt_secret(enc_file_path)
        for line in env_data.splitlines():
            if '=' in line and not line.startswith('#'):
                key, val = line.split('=', 1)
                os.environ[key.strip()] = val.strip()
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        raise
