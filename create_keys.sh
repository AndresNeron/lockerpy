#!/bin/bash

# Define paths
PARENT_PATH="$(dirname "$(realpath "$0")")"
cd "$PARENT_PATH"

# Create directories where keys will live
mkdir -p AES_keys/ lockerpy/src/lockerpy/RSA/

# Create AES key
locker -ag AES_keys/aes_key1

# Create RSA key
locker -rg lockerpy/src/lockerpy/RSA/lock

# Cipher AES key with RSA public key
locker -re AES_keys/aes_key1 -rpub src/lockerpy/RSA/lock_pem.pub

# Setup the .env to start ciphering content
cat << EOF > '.env'
AES_KEY_PATH=$PARENT_PATH/AES_keys/aes_key1.enc
RSA_KEY_PATH=$PARENT_PATH/lockerpy/src/lockerpy/RSA/lock.pem
EOF 
