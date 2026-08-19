#!/bin/bash

# Encrypt credentials
cd /home/ainode/Sync/lockerpy
find $(pwd)/accounts -type f | grep -v bin >> enc_paths/accounts_path && sort -V -u -o enc_paths/accounts_path enc_paths/accounts_path
sudo ./locker.py -rd /home/ainode/Sync/lockerpy/AES_keys/aes_key1.enc -rpem /home/ainode/Sync/lockerpy/RSA/lock.pem -ae -l enc_paths/accounts_path
