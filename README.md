# Lockerpy - Encryption Tool

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [License](#license)

## <a name="introduction"></a>Introduction

Lockerpy is a versatile encryption tool written in Python. It supports both AES and RSA encryption algorithms, 
offering features for generating symmetric (AES) and asymmetric (RSA) keys, 
as well as encrypting and decrypting files on the host system. 
Additionally, Lockerpy compresses files before encryption to save space. 
This program is ideal for users who need to secure their data or manage encryption within various cybersecurity workflows.

## <a name="features"></a>Features

- **Generate Keys**: Create new AES and RSA keys for encryption.
- **Encrypt/Decrypt Files**: Encrypt files using AES with RSA-encrypted symmetric keys and decrypt them accordingly.
- **Batch Processing**: Encrypt or decrypt multiple files listed in a text file.
- **Logging**: Track encryption activities in `key_logs.csv` for future reference.

## <a name="usage"></a>Usage

To use the Locker script, execute it from the terminal with various options to perform encryption and decryption tasks:

```bash
./locker.py [options]
```


## <a name="options"></a>Options

Here are the available options for the script:

- -p, --path: Path to a file for encryption or decryption.
- -l, --list: Path to a file containing a list of files for encryption or decryption.
- -ag, --aes_gen: Path to save a newly generated AES key.
- -rg, --rsa_gen: Path to save a newly generated RSA key pair.
- -re, --rsa_encrypt: Path to a plain text symmetric key to encrypt with RSA.
- -rpub, --rsa_public: Path to the public RSA key for encryption.
- -rd, --rsa_decrypt: Path to an RSA-encrypted symmetric key to decrypt.
- -rpem, --rsa_private: Path to the private RSA key for decryption.
- -ae, --aes_encrypt: Encrypt a file using AES with the decrypted symmetric key.
- -ad, --aes_decrypt: Decrypt a file using AES.

## <a name="examples"></a>Examples

Here are some examples of how to use the script:

- Generate a new AES key:

```bash
sudo ./locker.py -ag AES_keys/aes_key1
```

- Generate a new RSA key pair:

```bash
sudo ./locker.py -rg RSA/lock
```

- Encrypt an AES key using RSA:

```bash
sudo ./locker.py -re AES_keys/aes_key1 -rpub RSA/lock_pem.pub
```

- Decrypt an AES key using RSA:

```bash
sudo ./locker.py -rd AES_keys/aes_key1.enc -rpem RSA/lock.pem
```

- Decrypt an AES key and then encrypt a file using AES:

```bash
sudo ./locker.py -rd AES_keys/aes_key1.enc -rpem RSA/lock.pem -ae -p books/important_book.pdf
```

- Decrypt an AES key and then decrypt a file using AES:

```bash
sudo ./locker.py -rd AES_keys/aes_key1.enc -rpem RSA/lock.pem -ad -p books/important_book.pdf.gz.bin
```

- Decrypt an AES key and then encrypt a list of paths using AES:

```bash
sudo ./locker.py -rd AES_keys/aes_key1.enc -rpem RSA/lock.pem -ae -l samples/paths_for_encryption
```

- Decrypt an AES key and then decrypt a list of paths using AES:

```bash
sudo ./locker.py -rd AES_keys/aes_key1.enc -rpem RSA/lock.pem -ad -l samples/paths_for_decryption
```

- Logging: The key_logs.csv file will log which files were encrypted and which key was used for further decryption purposes.

## <a name="installation"></a>Installation

To use this script, clone the GitHub repository and install the necessary dependencies using pip:

```bash
git clone https://github.com/AndresNeron/lockerpy.git
cd lockerpy
pip install -r requirements.txt
```

Protect your code using symmetric (AES) and asymmetric (RSA) algorithms with ease using Lockerpy!
The encrypted binary data is base64 encoded after AES encryption. You can decrypt your AES key using your RSA private key to finally 
decrypt your file.

## <a name="license"></a>License

This project is licensed under the MIT License, which means you are free to use, modify, 
and distribute the code according to the terms of the license. 
