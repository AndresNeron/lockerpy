from Crypto.PublicKey import Kyber
import base64

# Function to generate Kyber key pair
def generate_kyber_key_pair():
    # Generate a new Kyber key pair
    private_key = Kyber.generate(private_key_format='raw')
    public_key = private_key.public_key().export(format='raw')

    return private_key, public_key

# Function to encrypt data using Kyber public key
def kyber_encrypt(public_key, plaintext):
    # Encrypt the plaintext using the public key
    ciphertext, shared_secret = Kyber.encrypt(public_key, plaintext)
    return ciphertext, shared_secret

# Function to decrypt data using Kyber private key
def kyber_decrypt(private_key, ciphertext):
    # Decrypt the ciphertext using the private key
    shared_secret = Kyber.decrypt(private_key, ciphertext)
    return shared_secret

# Main function to demonstrate Kyber encryption and decryption
def main():
    # Step 1: Generate Kyber key pair
    private_key, public_key = generate_kyber_key_pair()
    print("[+] Kyber key pair generated successfully.")

    # Step 2: Encrypt a message
    plaintext = b"Hello, Kyber post-quantum encryption!"
    print(f"[+] Plaintext: {plaintext.decode('utf-8')}")

    ciphertext, shared_secret_enc = kyber_encrypt(public_key, plaintext)
    print(f"[+] Ciphertext (Base64): {base64.b64encode(ciphertext).decode('utf-8')}")
    print(f"[+] Shared Secret (Base64): {base64.b64encode(shared_secret_enc).decode('utf-8')}")

    # Step 3: Decrypt the message
    shared_secret_dec = kyber_decrypt(private_key, ciphertext)
    print(f"[+] Decrypted Shared Secret (Base64): {base64.b64encode(shared_secret_dec).decode('utf-8')}")

    # Step 4: Verify the shared secrets match
    if shared_secret_enc == shared_secret_dec:
        print("[+] Encryption and decryption successful! Shared secrets match.")
    else:
        print("[-] Error: Shared secrets do not match.")

if __name__ == "__main__":
    main()
