from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import time

def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Generate key pair
private_key, public_key = generate_keypair()

# Message to encrypt
message = b"Hello, this is a test message to be encrypted!"

# Measure encryption time
start_time = time.time()
encrypted_message = encrypt(message, public_key)
encryption_time = time.time() - start_time

# Measure decryption time
start_time = time.time()
decrypted_message = decrypt(encrypted_message, private_key)
decryption_time = time.time() - start_time

# Print results
print(f"\nEncryption Time:", encryption_time, "seconds")
print(f"\nDecryption Time:", decryption_time, "seconds")
