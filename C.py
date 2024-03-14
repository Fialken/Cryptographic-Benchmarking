from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import timeit
from binascii import hexlify


def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
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



files_RSA = ["type_RSA__size_2.txt","type_RSA__size_4.txt","type_RSA__size_8.txt","type_RSA__size_16.txt","type_RSA__size_32.txt","type_RSA__size_64.txt","type_RSA__size_128.txt"]

private_key, public_key = generate_keypair()

for f_id in files_RSA:
    with open(f_id, 'rb') as file:

        print(f"Starting! {f_id}")
        data = file.read()
        
        #encrypt
        start_timer = timeit.default_timer() #timer
        encrypted_message = encrypt(data, public_key)
        print(f"Time to decrypt: {(timeit.default_timer() - start_timer):.9f}")


        #decrypt
        start_timer = timeit.default_timer() #timer
        decrypted_message = decrypt(encrypted_message, private_key)
        print(f"Time to decrypt: {(timeit.default_timer() - start_timer):.9f}")
    
        print(f"Done! {f_id}\n")