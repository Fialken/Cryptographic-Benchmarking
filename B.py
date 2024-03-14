import os
import timeit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
from binascii import hexlify


# Function to pad the data to be a multiple of AES block size
def pad_data(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Function to encrypt data using AES
def encrypt_data(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data

# Function to decrypt data using AES
def decrypt_data(data, key):
    iv = data[:algorithms.AES.block_size]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data[algorithms.AES.block_size:]) + decryptor.finalize()
    return decrypted_data

# Function to measure time taken for encryption and decryption
def measure_time(filename):
    with open(filename, 'r') as f:
        data = f.read()

    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)

    encrypt_timer = timeit.Timer(lambda: encrypt_data(pad_data(data), key, iv))
    decrypt_timer = timeit.Timer(lambda: decrypt_data(encrypt_data(pad_data(data), key, iv), key))

    encrypt_time = encrypt_timer.timeit(number=1)
    decrypt_time = decrypt_timer.timeit(number=1)

    return encrypt_time, decrypt_time

# List of files to be encrypted and decrypted
files_AES = ["type_AES__size_8.txt","type_AES__size_64.txt","type_AES__size_512.txt","type_AES__size_4096.txt","type_AES__size_32768.txt","type_AES__size_262144.txt","type_AES__size_2097152.txt"]
files_SHA = ["type_SHA__size_8.txt","type_SHA__size_64.txt","type_SHA__size_512.txt","type_SHA__size_4096.txt","type_SHA__size_32768.txt","type_SHA__size_262144.txt","type_SHA__size_2097152.txt"]
files_RSA = ["type_RSA__size_2.txt","type_RSA__size_4.txt","type_RSA__size_8.txt","type_RSA__size_16.txt","type_RSA__size_32.txt","type_RSA__size_64.txt","type_RSA__size_128.txt"]


'''
for file in files_AES:
    encrypt_time, decrypt_time = measure_time(file)
    print(f"Time taken to encrypt {file}: {encrypt_time} seconds")
    print(f"Time taken to decrypt {file}: {decrypt_time} seconds")
'''



key = os.urandom(32)  # 256-bit key
iv = os.urandom(16)
print(f"key: {hexlify(key)}")
print(f"iv: {hexlify(iv)}")


#encripting
with open("type_AES__size_8.txt", 'r') as file:
    data = file.read().encode('utf-8')
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    cphFile = open("ciphertext.bin", "wb")
    cphFile.write(encrypted_data)
    cphFile.close()
