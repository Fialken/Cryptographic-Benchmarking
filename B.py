import os
import timeit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from binascii import hexlify


# List of files to be encrypted and decrypted
files_AES = ["type_AES__size_8.txt","type_AES__size_64.txt","type_AES__size_512.txt","type_AES__size_4096.txt","type_AES__size_32768.txt","type_AES__size_262144.txt","type_AES__size_2097152.txt"]

key = os.urandom(32)  # 256-bit key
iv = os.urandom(16)
print(f"key: {hexlify(key)}")
print(f"iv: {hexlify(iv)}\n")


for f_id in files_AES:
    with open(f_id, 'rb') as file:

        print(f"Starting! {f_id}")

        #setup data
        data = file.read()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        ##encryption setup
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

        ##encrypting
        encryptor = cipher.encryptor()

        start_timer = timeit.default_timer() #timer
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        print(f"Time to encrypt: {(timeit.default_timer() - start_timer):.9f}")

        ##decrypting
        decryptor = cipher.decryptor()

        start_timer = timeit.default_timer() #timer
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        print(f"Time to decrypt: {(timeit.default_timer() - start_timer):.9f}")



        '''##remove padding apos decrypt, para analisar se esta correto
        ##nao faz parte da entrega 
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        #print(f"decrypted data: {decrypted_data}")'''


        print(f"Done! {f_id}\n")