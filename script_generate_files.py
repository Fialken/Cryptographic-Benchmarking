import os
import random
import string
import timeit


#temporario
files_AES = ["type_AES__size_8.txt","type_AES__size_64.txt","type_AES__size_512.txt","type_AES__size_4096.txt","type_AES__size_32768.txt","type_AES__size_262144.txt","type_AES__size_2097152.txt"]
files_SHA = ["type_SHA__size_8.txt","type_SHA__size_64.txt","type_SHA__size_512.txt","type_SHA__size_4096.txt","type_SHA__size_32768.txt","type_SHA__size_262144.txt","type_SHA__size_2097152.txt"]
files_RSA = ["type_RSA__size_2.txt","type_RSA__size_4.txt","type_RSA__size_8.txt","type_RSA__size_16.txt","type_RSA__size_32.txt","type_RSA__size_64.txt","type_RSA__size_128.txt"]



#===================A===================
def generate_text(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def generate_file(file_path, file_size_bytes):
    """Generate a text file with given file size."""
    with open(file_path, 'w') as file:
        text_to_right = generate_text(file_size_bytes)
        file.write(text_to_right)

def gerar(file_type):
    ''' Choose what encryption method to generate files '''
    aes = [8, 64, 512, 4096, 32768, 262144, 2097152]
    sha = [8, 64, 512, 4096, 32768, 262144, 2097152]
    rsa = [2, 4, 8, 16, 32, 64, 128]

    if file_type == "AES": sizes = aes 
    elif file_type == "SHA": sizes = sha
    elif file_type == "RSA": sizes = rsa
    else: 
        print("No file generated, wrong type input")
        return
    
    for size in sizes:
        file_path = f'type_{file_type}__size_{size}.txt'
        generate_file(file_path, size)
        print(f"Generated text file '{file_path}' with size {os.path.getsize(file_path)} bytes.")


gerar("AES")


#===================B===================
        
    
#===================C===================
        
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
