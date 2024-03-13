import os
import random
import string


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

gerar("RSA")


#===================B===================