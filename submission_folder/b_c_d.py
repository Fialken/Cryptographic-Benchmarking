import os
import timeit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as padding_2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

FILES_AES = ["type_AES__size_8.txt","type_AES__size_64.txt","type_AES__size_512.txt","type_AES__size_4096.txt","type_AES__size_32768.txt","type_AES__size_262144.txt","type_AES__size_2097152.txt"]
FILES_SHA = ["type_SHA__size_8.txt","type_SHA__size_64.txt","type_SHA__size_512.txt","type_SHA__size_4096.txt","type_SHA__size_32768.txt","type_SHA__size_262144.txt","type_SHA__size_2097152.txt"]
FILES_RSA = ["type_RSA__size_2.txt","type_RSA__size_4.txt","type_RSA__size_8.txt","type_RSA__size_16.txt","type_RSA__size_32.txt","type_RSA__size_64.txt","type_RSA__size_128.txt"]



#===================B===================#
def AES():
    # Gera uma chave aleatória de 256 bits (32 bytes)
    # E um vetor de inicialização (IV) de 16 bytes
    # O print mostra a chave e o IV em formato hexadecimal
    key = os.urandom(32)  
    iv = os.urandom(16)
    num_file = 0 # os primeiros 3 ficheiros sao considerados pequenos logo fazemos mais iteracos para calcular uma media do tempo
    tempos = []

    for f_id in FILES_AES:
        with open(f_id, 'rb') as file:
            time_decr = time_encr = 0

            if num_file < 3:
                n_iteracoes = 500 #ficheiros pequenos fazemos 500 iteracoes
            else: n_iteracoes = 100 #ficheiro maiores fazemos 100 iteracoes
            
            for i in range(n_iteracoes):

                #setup data, whit padding
                data = file.read()
                padder = padding.PKCS7(algorithms.AES.block_size).padder()
                padded_data = padder.update(data) + padder.finalize()

                ##encryption setup
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv),backend=default_backend())

                ##encrypting
                encryptor = cipher.encryptor()

                start_timer = timeit.default_timer() #timer
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                if i > 10: #para ignorar as 10 primeiras iteracoes
                    time_encr += (timeit.default_timer() - start_timer)*10e6

                ##decrypting
                decryptor = cipher.decryptor()

                start_timer = timeit.default_timer() #timer
                decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                if i > 10: #para ignorar as 10 primeiras iteracoes
                    time_decr += (timeit.default_timer() - start_timer)*10e6
            
            tempos.append([time_encr/(n_iteracoes-10), time_decr/(n_iteracoes-10)])
        num_file += 1
    return tempos



#===================C===================#
#funcoes auxiliares
def generate_keypair(): #para criar as chaves, privada e publica
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(message, public_key): #para encryptar o plaintext
    ciphertext = public_key.encrypt(
        message,
        padding_2.OAEP(
            mgf=padding_2.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(ciphertext, private_key): #para decryptar o plaintext
    plaintext = private_key.decrypt(
        ciphertext,
        padding_2.OAEP(
            mgf=padding_2.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def RSA():
    private_key, public_key = generate_keypair() # gerar um par de keys
    tempos = []
    n_iteracoes = 500 #os ficheiros sao pequenos logo fazemos sempre 500 iteracoes

    for f_id in FILES_RSA:

        with open(f_id, 'rb') as file:
            time_decr = time_encr = 0
            plaintext = file.read()
            
            for i in range(n_iteracoes):
                # Measure encryption time
                start_time = timeit.default_timer()
                encrypted_message = encrypt(plaintext, public_key)
                if i > 10: #para ignorar as 10 primeiras iteracoes
                    time_encr += (timeit.default_timer() - start_time)*10e6

                # Measure decryption time
                start_time = timeit.default_timer()
                decrypted_message = decrypt(encrypted_message, private_key)
                if i > 10: #para ignorar as 10 primeiras iteracoes
                    time_decr += (timeit.default_timer() - start_time)*10e6

            tempos.append([time_encr/(n_iteracoes-10), time_decr/(n_iteracoes-10)])

    return tempos



#===================D===================#
def SHA256(): 
    tempos = []
    n_iteracoes = 500
    num_file = 0

    for f_id in FILES_SHA:
        time_taken = 0
        
        if num_file < 3:
            n_iteracoes = 500
        else: n_iteracoes = 100

        with open(f_id, 'rb') as file:
            plaintext = file.read()

            for i in range(n_iteracoes):
                digest = hashes.Hash(hashes.SHA256())
                #apply algoritm
                start_time = timeit.default_timer()
                digest.update(plaintext) 

                if i > 10: #para ignorar as 10 primeiras iteracoes
                    time_taken += (timeit.default_timer() - start_time)*10e6

            tempos.append(time_taken/(n_iteracoes-10))
            digest.finalize()

        num_file +=1 
    return tempos

