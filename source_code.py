import os
import random
import string
import timeit, time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as padding_2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

#files names
FILES_AES = ["type_AES__size_8.txt","type_AES__size_64.txt","type_AES__size_512.txt","type_AES__size_4096.txt","type_AES__size_32768.txt","type_AES__size_262144.txt","type_AES__size_2097152.txt"]
FILES_RSA = ["type_RSA__size_2.txt","type_RSA__size_4.txt","type_RSA__size_8.txt","type_RSA__size_16.txt","type_RSA__size_32.txt","type_RSA__size_64.txt","type_RSA__size_128.txt"]
FILES_SHA = ["type_SHA__size_8.txt","type_SHA__size_64.txt","type_SHA__size_512.txt","type_SHA__size_4096.txt","type_SHA__size_32768.txt","type_SHA__size_262144.txt","type_SHA__size_2097152.txt"]



#=======================================#
#=================CODE==================#
#=======================================#


#===================A===================#
#CODE TO GENERATE FILES#

# Gera uma string aleatória de comprimento length 
# Random.choice seleciona caracteres aleatórios 
def generate_text(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

# Gera um arquivo de texto no caminho especificado com o tamanho em bytes fornecido (argumentos da função)
# Chama a função generate_text para gerar o texto a ser escrito no arquivo e depois escreve esse texto no arquivo
def generate_file(file_path, file_size_bytes):
    """Generate a text file with given file size."""
    with open(file_path, 'w') as file:
        text_to_right = generate_text(file_size_bytes)
        file.write(text_to_right)

# Com base no argumento passado á função, escolhe o método de criptografia a ser usado ('AES', 'SHA' ou 'RSA')
# Para cada tamanho de aequivo associado ao tipo de criptografia escolhido, gera um arquivo de texto
def gerar(file_type, print_q: str):
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
        if print_q == 'y':
            print(f"Generated text file '{file_path}' with size {os.path.getsize(file_path)} bytes.")
    print("")



#===================B===================#
#1 para avaliar sempre os mesmos ficheiros
#2 para avaliar com diferentes ficheiros
def AES(print_q: str):
    # Gera uma chave aleatória de 256 bits (32 bytes)
    # E um vetor de inicialização (IV) de 16 bytes
    # O print mostra a chave e o IV em formato hexadecimal
    key = os.urandom(32)  
    iv = os.urandom(16)
    num_file = 0

    tempos = []

    for f_id in FILES_AES:
        with open(f_id, 'rb') as file:
            time_decr = time_encr = 0

            if num_file < 3:
                n_iteracoes = 500
            else: n_iteracoes = 100
            
            if(print_q == 'y'):
                print(f"Starting! {f_id}")
            
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
                if i > 10:
                    time_encr += (timeit.default_timer() - start_timer)*10e6

                ##decrypting
                decryptor = cipher.decryptor()

                start_timer = timeit.default_timer() #timer
                decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                if i > 10:
                    time_decr += (timeit.default_timer() - start_timer)*10e6
            
            tempos.append([time_encr/(n_iteracoes-10), time_decr/(n_iteracoes-10)])
            if(print_q == 'y'):
                print(f"Media do tempo para encryptar: {time_encr/(n_iteracoes-10):.3f} microseconds\nMedia do tempo para decryptar: {time_decr/(n_iteracoes-10):.3f} microseconds")
                print(f"Done! {f_id}\n")
        num_file += 1
    return tempos

def AES_diff_files():
    total = 10 
    tempo_total = [[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]]
    for i in range(total):
        gerar("AES",'n')
        tempos = AES('n')
        for j in range (len(tempos)):
            tempo_total[j][0] += tempos[j][0]
            tempo_total[j][1] += tempos[j][1]
    i = 0
    print(f"Foram gerados {total} vezes ficheiros diferentes\n")
    for f in FILES_AES:
        print(f"Ficheiro {f}\nMedia do tempo para encryptar: {tempo_total[i][0]/total:.3f} microseconds\nMedia do tempo para decryptar: {tempo_total[i][1]/total:.3f} microseconds\n")    
        i += 1
    return tempo_total


#===================C===================#
#funcoes auxiliares
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
        padding_2.OAEP(
            mgf=padding_2.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding_2.OAEP(
            mgf=padding_2.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

#1 para avaliar sempre os mesmos ficheiros
#2 para avaliar com diferentes ficheiros
def RSA(print_q: str):
    # Generate key pair
    private_key, public_key = generate_keypair()
    tempos = []

    for f_id in FILES_RSA:
        num_file = 0

        with open(f_id, 'rb') as file:
            time_decr = time_encr = 0
            plaintext = file.read()

            if num_file < 3:
                n_iteracoes = 500
            else: n_iteracoes = 100
            
            if(print_q == 'y'):
                print(f"Starting! {f_id}")
            
            for i in range(n_iteracoes):
                # Measure encryption time
                start_time = timeit.default_timer()
                encrypted_message = encrypt(plaintext, public_key)
                if i > 10:
                    time_encr += (timeit.default_timer() - start_time)*10e6

                # Measure decryption time
                start_time = timeit.default_timer()
                decrypted_message = decrypt(encrypted_message, private_key)
                if i > 10:
                    time_decr += (timeit.default_timer() - start_time)*10e6


            tempos.append([time_encr/(n_iteracoes-10), time_decr/(n_iteracoes-10)])
            # Print results
            if(print_q == 'y'):
                print(f"Media do tempo para encryptar: {time_encr/(n_iteracoes-10):.3f} microseconds\nMedia do tempo para decryptar: {time_decr/(n_iteracoes-10):.3f} microseconds")
                print(f"Done! {f_id}\n")

        num_file += 1
    return tempos

def RSA_diff_files():
    total = 10 
    tempo_total = [[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]]
    for i in range(total):
        gerar("RSA",'n')
        tempos = RSA('n')
        for j in range (len(tempos)):
            tempo_total[j][0] += tempos[j][0]
            tempo_total[j][1] += tempos[j][1]
    i = 0
    print(f"Foram gerados {total} vezes ficheiros diferentes\n")
    for f in FILES_AES:
        print(f"Ficheiro {f}\nMedia do tempo para encryptar: {tempo_total[i][0]/total:.3f} microseconds\nMedia do tempo para decryptar: {tempo_total[i][1]/total:.3f} microseconds\n")    
        i += 1
    return tempo_total


#===================D===================#
        

def SHA256(print_q: str): 
    tempos = []
    n_iteracoes = 500
    num_file = 0

    for f_id in FILES_SHA:
        time_taken = 0
        if(print_q == 'y'):
            print(f"Starting! {f_id}")
        
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

                if i > 10:
                    time_taken += (timeit.default_timer() - start_time)*10e6

            tempos.append(time_taken/(n_iteracoes-10))
            digest.finalize()

            if(print_q == 'y'):
                print(f"Media do tempo para aplicar algoritmo: {time_taken/(n_iteracoes-10):.3f} microseconds")
                print(f"Done! {f_id}\n")

        num_file +=1 

    return tempos

def SHA256_diff_files():
    total = 10 
    tempo_total = [0,0,0,0,0,0,0]
    for i in range(total):
        gerar("SHA",'n')
        tempos = SHA256('n')
        for j in range (len(tempos)):
            tempo_total[j] += tempos[j]
    i = 0
    print(f"Foram gerados {total} vezes ficheiros diferentes\n")
    for f in FILES_SHA:
        print(f"Ficheiro {f}\nMedia do tempo para aplicar algoritmo: {tempo_total[i]/total:.3f} microseconds\n")
        i += 1
    return tempo_total

#===============Main Funcion============#

def main():
    print("A criar todos os ficheiros necessarios:\n")
    gerar("AES",'y')
    gerar("SHA",'y')
    gerar("RSA",'y')

    what_to_do = 0 # 1 -> AES | 2 -> RSA | 3 -> SHA | -1 -> end
    while what_to_do != -1:
        print(f"\n\n1: Benchmark for AES (point B)")
        print(f"2: Benchmark for RSA (point C)")
        print(f"3: Benchmark for SHA (point D)")
        print(f"-1: to end\n")
        what_to_do = int(input("Escolha a opcao: "))


        if what_to_do == 1:
            print(f"\nBenchmark for AES")
            qual = int(input(f"1: Usar sempre os mesmos ficheiro\n2: Usar diferentes ficheiros\nEscolha: "))
            print(f"")
            if qual == 1:
                AES('y')    
            else: AES_diff_files()    
            time.sleep(0.5)

        elif what_to_do == 2:
            print(f"\nBenchmark for RSA")
            qual = int(input(f"1: Usar sempre os mesmos ficheiro\n2: Usar diferentes ficheiros\nEscolha: "))
            print(f"")
            if qual == 1:
                RSA('y')  
            else: RSA_diff_files()    
            time.sleep(0.5)

        elif what_to_do == 3:
            print(f"\nBenchmark for SHA")
            qual = int(input(f"1: Usar sempre os mesmos ficheiro\n2: Usar diferentes ficheiros\nEscolha: "))
            print(f"")
            if qual == 1:
                SHA256('y')  
            else: SHA256_diff_files() 
            time.sleep(0.5)


if __name__ == "__main__":
    main()

