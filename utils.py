from des1 import *
from random import randint


lower_case = {chr(i+71):i for i in range(26,52)}
upper_case = {chr(i+65):i for i in range(0,26)}
letters = upper_case | lower_case
letters_list = list(letters.keys())

a = 250
b = 479

def generate_non_zero_k():
    k_prime = 0

    while k_prime == 0:
        k = randint(1, 1000000)  # generate random number
        k_prime = (a - k + b) % 52

    return k

def decrypt_cipher(ciphertext, k_prime):
    decryption = ''

    for i in range(len(ciphertext)):
        y = ciphertext[i]

        if y in letters_list:
            y_index = letters[y]
            x = (y_index - k_prime) % 52
            decryption += letters_list[x]

        else:
            decryption += y

    return decryption;

def shift_cipher(plaintext, k_prime):
    ciphertext = ''
    # Loop through the plain text
    for i in range(len(plaintext)):
        x = plaintext[i]

        if x in letters_list:
            x_index = letters[x]
            y = (x_index + k_prime) % 52
            ciphertext += letters_list[y]

        else:
            ciphertext += x

    return ciphertext

def receive_message(client_socket, HEADER_LENGTH):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)

        if not len(message_header):
            return

        message_length = int(message_header.decode('utf-8').strip())
        return {"header": message_header, "data": client_socket.recv(message_length)}

    except Exception as e:
        return e


def decrypt_message(message, SHARED_KEY):
    same_line_list = []
    plaintext_list = []
    for i in message:
        if isinstance(i, list):
            for x in i:
                plt = bin2hex(encrypt(x.strip(), SHARED_KEY.strip(), True))
                same_line_list.append(plt)
                if len(same_line_list) == len(i):
                    plaintext_list.append(same_line_list)
                    same_line_list = []

        else:
            pt = bin2hex(encrypt(i.strip(), SHARED_KEY.strip(), True))
            plaintext_list.append(pt)
            # print(message_text)

    return plaintext_list

def encrypt_txt_lines(lines, SHARED_KEY):
    same_line_list = []
    ciphertext_list = []
    for i in lines:
        if len(i.strip()) > 16:
            same_line = i.split(' ')
            for x in same_line:
                same_line_encrypt = bin2hex(encrypt(x.strip(), SHARED_KEY.strip()))
                same_line_list.append(same_line_encrypt)
                if len(same_line_list) == len(same_line):
                    ciphertext_list.append(same_line_list)
                    same_line_list = []
        elif len(i.strip()) != 16:
            pass
        else:
            ciphertext = bin2hex(encrypt(i.strip(), SHARED_KEY.strip()))
            ciphertext_list.append(ciphertext)

    return ciphertext_list;

def prepare_to_send(lines):
    same_line_list = []
    overall_list = []
    for i in lines:
        if len(i.strip()) > 18:
            same_line = i.split(' ')
            for x in same_line:
                same_line_list.append(x)
                if len(same_line_list) == len(same_line):
                    overall_list.append(same_line_list)
                    same_line_list = []
        else:
            overall_list.append(i)

    return overall_list;