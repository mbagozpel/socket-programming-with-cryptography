import socket
from utils import *
import pickle
import sys


SHARED_KEY = 'C30950FA36CF58CF'
HEADER_LENGTH = 10
a = 250
b = 479

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((socket.gethostname(), 1235))

message = receive_message(client_socket, HEADER_LENGTH)
k = pickle.loads(message['data'])
print(k)

check = True

while True:
    select = input("Select an option: ")
    if select in ["1", "2"]:
        # Send selected option to servver
        send_select = select.encode('utf-8')
        send_k_header = f"{len(send_select):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(send_k_header + send_select)

        if select == "1":
            # Shift Cipher Program
            k = generate_non_zero_k()
            send_k = str(k).encode('utf-8')
            send_k_header = f"{len(send_k):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(send_k_header + send_k)

            while True:
                message = input("Enter a message:")

                if message:
                    k_prime = (a - k + b) % 52
                    ciphertext = shift_cipher(message, k_prime)
                    print(f"Plaintext: {message}, Ciphertext: {ciphertext}")
                    send_ciphertext = ciphertext.encode('utf-8')
                    ciphertext_header = f"{len(ciphertext):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(ciphertext_header + send_ciphertext)

                # receive message
                acknowledgement_header = client_socket.recv(HEADER_LENGTH)
                if not len(acknowledgement_header):
                    print("connection closed by the server")
                    sys.exit()

                acknowledgement_length = int(acknowledgement_header.decode('utf-8').strip())
                acknowledgement = client_socket.recv(acknowledgement_length)
                print(acknowledgement.decode('utf-8'))

        else:

            # DES Program
            with open("test.txt", 'r') as f:
                lines = f.readlines()

            # Encrypt and send to server
            encrypted_lines = encrypt_txt_lines(lines, SHARED_KEY)
            send_encrypted_lines = pickle.dumps(encrypted_lines)
            encrypted_lines_header = f"{len(send_encrypted_lines):<{HEADER_LENGTH}}".encode('utf-8')
            plainlines = prepare_to_send(lines)
            print(f"Ciphertext: {encrypted_lines} \n Plaintext: {plainlines}")
            client_socket.send(encrypted_lines_header + send_encrypted_lines)

            # receive acknowledgement message
            acknowledgement_header = client_socket.recv(HEADER_LENGTH)
            if not len(acknowledgement_header):
                print("connection closed by the server")
                sys.exit()

            acknowledgement_length = int(acknowledgement_header.decode('utf-8').strip())
            acknowledgement = client_socket.recv(acknowledgement_length)
            print(acknowledgement.decode('utf-8'))

        break
    else:
        print("Incorrect value")







