import socket
import pickle
from utils import *

'''
File using for testing == test.txt
'''

SHARED_KEY = 'C30950FA36CF58CF'
HEADER_LENGTH = 10
a = 250
b = 479

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((socket.gethostname(), 1235))
server_socket.listen(1)


clt, adrs = server_socket.accept()
# Send options to client
options = {1: "Shift Cipher", 2: "DES"}
send_options = pickle.dumps(options)
options_header = f"{len(send_options):<{HEADER_LENGTH}}".encode('utf-8')
clt.send(options_header + send_options)

# Recieve selected options from client
check_options = receive_message(clt, HEADER_LENGTH)
k = f"{check_options['data'].decode('utf-8')}"
print(f"Selected option {k}")

# Based on options
if k == '1':
    received_k = receive_message(clt, HEADER_LENGTH)
    k = f"{received_k['data'].decode('utf-8')}"
    k_prime = (a - int(k) + b) % 52

    while True:
        message = receive_message(clt, HEADER_LENGTH)
        message_received = f"{message['data'].decode('utf-8')}"
        message_decrypted = decrypt_cipher(message_received, k_prime)
        print(f"Ciphertext: {message_received}, Plaintext: {message_decrypted}")

        msg = "Message acknowledged".encode('utf-8')
        msg_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
        clt.send(msg_header + msg)
else:

    received = receive_message(clt, HEADER_LENGTH)
    k = pickle.loads(received['data'])
    decrypted_message = decrypt_message(k, SHARED_KEY)
    print(f"Ciphertext: {k} \n Plaintext: {decrypted_message}")

    # Send acknowledgement message to client
    msg = "Message acknowledged".encode('utf-8')
    msg_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
    clt.send(msg_header + msg)






