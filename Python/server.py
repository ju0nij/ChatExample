from hashlib import sha256
from base64 import b64decode
from base64 import b64encode

import socket, threading
import base64
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

class AES():
    def __init__(self, key, iv):
        self.key = sha256(key.encode()).digest()
        # self.iv = iv.encode('utf-8')
        self.iv = sha256(iv.encode()).digest()

    def encrypt(self, plain):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return bytes.decode(b64encode(cipher.encrypt(pad('abcd'.encode(), 
            AES.block_size))))

    def decrypt(self, cipher_text):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return bytes.decode(unpad(cipher.decrypt(b64decode(cipher_text)), 
            AES.block_size))

aes = AES('abcdefgh12345678abcdefgh12345678', 'abcdefgh12345678')

def client_receiver(client_socket, addr):
    
    print('Connected by', addr)
    try:
        while True:
            data = client_socket.recv(1024)
            msg = data.decode()
            print('Received from', addr, aes.decrypt(msg).encode())
            data = msg.encode()
            client_socket.sendall(data)
    except:
        print('except : ' , addr)
    finally:
        client_socket.close()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('', 15000))
server_socket.listen()
 
try:
    
    while True:
        client_socket, addr = server_socket.accept()
        th = threading.Thread(target=client_receiver, args = (client_socket,addr))
        th.start()
except:
    print('err')
finally:
    server_socket.close()
