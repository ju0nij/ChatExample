import socket
HOST = '127.0.0.1'  
PORT = 15000
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
while True:
    msg = input('Type message here(q to quit): ')
    if msg == 'q':
        break
    data = msg.encode()
    client_socket.sendall(data)
    data = client_socket.recv(1024)
    msg = data.decode()
    print('Received from : ', msg)
    
client_socket.close()

