import socket, threading

def client_receiver(client_socket, addr):
    
    print('Connected by', addr)
    try:
        while True:
            data = client_socket.recv(1024)
            msg = data.decode()
            print('Received from', addr, msg)
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
