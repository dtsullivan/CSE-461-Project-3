import AES
import socket
import sys
import TLSHandshake

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 10000)
print('connecting to ' + str(server_address[0]) + ' port ' + str(server_address[1]))
sock.connect(server_address)    
try:
    key = TLSHandshake.ClientHandshake(sock)
    if key == None:
        print('Client and Server key check failed')
    else:
        message = input("Type a message to send: ")
        print('sending ' + message)
        sock.sendall(AES.Encrypt(bytes(message.encode()), key))
        
        amount_received = 0
        amount_expected = len(message)
    
        while amount_received < amount_expected:
            data = sock.recv(1024)
            amount_received += len(data)
            print('received ', AES.Decrypt(data, key))

finally:
    print('closing socket')
    sock.close()

