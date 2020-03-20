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
        print('encrypting: ', message)
        encrypted_message = AES.Encrypt(bytes(message.encode('utf-8')), key)
        print('sending encrypted message: ', ''.join(format(x, '02x') for x in encrypted_message))
        sock.sendall(encrypted_message)
        
        amount_received = 0
        amount_expected = len(message)
    
        while amount_received < amount_expected:
            data = sock.recv(1024)
            amount_received += len(data)
            print('received encrypted data: ', ''.join(format(x, '02x') for x in data))
            decrypted_data = AES.Decrypt(data, key)
            print('decrypted as: ', decrypted_data.decode('utf-8'))

finally:
    print('closing socket')
    sock.close()

