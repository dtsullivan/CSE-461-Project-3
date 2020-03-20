import socket
import sys
import TLSHandshake
import AES

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = ('localhost', 10000)
print('starting up on ' + str(server_address[0]) + ' port ' + str(server_address[1]))
sock.bind(server_address)
sock.listen()

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        
        key = TLSHandshake.ServerHandshake(connection)
        if key == None:
            print('Client and Server key check failed')
        else:
            print(connection)
            print(client_address)
            print ('connection from ', str(client_address))
            while True:
                data = connection.recv(1024)
                if data:
                    print('received encrypted data: ', ''.join(format(x, '02x') for x in data))
                    decrypted_data = AES.Decrypt(data, key)
                    print('decrypted data as: ', decrypted_data.decode('utf-8'))
                    encrypted_data = AES.Encrypt(decrypted_data, key)
                    print('encrypted data as: ', ''.join(format(x, '02x') for x in encrypted_data))
                    print('sending data back to the client')
                    connection.sendall(encrypted_data)
                else:
                    print('no more data from ', str(client_address))
                    break
            
    finally:
        # Clean up the connection
        connection.close()
