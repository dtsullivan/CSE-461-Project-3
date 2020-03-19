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
        if key != None:
            print(connection)
            print(client_address)
            print ('connection from ' + str(client_address))
            while True:
                data = connection.recv(1024)
                print('received %s' %AES.Decrypt(data, key))
                if data:
                    print('sending data back to the client')
                    connection.sendall(data)
                else:
                    print('no more data from ' + str(client_address))
                    break
            
    finally:
        # Clean up the connection
        connection.close()
