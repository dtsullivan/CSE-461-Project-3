import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = ('localhost', 10000)
print('starting up on ' + str(server_address[0]) + ' port ' + str(server_address[1]))
sock.bind(server_address)
sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print(connection)
        print(client_address)
        print ('connection from ' + str(client_address))
        while True:
            data = connection.recv(1024)
            print('received %s' %data.decode())
            if data:
                print('sending data back to the client')
                connection.sendall(data)
            else:
                print('no more data from ' + str(client_address))
                break
            
    finally:
        # Clean up the connection
        connection.close()