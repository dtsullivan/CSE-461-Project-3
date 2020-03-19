# CSE 461 Project 3
# Simple TLS Handshake procedure
import os
import AES

# In a real TLS, we would use an asymmetric encryption for
# the server key
SERVER_KEY = b'\x0f\xe6\x80\xdfSRgW\xf5\x8cm\x04\x8a\xb2\xe3\x15'


# Client-side TLS handshake
def ClientHandshake(sock):
    # Send hello msg with client_random
    client_random = os.urandom(AES.keySize)
    print("Sending client_random: ", client_random)
    sock.sendall(client_random)
    
    # Receive Server reply with server_random
    server_random = ReceiveData(sock, AES.keySize)
    print("Received server_random: ", server_random)

    # Send premaster
    premaster = os.urandom(AES.keySize)
    print("Sending premaster: ", premaster)
    sock.sendall(AES.Encrypt(bytes(premaster), SERVER_KEY))

    # Create Session Key
    # Super simple key
    key = bytearray(AES.keySize)
    for i in range(AES.keySize):
        key[i] = client_random[i] ^ server_random[i] ^ premaster[i]

    # Verify Session Key
    print("Sending key: ", key)
    sock.sendall(key)
    server_key = ReceiveData(sock, AES.keySize)
    print("Received key: ", server_key)
    if key == server_key:
        return key
    else:
        return None

def ServerHandshake(sock):
    # Receive client_random from client
    client_random = ReceiveData(sock, AES.keySize)
    print("Received client_random: ", client_random)

    # Send server_random
    server_random = os.urandom(AES.keySize)
    print("Sending server_random: ", server_random)
    sock.sendall(server_random)                                                                                                                               
    premaster_encoded = ReceiveData(sock, AES.keySize)
    premaster = AES.Decrypt(premaster_encoded, SERVER_KEY)
    print("Received premaster: ", premaster)

    key = bytearray(AES.keySize)
    for i in range(AES.keySize):
        key[i] = client_random[i] ^ server_random[i] ^ premaster[i]

    # Verify Session Key                                                                                                                             
    client_key = ReceiveData(sock, AES.keySize)
    print("Received key: ", client_key)
    print("Sending key: ", key)
    sock.sendall(key)

    if key == client_key:
        return key
    else:
        return None

# Receive $expected bytes from $sock
# Returns: all bytes received as a bytearray
def ReceiveData(sock, expected):
    data = bytearray()
    while len(data) < expected:
        newdata = sock.recv(1024)
        for i in range(len(newdata)):
            data.append(newdata[i])
    return bytes(data)
