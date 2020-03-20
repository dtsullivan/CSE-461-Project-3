# CSE 461 Project 3
# Simple TLS Handshake procedure
import os
import AES

# In a real TLS, we would use an asymmetric encryption for
# the server key
SERVER_KEY = b'\x0f\xe6\x80\xdfSRgW\xf5\x8cm\x04\x8a\xb2\xe3\x15'
FINISHED_MESSASGE = "finished"


# Client-side TLS handshake
# Returns None if handshake failed, else returns session_key
def ClientHandshake(sock):
    # Send client_random
    client_random = os.urandom(AES.keySize)
    print("Sending client_random: ", client_random)
    sock.sendall(client_random)
    
    # Receive server_random
    server_random = ReceiveData(sock, AES.keySize)
    print("Received server_random: ", server_random)

    # Send premaster (encrypted with SERVER_KEY)
    premaster = os.urandom(AES.keySize)
    print("Encrypting premaster: ", premaster)
    premaster_encrypted = AES.Encrypt(bytes(premaster), SERVER_KEY)
    print("Sending premaster_encrypted: ", premaster_encrypted)
    sock.sendall(premaster_encrypted)

    # Create session_key
    session_key = bytearray(AES.keySize)
    for i in range(AES.keySize):
        session_key[i] = client_random[i] ^ server_random[i] ^ premaster[i]

    # Verify session_key with server
    client_verification = AES.Encrypt(FINISHED_MESSAGE.encode(), session_key)
    print("Sending client_finished: ", client_verification)
    sock.sendall(client_verification)
    
    server_verification = ReceiveData(sock, len(client_verification))
    print("Received server_finished: ", server_verification)
    
    server_finished = AES.Decrypt(server_verification, session_key).decode('utf8')
    print("Decrypted server_finished: ", server_finished)
    
    # Return result
    if server_finished == FINISHED_MESSAGE:
        return session_key
    else:
        return None

# Server-side TLS handshake
# Returns None if handshake failed, else returns session_key
def ServerHandshake(sock):
    # Receive client_random
    client_random = ReceiveData(sock, AES.keySize)
    print("Received client_random: ", client_random)

    # Send server_random
    server_random = os.urandom(AES.keySize)
    print("Sending server_random: ", server_random)
    sock.sendall(server_random)      
    
    # Receive and decrypt premaster
    premaster_encoded = ReceiveData(sock, AES.keySize)
    premaster = AES.Decrypt(premaster_encoded, SERVER_KEY)
    print("Received premaster: ", premaster)

    # Create session_key
    session_key = bytearray(AES.keySize)
    for i in range(AES.keySize):
        session_key[i] = client_random[i] ^ server_random[i] ^ premaster[i]

    # Verify session_key with client                                                                                                                         
    server_verification = AES.Encrypt(FINISHED_MESSAGE.encode(), session_key)
    
    client_verification = ReceiveData(sock, len(server_verification))
    print("Received client_finished: ", client_verification)
    
    client_finished = AES.Decrypt(client_verification, session_key).decode('utf8')
    print("Decrypted client_finished: ", client_finished)
    
    print("Sending server_finished: ", server_verification)
    sock.sendall(server_verification)
    
    if client_finished == FINISHED_MESSAGE:
        return session_key
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
