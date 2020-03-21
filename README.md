# CSE 461 Project 3
## AES Encryption with TLS Handshake for TCP
### Daniel Sullivan, Micah Verwey, Kevin Jeong

For project 3 we chose to implement 128-bit AES encryption on top of a TCP connection. [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) is a deprecated symmetric cipher network encryption standard. Generally, server keys are implemented using asymmetric encryption, but for the purposes of demonstrating our cipher, we hard coded in the server key. Using this, we generated 128-bit session keys using a [TLS handshake](https://en.wikipedia.org/wiki/Transport_Layer_Security) which the TCP connction uses to encrypt all communications with the AES cipher.

## Demo
We chose to implement our project in python3 for ease of scripting and portability over many platforms so TAs could easily test our code. To run the demo, follow the steps below:

- From the repo directory, run `python3 Server.py`. This will open a listening socket on port 10000
- Open another shell in the repo directory and run `python3 Client.py`. This create a socket to connect to the listening server and establish a session key with a TLS handshake
- On the `Client.py` shell, enter a string to test. The client will encrypt and  send it to the server. The server will then decrypt, then encrypt and send it back. The client will finally decrypt the message and close its socket. This demonstrates encryption and decryption working on both sides of the connection.