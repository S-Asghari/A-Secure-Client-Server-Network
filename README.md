# A-Secure-Client-Server-Network
A simple messenger which is used to exchange messages and files through a secure tunnel

In this project, "socket" and "cryptography" libraries have been used.

## Symmetric Encryption:
After a successful connection between a client and server, each side generates a (private key, public key) set and sends its public key to the other side. 

The user decides each client to play a "sender" or a "receiver" role.


## Asymmetric Encryption:

### Note:
- First run the server code and then run then client code as many times as you wish, because if you run the client code before the server code, there would be no server to bind to that client and the client terminates with a message saying: "Failed to connect to host: 127.0.0.1 on port: 9999, because: [WinError 10061] No connection could be made because the target machine actively refused it".
