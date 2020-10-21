import socket
import argparse
import os
import json
import time
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

parser = argparse.ArgumentParser(description="This is a client.")
parser.add_argument('--host', metavar='host', type=str, nargs='?', default=socket.gethostname())
parser.add_argument('--port', metavar='port', type=int, nargs='?', default=9999)
args = parser.parse_args()
args.host = '127.0.0.1'

print(f"Connecting to server: {args.host} on port: {args.port}")

############################################################################
# the information which should be stored in json file

data = {}
data['self'] = []           # id, private key
data['server'] = []         # server_id, public key
data['master_key'] = []     # sender_id, receiver_id, master_key, iv0

session_key_expire_time = 5       # 5 secs

############################################################################
# creating a (private key, public key) and storing the private key

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()
pem_private_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption())

id = input("Enter id(name): ")

data['self'].append({
    'id': id,
    'key': pem_private_key.decode("utf-8")
})

############################################################################

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sck:
    try:
        sck.connect((args.host, args.port))
    except Exception as e:
        raise SystemExit(f"Failed to connect to host: {args.host} on port: {args.port}, because: {e}")

    ########################################################################
    # sending the public key, receiving server's public key, storing it

    sck.sendall(id.encode("utf-8"))
    time.sleep(0.5)

    pem_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sck.sendall(pem_public_key)

    server_id = sck.recv(1024)
    pem_server_key = sck.recv(1024)
    server_key = load_pem_public_key(pem_server_key, backend=default_backend())

    data['server'].append({
        'id': server_id.decode(),
        'key':pem_server_key.decode("utf-8")
    })

    ########################################################################

    while True:

        print(" ")
        clientType = input("Enter 'S' for being sender and 'R' for being receiver and 'E' for exit: ")

        while clientType != 'S' and clientType != 'R' and clientType != 'E':
            print('Wrong format!')
            clientType = input("Enter 'S' for being sender and 'R' for being receiver and 'E' for exit: ")

        sck.sendall(clientType.encode("utf-8"))

        ####################################################################

        if clientType == 'S':

            targetClientID = input("\tEnter the id(name) of target client: ")
            sck.sendall(targetClientID.encode("utf-8"))
            YN = sck.recv(1024)

            if YN.decode() == 'N':
                print("Target client is not connected to server.")
                continue

            elif YN.decode() == 'Z':
                print("Target client is in sender mode.")
                continue

            ################################################################
            # creating physical key(if doesn't exist!), session key and sending encrypted version of them

            master_key = ""
            iv0 = ""

            for m in data['master_key']:

                if (m['sender_id'] == id and m['receiver_id'] == targetClientID) or \
                        (m['sender_id'] == targetClientID and m['receiver_id'] == id):
                    master_key = binascii.unhexlify(m['master_key'])
                    iv0 = binascii.unhexlify(m['iv0'])
                    break

            if master_key == "" and iv0 == "":
                master_key = os.urandom(32)  # Physical key
                encrypted_master_key = server_key.encrypt(master_key,
                                                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                       algorithm=hashes.SHA256(), label=None))
                sck.sendall(encrypted_master_key)
                time.sleep(0.5)

                iv0 = os.urandom(16)  # initialization vector
                sck.sendall(iv0)
                time.sleep(0.5)

                data['master_key'].append({
                    'sender_id': id,
                    'receiver_id': targetClientID,
                    'master_key': binascii.hexlify(master_key).decode("utf-8"),
                    'iv0': binascii.hexlify(iv0).decode("utf-8")
                })

            cipher0 = Cipher(algorithms.AES(master_key), modes.CTR(iv0), backend=default_backend())
            encryptor0 = cipher0.encryptor()

            session_key = os.urandom(32)
            encrypted_session_key = encryptor0.update(session_key) + encryptor0.finalize()
            sck.sendall(encrypted_session_key)
            time.sleep(0.5)

            iv = os.urandom(16)
            sck.sendall(iv)
            time.sleep(0.5)

            cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            ###############################################################

            typeOfMsg = input("\t\tEnter 'M' for message and 'F' for file: ")

            while typeOfMsg != 'M' and typeOfMsg != 'F':
                print("Wrong format!")
                typeOfMsg = input("\t\tEnter 'M' for message and 'F' for file: ")

            sck.sendall(typeOfMsg.encode("utf-8"))

            ###############################################################

            if typeOfMsg == 'M':

                msg = input("\t\t\tEnter the message: ")

                msg = encryptor.update(msg.encode("utf-8")) + encryptor.finalize()
                sck.sendall(msg)

                print("Server received the msg!")

            #######################################################

            elif typeOfMsg == 'F':

                addr = input("\t\t\tEnter the file address: ")      # sender_file/books.jpg
                while not os.path.exists(addr):
                    print("This file doesn't exist.")
                    addr = input("\t\t\tEnter the file address: ")

                typeOfFile = (addr.split('.'))[1]
                sck.sendall(typeOfFile.encode("utf-8"))

                f = open(addr, 'rb')
                l = f.read(1024)

                start_time = time.time()

                while l:
                    end_time = time.time()
                    # print(end_time - start_time)
                    if end_time - start_time > session_key_expire_time:
                        print("transferring this file takes more time...")
                        sck.sendall("new session".encode("utf-8"))

                        session_key = os.urandom(32)
                        iv = os.urandom(16)
                        cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv), backend=default_backend())
                        encryptor = cipher.encryptor()

                        encrypted_session_key = encryptor0.update(session_key) + encryptor0.finalize()
                        sck.sendall(encrypted_session_key)
                        time.sleep(0.5)
                        sck.sendall(iv)
                        start_time = time.time()

                    l = encryptor.update(l)
                    sck.sendall(l)
                    l = f.read(1024)
                f.close()

                time.sleep(0.5)
                sck.sendall("theEnd".encode("utf-8"))

                print("Server received the file!")

            ###############################################################

            master_key = os.urandom(32)  # new Physical key for next connection to this target client
            encrypted_master_key = server_key.encrypt(master_key,
                                                      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                   algorithm=hashes.SHA256(), label=None))
            sck.sendall(encrypted_master_key)
            time.sleep(0.5)

            iv0 = os.urandom(16)  # initialization vector
            sck.sendall(iv0)

            for m in data['master_key']:
                if (m['sender_id'] == id and m['receiver_id'] == targetClientID) or \
                        (m['sender_id'] == targetClientID and m['receiver_id'] == id):
                    m['master_key'] = binascii.hexlify(master_key).decode("utf-8")
                    m['iv0'] = binascii.hexlify(iv0).decode("utf-8")
                    break

        ###################################################################

        elif clientType == 'R':

            # receiving sender id, encrypted master key, encrypted session key and decrypting them

            senderId = sck.recv(1024)

            master_key = ""
            iv0 = ""

            for m in data['master_key']:
                if (m['sender_id'] == senderId.decode() and m['receiver_id'] == id) or \
                        (m['sender_id'] == id and m['receiver_id'] == senderId.decode()):
                    master_key = binascii.unhexlify(m['master_key'])
                    iv0 = binascii.unhexlify(m['iv0'])
                    break

            if master_key == "" and iv0 == "":
                master_key = sck.recv(1024)
                master_key = private_key.decrypt(master_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                          algorithm=hashes.SHA256(), label=None))
                iv0 = sck.recv(1024)

                data['master_key'].append({
                    'sender_id': senderId.decode(),
                    'receiver_id': id,
                    'master_key': binascii.hexlify(master_key).decode("utf-8"),
                    'iv0': binascii.hexlify(iv0).decode("utf-8")
                })

            cipher0 = Cipher(algorithms.AES(master_key), modes.CTR(iv0), backend=default_backend())
            decryptor0 = cipher0.decryptor()

            session_key = sck.recv(1024)
            session_key = decryptor0.update(session_key) + decryptor0.finalize()

            iv = sck.recv(1024)

            cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            ###############################################################

            typeOfMsg = sck.recv(1024)

            if typeOfMsg.decode() == 'M':
                msg = sck.recv(1024)
                msg = decryptor.update(msg) + decryptor.finalize()
                print(f"Message from client id {senderId.decode()} is: {msg.decode()}")

            ###############################################################

            else:   # typeOfMsg.decode() == 'F'

                typeOfFile = sck.recv(1024)
                f = open("receiver_file/output." + typeOfFile.decode(), 'wb')

                msg = sck.recv(1024)

                while msg != "theEnd".encode("utf-8"):
                    if msg == "new session".encode("utf-8"):
                        session_key = sck.recv(1024)
                        session_key = decryptor0.update(session_key) + decryptor0.finalize()
                        iv = sck.recv(1024)
                        cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        msg = sck.recv(1024)
                        continue

                    msg = decryptor.update(msg)
                    f.write(msg)
                    msg = sck.recv(1024)

                f.close()
                print(f"File received completely from id {senderId.decode()}.")

            ###############################################################

            master_key = sck.recv(1024)
            master_key = private_key.decrypt(master_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                      algorithm=hashes.SHA256(), label=None))
            iv0 = sck.recv(1024)

            for m in data['master_key']:
                if (m['sender_id'] == senderId.decode() and m['receiver_id'] == id) or \
                        (m['sender_id'] == id and m['receiver_id'] == senderId.decode()):
                    m['master_key'] = binascii.hexlify(master_key).decode("utf-8")
                    m['iv0'] = binascii.hexlify(iv0).decode("utf-8")
                    break

        ###################################################################

        else:        # clientType == 'E'
            print("Client is disconnecting...")
            break

with open('client_file/data.txt', 'w') as outfile:
    json.dump(data, outfile)
