import socket
import argparse
import os
import json
import time
import hashlib
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
    # sending the id and public key, receiving server's id and public key, storing it

    sck.sendall(id.encode('utf-8'))
    time.sleep(0.5)

    pem_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sck.sendall(pem_public_key)

    server_id = sck.recv(1024)
    server_id = server_id.decode()
    pem_server_key = sck.recv(1024)
    server_key = load_pem_public_key(pem_server_key, backend=default_backend())

    ########################################################################
    # Authentication

    encrypted_Rs = sck.recv(1024)
    Rs = private_key.decrypt(encrypted_Rs, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
    Rc = os.urandom(32)         # client's random number
    encrypted_Rs = server_key.encrypt(Rs, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                       algorithm=hashes.SHA256(), label=None))
    sck.sendall(encrypted_Rs)
    time.sleep(0.5)
    encrypted_Rc = server_key.encrypt(Rc, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                       algorithm=hashes.SHA256(), label=None))
    sck.sendall(encrypted_Rc)
    encrypted_Rc_prim = sck.recv(1024)
    Rc_prim = private_key.decrypt(encrypted_Rc_prim, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
    authenticated = False
    if Rc == Rc_prim:
        print("Server authenticated!")
        authenticated = True

        data['server'].append({
            'id': server_id,
            'key': pem_server_key.decode("utf-8")
        })

    else:
        print("Authentication problem with server!")

    ########################################################################

    while authenticated:       # authenticated == True

        print(" ")
        clientType = input("Enter 'S' for being sender and 'R' for being receiver and 'E' for exit: ")

        while clientType != 'S' and clientType != 'R' and clientType != 'E':
            print('Wrong format!')
            clientType = input("Enter 'S' for being sender and 'R' for being receiver and 'E' for exit: ")

        sck.sendall(clientType.encode('utf-8'))

        ####################################################################

        if clientType == 'S':

            # Receiving list of authenticated Receivers from server to choose from

            list = sck.recv(1024)
            list = private_key.decrypt(list, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))
            list = list.decode()
            list = list.split(';')

            print("\tEnter the id(name) of target client by choosing a number from the list below: ")
            for i in range(len(list)):
                print(f"\t{i+1}. {list[i]}")
            targetClientID = ""
            while True:
                try:
                    targetClientID = list[int(input("\t"))-1]
                    break
                except Exception as e:
                    print("\tTry again!")

            ################################################################

            typeOfMsg = input("\t\tEnter 'M' for message and 'F' for file: ")

            while typeOfMsg != 'M' and typeOfMsg != 'F':
                print("Wrong format!")
                typeOfMsg = input("\t\tEnter 'M' for message and 'F' for file: ")

            # Creating and sending digital signature

            signature_msg = '{0: >16}'.format(id) + '{0: >16}'.format(targetClientID) + typeOfMsg + str(int(time.time()))

            signature_msg = signature_msg.encode("utf-8")
            sck.sendall(signature_msg)

            sign_hash = hashlib.sha256(signature_msg)
            sign_hash = (sign_hash.hexdigest()).encode("utf-8")
            signature = private_key.sign(sign_hash, padding.PKCS1v15(),
                                       hashes.SHA1())
            sck.sendall(signature)

            YN = sck.recv(1024)

            if YN.decode() == 'N':
                print("Target client is busy now!")
                continue

            ################################################################
            # handling digital signature response from target client

            encrypted_respond = sck.recv(1024)
            respond = private_key.decrypt(encrypted_respond,
                                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                       algorithm=hashes.SHA256(), label=None))
            if respond != b'V':
                print(f"digital signature is rejected by {targetClientID}.")
                break

            ################################################################
            # creating session key and sending encrypted version of it

            session_key = os.urandom(32)
            encrypted_key = server_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                       algorithm=hashes.SHA256(), label=None))
            sck.sendall(encrypted_key)
            time.sleep(0.5)

            iv = os.urandom(16)  # initialization vector
            sck.sendall(iv)
            time.sleep(0.5)

            cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            ###############################################################

            if typeOfMsg == 'M':

                msg = input("\t\t\tEnter the message: ")
                msg_hash = hashlib.sha256(msg.encode("utf-8"))
                msg_hash = msg_hash.hexdigest()
                msg = msg_hash + msg

                msg = encryptor.update(msg.encode("utf-8")) + encryptor.finalize()

                while True:
                    sck.sendall(msg)
                    result = sck.recv(1024)
                    if result == b"correct data":
                        break
                    else:
                        print("data is damaged. Resending process...")

                print("Server received the msg!")

            #######################################################

            elif typeOfMsg == 'F':

                addr = input("\t\t\tEnter the file address: ")      # sender_file/books.jpg
                while not os.path.exists(addr):
                    print("This file doesn't exist.")
                    addr = input("\t\t\tEnter the file address: ")

                typeOfFile = (addr.split('.'))[1]
                sck.sendall(typeOfFile.encode('utf-8'))

                f = open(addr, 'rb')
                l = f.read(1024)

                start_time = time.time()

                while l:
                    end_time = time.time()
                    # print(end_time - start_time)
                    if end_time - start_time > session_key_expire_time:
                        print("transferring this file takes more time...")
                        sck.sendall("new session".encode('utf-8'))

                        session_key = os.urandom(32)
                        iv = os.urandom(16)
                        cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv), backend=default_backend())
                        encryptor = cipher.encryptor()

                        encrypted_key = server_key.encrypt(session_key,
                                                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                        algorithm=hashes.SHA256(), label=None))
                        sck.sendall(encrypted_key)
                        time.sleep(0.5)
                        sck.sendall(iv)
                        start_time = time.time()

                    l_hash = hashlib.sha256(l)
                    l_hash = l_hash.hexdigest()
                    l = l_hash + l.decode()

                    l = encryptor.update(l.encode("utf-8"))

                    while True:
                        sck.sendall(l)
                        result = sck.recv(1024)
                        if result == b"correct data...not finished":
                            break
                        else:
                            print("data is damaged. Resending process...")

                    l = f.read(1024)
                f.close()

                time.sleep(0.5)
                sck.sendall("theEnd".encode('utf-8'))

                print("Server received the file!")

        ###################################################################

        elif clientType == 'R':

            # receiving sender id, signatute and verifying it

            signature_msg = sck.recv(1024)

            senderId = ((signature_msg.decode())[0:16]).lstrip()
            typeOfMsg = (signature_msg.decode())[32]

            sign_hash = hashlib.sha256(signature_msg)
            sign_hash = (sign_hash.hexdigest()).encode("utf-8")

            signature = sck.recv(1024)
            respond = ''
            try:
                verifying = server_key.verify(signature, sign_hash, padding.PKCS1v15(), hashes.SHA1())
                if ((signature_msg.decode())[16:32]).lstrip() == id:
                    if int(time.time()) - int((signature_msg.decode())[33:43]) > 60:
                        print(f"Valid signature from id: {senderId} but time limit is finished!")
                        respond = 'T'
                    else:
                        print(f"Valid signature from id: {senderId}")
                        respond = 'V'
                else:
                    print(f"Valid signature from id: {senderId} but wrong target client is chosen!")
                    respond = 'W'
            except Exception as e:
                print(f"Invalid signature from id: {senderId}")
                respond = 'I'

            encrypted_respond = server_key.encrypt(respond.encode("utf-8"), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(), label=None))
            sck.sendall(encrypted_respond)

            if respond != 'V':
                break

            ###############################################################

            # Receiving Sender's encrypted session key and decrypting it

            session_key = sck.recv(1024)
            session_key = private_key.decrypt(session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))

            iv = sck.recv(1024)

            cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            ###############################################################

            if typeOfMsg == 'M':

                while True:
                    msg = sck.recv(1024)
                    msg = decryptor.update(msg) + decryptor.finalize()
                    msg = msg.decode()

                    # msg = msg_hash + main_msg
                    msg_hash = msg[0:64]
                    main_msg = msg[64: len(msg)]
                    calculated_hash = hashlib.sha256(main_msg.encode("utf-8"))
                    calculated_hash = calculated_hash.hexdigest()

                    if msg_hash == calculated_hash:
                        sck.sendall(b"correct data")
                        break
                    else:
                        sck.sendall(b"damaged data")

                print(f"Message from client id {senderId} is: {main_msg}")

            ###############################################################

            else:   # typeOfMsg.decode() == 'F'

                typeOfFile = sck.recv(1024)
                f = open("receiver_file/output." + typeOfFile.decode(), 'wb')

                msg = sck.recv(1024)

                while msg != "theEnd".encode('utf-8'):
                    if msg == "new session".encode('utf-8'):
                        session_key = sck.recv(1024)
                        session_key = private_key.decrypt(session_key,
                                                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                       algorithm=hashes.SHA256(), label=None))
                        iv = sck.recv(1024)
                        cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        msg = sck.recv(1024)
                        continue

                    while True:
                        msg = decryptor.update(msg)
                        msg = msg.decode()

                        msg_hash = msg[0:64]
                        main_msg = msg[64:len(msg)]
                        calculated_hash = hashlib.sha256(main_msg.encode("utf-8"))
                        calculated_hash = calculated_hash.hexdigest()

                        if msg_hash == calculated_hash:
                            sck.sendall(b"correct data...not finished")
                            f.write(main_msg.encode("utf-8"))
                            break
                        else:
                            sck.sendall(b"damaged data")
                            msg = sck.recv(1024)

                    msg = sck.recv(1024)

                sck.sendall(b"correct data")
                f.close()
                print(f"File received from id {senderId}.")

        ###################################################################

        else:        # clientType == 'E'
            print("Client is disconnecting...")
            break

with open('client_file/data.txt', 'w') as outfile:
    json.dump(data, outfile)
