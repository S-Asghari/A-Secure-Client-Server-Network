import socket
import argparse
import threading
import time
import json
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

parser = argparse.ArgumentParser(description="This is the server.")
parser.add_argument('--host', metavar='host', type=str, nargs='?', default=socket.gethostname())
parser.add_argument('--port', metavar='port', type=int, nargs='?', default=9999)
args = parser.parse_args()

args.host = '127.0.0.1'

print(f"Running the server on: {args.host} and port: {args.port}")

sck = socket.socket()
sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

############################################################################
# the information which should be stored

clientDict = {}     # (client_id, client_socket)
clientType = {}     # (client_id, R | S)

data = {}
data['self'] = []           # id, private key
data['client'] = []         # client_id, public key
data['master_key'] = []     # sender_id, receiver_id, master_key, iv0

############################################################################
# creating a (private key, public key) and storing the private key

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()
pem_private_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption())

id = input("Enter server id(name): ")

data['self'].append({
    'id': id,
    'key': pem_private_key.decode("utf-8")
})

############################################################################

try:
    sck.bind((args.host, args.port))
    sck.listen(5)
except Exception as e:
    raise SystemExit(f"Could not bind the server on host: {args.host} to port: {args.port}, because: {e}")

############################################################################


def on_new_client(client, connection):
    ip = connection[0]
    port = connection[1]
    print(f"New connection from IP: {ip}, and port: {port}!")

    ########################################################################
    # sending the public key, receiving client's public key, storing it

    client_id = client.recv(1024)
    client_id = client_id.decode()
    pem_client_key = client.recv(1024)

    client.sendall(id.encode("utf-8"))
    time.sleep(0.5)

    pem_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client.sendall(pem_public_key)

    data['client'].append({
        'id': client_id,
        'key': pem_client_key.decode("utf-8")
    })

    clientDict[client_id] = client

    ########################################################################

    while True:

        ct = client.recv(1024)      # client type
        clientType[client_id] = ct.decode()

        ####################################################################

        if clientType[client_id] == 'S':

            targetClientId = client.recv(1024)
            targetClientId = targetClientId.decode()

            if targetClientId in clientDict and targetClientId in clientType and clientType[targetClientId] == 'R':
                YN = 'Y'
                client.sendall(YN.encode("utf-8"))
                targetClient = clientDict[targetClientId]

                targetClient.sendall(client_id.encode("utf-8"))

                target_client_key = ""  # target client's public key
                for c in data['client']:
                    if c['id'] == targetClientId:
                        target_client_key = load_pem_public_key(c['key'].encode("utf-8"), backend=default_backend())
                        break

            ################################################################
            # receiving master key, session key and decrypting them

                master_key = ""
                iv0 = ""

                for m in data['master_key']:

                    if (m['sender_id'] == client_id and m['receiver_id'] == targetClientId) or \
                            (m['sender_id'] == targetClientId and m['receiver_id'] == client_id):
                        print("There is a history between these 2 clients.")
                        master_key = binascii.unhexlify(m['master_key'])
                        iv0 = binascii.unhexlify(m['iv0'])
                        break

                if master_key == "" and iv0 == "":
                    master_key = client.recv(1024)
                    master_key = private_key.decrypt(master_key,
                                                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))
                    encrypted_master_key = target_client_key.encrypt(master_key,
                                                                     padding.OAEP(
                                                                         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                         algorithm=hashes.SHA256(), label=None))
                    targetClient.sendall(encrypted_master_key)
                    time.sleep(0.5)

                    iv0 = client.recv(1024)
                    targetClient.sendall(iv0)
                    time.sleep(0.5)

                    data['master_key'].append({
                        'sender_id': client_id,
                        'receiver_id': targetClientId,
                        'master_key': binascii.hexlify(master_key).decode("utf-8"),
                        'iv0': binascii.hexlify(iv0).decode("utf-8")
                    })

                encrypted_session_key = client.recv(1024)
                targetClient.sendall(encrypted_session_key)
                time.sleep(0.5)

                iv = client.recv(1024)
                targetClient.sendall(iv)
                time.sleep(0.5)

                ############################################################

                typeOfMsg = client.recv(1024)
                targetClient.sendall(typeOfMsg)

                ############################################################

                if typeOfMsg.decode() == 'M':

                    print(f"Client with id: {client_id} is sending a message...")

                    msg = client.recv(1024)
                    print(f"Message received successfully from id: {client_id}.")

                    targetClient.sendall(msg)
                    print(f"Message transferred successfully to id: {targetClientId}.")

                ############################################################

                elif typeOfMsg.decode() == 'F':

                    print(f"Client with id: {client_id} is sending a file...")

                    typeOfFile = client.recv(1024)
                    targetClient.sendall(typeOfFile)

                    msg = client.recv(1024)
                    while msg != "theEnd".encode("utf-8"):
                        if msg == "new session".encode("utf-8"):
                            targetClient.sendall(msg)

                            encrypted_session_key = client.recv(1024)
                            targetClient.sendall(encrypted_session_key)
                            time.sleep(0.5)
                            iv = client.recv(1024)
                            targetClient.sendall(iv)

                            msg = client.recv(1024)
                            continue

                        targetClient.sendall(msg)
                        msg = client.recv(1024)

                    targetClient.sendall("theEnd".encode("utf-8"))
                    print(f"File received completely from id: {client_id} and transferred completely to id: {targetClientId}.")

                ############################################################

                else:
                    print("Wrong format!")
                    reply = "Error"
                    client.sendall(reply.encode("utf-8"))
                    continue

                ############################################################
                # new Physical key for next connection of this client pair

                master_key = client.recv(1024)
                master_key = private_key.decrypt(master_key,
                                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(), label=None))
                encrypted_master_key = target_client_key.encrypt(master_key,
                                                                 padding.OAEP(
                                                                     mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(), label=None))
                targetClient.sendall(encrypted_master_key)
                time.sleep(0.5)

                iv0 = client.recv(1024)
                targetClient.sendall(iv0)

                for m in data['master_key']:
                    if (m['sender_id'] == client_id and m['receiver_id'] == targetClientId) or \
                            (m['sender_id'] == targetClientId and m['receiver_id'] == client_id):
                        m['master_key'] = binascii.hexlify(master_key).decode("utf-8")
                        m['iv0'] = binascii.hexlify(iv0).decode("utf-8")

                del clientType[client_id]
                del clientType[targetClientId]

            ################################################################

            elif not(targetClientId in clientDict) or not(targetClientId in clientType):
                YN = 'N'
                client.sendall(YN.encode("utf-8"))

            ################################################################

            else:       # clientType[targetClientId] == 'S'
                YN = 'Z'
                client.sendall(YN.encode("utf-8"))

        ####################################################################

        elif clientType[client_id] == 'E':
            print(f"Client from ip: {ip}, and port: {port} disconnected.")
            del clientDict[client_id]
            del clientType[client_id]

            index = 0
            for c in data['client']:
                if c['id'] == client_id:
                    data['client'].pop(index)
                    break
                index = index + 1

            index = 0
            for m in data['master_key']:
                if m['sender_id'] == client_id or m['receiver_id'] == client_id:
                    data['master_key'].pop(index)
                    break
                index = index + 1

            with open('server_file/data.txt', 'w') as outfile:
                json.dump(data, outfile)

            break

    client.close()


############################################################################

while True:
    try:
        client, ip = sck.accept()
        threading._start_new_thread(on_new_client,(client, ip))

    #########################################################################

    except KeyboardInterrupt:

        print(f"Server is shutting down...")
        break

    except Exception as e:
        print(f"Error: {e}")
        break

sck.close()
