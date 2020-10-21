import socket
import argparse
import threading
import time
import json
import os
import hashlib
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

clientDict = {}         # (client_id, client_socket)
clientType = {}         # (client_id, R | S)
dataResult0 = {}        # (client_id, signature check result)
dataResult = {}         # (client_id, MAC check result)
authenticatedClients = []

data = {}
data['self'] = []       # id, private key
data['client'] = []     # client_id, public key

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
    # sending the id and public key, receiving client's id and public key, storing it

    client_id = client.recv(1024)
    client_id = client_id.decode()
    pem_client_key = client.recv(1024)
    client_key = load_pem_public_key(pem_client_key, backend=default_backend())

    client.sendall(id.encode('utf-8'))
    time.sleep(0.5)

    pem_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client.sendall(pem_public_key)

    ########################################################################
    # Authentication

    Rs = os.urandom(32)     # server's random number
    encrypted_Rs = client_key.encrypt(Rs, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    client.sendall(encrypted_Rs)
    encrypted_Rs_prim = client.recv(1024)
    Rs_prim = private_key.decrypt(encrypted_Rs_prim, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
    encrypted_Rc = client.recv(1024)
    Rc = private_key.decrypt(encrypted_Rc, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
    encrypted_Rc = client_key.encrypt(Rc, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                       algorithm=hashes.SHA256(), label=None))
    client.sendall(encrypted_Rc)

    authenticated = False
    if Rs == Rs_prim:
        print(f"Client with id: {client_id} authenticated!")
        authenticated = True

        data['client'].append({
            'id': client_id,
            'key': pem_client_key.decode("utf-8")
        })

        clientDict[client_id] = client

    else:
        print(f"Authentication problem with client: {client_id}!")

    ########################################################################

    while authenticated:        # authenticated == True

        ct = client.recv(1024)      # client type
        clientType[client_id] = ct.decode()

        ####################################################################

        if clientType[client_id] == 'S':

            # sending list of authenticated Receivers to client

            str_list = ';'.join(str(e) for e in authenticatedClients)
            encrypted_list = client_key.encrypt(str_list.encode("utf-8"), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(), label=None))
            client.sendall(encrypted_list)

            ################################################################

            # Receive and check client's digital signature

            signature_msg = client.recv(1024)
            sign_hash = hashlib.sha256(signature_msg)
            sign_hash = (sign_hash.hexdigest()).encode("utf-8")

            signature = client.recv(1024)
            try:
                verifying = client_key.verify(signature, sign_hash, padding.PKCS1v15(),
                                          hashes.SHA1())
                print(f"Valid singnature from id: {client_id}.")
            except Exception as e:
                print(f"Invalid signature from id: {client_id}, because: {e}.")

            signature_msg = signature_msg.decode()

            targetClientId = (signature_msg[16:32]).lstrip()
            typeOfMsg = signature_msg[32]

            if targetClientId in authenticatedClients:
                YN = 'Y'
                authenticatedClients.remove(targetClientId)     # targetClient is busy from now on!
                client.sendall(YN.encode('utf-8'))
                targetClient = clientDict[targetClientId]

                target_client_key = ""  # target client's public key
                for c in data['client']:
                    if c['id'] == targetClientId:
                        target_client_key = load_pem_public_key(c['key'].encode('utf-8'), backend=default_backend())
                        break

                # Sending digital signature to target client and handling the response

                targetClient.sendall(signature_msg.encode("utf-8"))
                signature = private_key.sign(sign_hash, padding.PKCS1v15(),
                                             hashes.SHA1())
                targetClient.sendall(signature)

                time.sleep(0.5)
                response = dataResult0[targetClientId]
                encrypted_response = client_key.encrypt(response.encode("utf-8"),
                                                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(), label=None))
                client.sendall(encrypted_response)
                del dataResult0[targetClientId]
                if response != 'V':
                    print(f"{client_id}'s digital signature is rejected by {targetClientId}.")
                    del clientDict[client_id]
                    del clientType[client_id]

                    index = 0
                    for c in data['client']:
                        if c['id'] == client_id:
                            data['client'].pop(index)
                            break
                        index = index + 1
                    break

                ################################################################
                # receiving session key and decrypting it

                encrypted_session_key = client.recv(1024)
                session_key = private_key.decrypt(encrypted_session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
                encrypted_key = target_client_key.encrypt(session_key,
                                                          padding.OAEP(
                                                              mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(), label=None))
                targetClient.sendall(encrypted_key)
                time.sleep(0.5)

                iv = client.recv(1024)
                targetClient.sendall(iv)
                time.sleep(0.5)

                ############################################################

                if typeOfMsg == 'M':

                    print(f"Client with id: {client_id} is sending a message...")
                    while True:
                        msg = client.recv(1024)
                        targetClient.sendall(msg)

                        time.sleep(0.5)
                        result = dataResult[targetClientId]
                        client.sendall(result.encode("utf-8"))
                        del dataResult[targetClientId]

                        if result == "correct data":
                            break
                        else:
                            print("data is damaged. Resending Process...")

                    # print(f"Message received successfully from id: {client_id}.")
                    print(f"Message transferred successfully to id: {targetClientId}.")

                ############################################################

                elif typeOfMsg == 'F':

                    print(f"Client with id: {client_id} is sending a file...")

                    typeOfFile = client.recv(1024)
                    targetClient.sendall(typeOfFile)

                    msg = client.recv(1024)
                    while msg != "theEnd".encode('utf-8'):
                        if msg == "new session".encode('utf-8'):
                            targetClient.sendall(msg)

                            encrypted_session_key = client.recv(1024)
                            session_key = private_key.decrypt(encrypted_session_key,
                                                              padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                           algorithm=hashes.SHA256(), label=None))
                            encrypted_key = target_client_key.encrypt(session_key,
                                                                      padding.OAEP(mgf=padding.MGF1(
                                                                          algorithm=hashes.SHA256()),
                                                                          algorithm=hashes.SHA256(),
                                                                          label=None))
                            targetClient.sendall(encrypted_key)
                            time.sleep(0.5)
                            iv = client.recv(1024)
                            targetClient.sendall(iv)

                            msg = client.recv(1024)
                            continue

                        while True:
                            targetClient.sendall(msg)

                            time.sleep(0.5)
                            result = dataResult[targetClientId]
                            if result == "correct data":
                                del dataResult[targetClientId]
                                break
                            client.sendall(result.encode("utf-8"))
                            del dataResult[targetClientId]

                            if result == "correct data...not finished":
                                break
                            else:
                                print("data is damaged. Resending process...")
                                msg = client.recv(1024)

                        msg = client.recv(1024)

                    targetClient.sendall("theEnd".encode('utf-8'))
                    print(f"File received completely from id: {client_id} and transferred completely to id: {targetClientId}.")

                ############################################################

                else:
                    print("Wrong format!")
                    reply = "Error"
                    client.sendall(reply.encode('utf-8'))
                    continue

            ################################################################

            else:
                YN = 'N'
                client.sendall(YN.encode('utf-8'))

        ####################################################################

        elif clientType[client_id] == 'R':

            authenticatedClients.append(client_id)

            encrypted_response = client.recv(1024)      # receiving signature check response from target client
            response = private_key.decrypt(encrypted_response, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
            dataResult0[client_id] = response.decode()
            if response != b'V':
                del clientDict[client_id]
                del clientType[client_id]
                try:
                    authenticatedClients.remove(client_id)
                except Exception:
                    1  # do nothing!

                index = 0
                for c in data['client']:
                    if c['id'] == client_id:
                        data['client'].pop(index)
                        break
                    index = index + 1
                break

            result = client.recv(1024)      # receiving MAC check response from target client
            dataResult[client_id] = result.decode()
            while result != b"correct data":
                while not (client_id in dataResult):
                    result = client.recv(1024)
                    dataResult[client_id] = result.decode()

        ####################################################################

        elif clientType[client_id] == 'E':
            print(f"Client from ip: {ip}, and port: {port} disconnected.")
            del clientDict[client_id]
            del clientType[client_id]
            try:
                authenticatedClients.remove(client_id)
            except Exception:
                1   # do nothing!

            index = 0
            for c in data['client']:
                if c['id'] == client_id:
                    data['client'].pop(index)
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
