import socket
import hmac
import hashlib
import random

from OpenSSL import crypto
import ssl
import time
import os
from datetime import datetime

import string
def soc():
     return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#creating socket to connect with TTP
def socket1(HOST, PORT_TTP):
    ttp_socket=soc()

    ttp_socket.connect((HOST, PORT_TTP))
    #common name is server
    ttp_socket.sendall(b'server')
    return ttp_socket

def make_it(client_conn):
    secure_serv_client_sock=ssl.wrap_socket(client_conn, server_side=True, cert_reqs=ssl.CERT_REQUIRED,
                                            ssl_version=ssl.PROTOCOL_TLSv1_2, ca_certs="./CA/ca.crt",
                                            certfile="./CA/server.crt", keyfile="./Server/server.key")
    return secure_serv_client_sock,secure_serv_client_sock.getpeercert();

#creating socket to connect with clients
def socket2(HOST, PORT_S):
    serv_client_sock=soc()

    serv_client_sock.bind((HOST, PORT_S))
    serv_client_sock.listen()
    return serv_client_sock
#generating key pair of server
def key_gen():
    print("Key pair generated")
    server_key=crypto.PKey()
    server_key.generate_key(crypto.TYPE_RSA, 4096)

    return server_key
def cls(p):
   p.close()

server_key=key_gen()
def file_op():

    if  os.path.exists('PubKeys') and not os.path.exists('Server'):

        os.makedirs('Server')
    with open('PubKeys/server.key', "wt") as f1,open('Server/server.key', "wt") as f2 :
        f1.write(crypto.dump_publickey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))
        f2.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))
file_op()

print ("Connecting to the TTP")
ttp_socket=socket1('127.0.0.1',54535)
cls(ttp_socket)

print("Certificate recieved")

time.sleep(3)


# Connecting to Client

serv_client_sock=socket2('127.0.0.1',54532)
client_conn, client_addr=serv_client_sock.accept()
print ("Requested Client Certificate")
secure_serv_client_sock,client_cert=make_it(client_conn)


# Check the client certificate bears the expected name as per server's policy
if client_cert:
    pass
elif not client_cert:
    raise Exception("Unable to get the certificate from the client");
clt_subject={}
for item in client_cert['subject']:
    n=item[0]
    clt_subject[n[0]]=n[1]

clt_commonName = clt_subject['commonName'];
try:
    if clt_commonName == 'client':
        pass
    else :
         raise Exception("Incorrect common name in client certificate");
finally:
    pass

## Check dates
after = str(client_cert['notAfter'])

try:
    pass
except:
    if datetime.timestamp(datetime.strptime(after[:-4],"%b %d %H:%M:%S %Y"))-time.time() < 0:
         raise Exception ("Certificate has expired")

print ("Certificate Verified")

m = "The OTP for transferring Rs 1,00,000 to your friend’s account is 256345."
def infinity():
    while True:
        yield
def my_function():
    time.sleep(1)
#sending message to client
with client_conn:
    print ("Connected to Client")
    for _ in infinity():

        record_key = secure_serv_client_sock.recv(1024)
        if record_key:
            pass
        elif not record_key:
            break
        time.sleep(1)
        key=record_key.decode()
        cipher=hmac.new(key.encode(), m.encode(), hashlib.sha1)
        data="sendrecieve" + str(cipher.digest())
        data=data+ m
        time.sleep(1)
        secure_serv_client_sock.send(data.encode())
cls(secure_serv_client_sock)


