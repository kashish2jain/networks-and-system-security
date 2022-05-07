import random
import os
from datetime import datetime
from OpenSSL import crypto
import ssl
import time
import socket
import hashlib
import hmac
import string
cipher_suite = ['ECDHE-RSA-AES128-SHA256','ECDHE-RSA-AES256-SHA384']
cipher_s = random.choice(cipher_suite)

def cls(p):
   p.close()
def cnt(p,hostname,port):
    p.connect((hostname,port))
    return p
#connecting with TTP
def socket1():
    ttp_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket=cnt(ttp_socket,'127.0.0.1',54536)

    return ttp_socket
#connecting with server
def socket2():
    serv_client_sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    secureClientSocket=context.wrap_socket(serv_client_sock);
    secureClientSocket=cnt(secureClientSocket,'127.0.0.1',54532)

    return secureClientSocket

def con(cipher_s):
    context.verify_mode=ssl.CERT_REQUIRED;

    context.set_ciphers(cipher_s)
    return context
#sharing secret key with server
def scs(secureClientSocket,record_key):
    time.sleep(1)
    secureClientSocket.send(record_key.encode())
    data = secureClientSocket.recv(4096)
    time.sleep(1)
    data=data.decode()
    return data
#generating key pair
def kg(client_key):
    client_key.generate_key(crypto.TYPE_RSA, 4096)
    return client_key
#decrypting the message received from server
def decrypt_record(data, key):
    if  data.startswith("sendrecieve"):
        pass
    elif not data.startswith("sendrecieve"):
        raise Exception("Message recieved from the wrong host or port")
    m1 = data.split("'")

    if  ("b'" + m1[1] + "'")!=str(hmac.new(key.encode(), m1[2].encode(),hashlib.sha1).digest()):
        raise Exception("Different keys on sender and reciever")
    obj = m1[2]
    return obj

#Creating Key
client_key = crypto.PKey()
client_key=kg(client_key)

print ("Key pair generated")
if  os.path.exists('PubKeys') and not os.path.exists('Client'):
    # os.makedirs('PubKeys')
    os.makedirs('Client')

with open('PubKeys/client.key', "wt") as f1 ,open('Client/client.key', "wt") as f2 :
    f1.write(crypto.dump_publickey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))
    f2.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))

print ("Connecting to the TTP")
ttp_socket=socket1()



ttp_socket.sendall(b'client')
cls(ttp_socket)

print ("Certificate recieved")
time.sleep(3)
context = ssl.SSLContext();
context=con(cipher_s)

context.load_verify_locations("./CA/ca.crt");

context.load_cert_chain(certfile="./CA/client.crt", keyfile="./Client/client.key");
secureClientSocket=socket2()

print ("Requested Server Certificate")
server_cert = secureClientSocket.getpeercert();

## VERIFY SERVER'S Certificate
### Validate whether the Certificate is indeed issued to the server
if server_cert:
    pass
elif not server_cert:
    raise Exception("Unable to retrieve server certificate");
subject={}
for item in server_cert['subject']:
    n=item[0]
    subject[n[0]]=n[1]

commonName = subject['commonName'];
if commonName == 'server':
    pass
elif commonName != 'server':
    raise Exception("Incorrect common name in server certificate");
### Check dates
after = str(server_cert['notAfter'])

if datetime.timestamp(datetime.strptime( after[:-4],"%b %d %H:%M:%S %Y"))-time.time() >= 0:
    pass
elif datetime.timestamp(datetime.strptime( after[:-4],"%b %d %H:%M:%S %Y"))-time.time() < 0:
    raise Exception ("Certificate has expired")
print ("Certificate verified")
str1=''
#generating a random secret key to be shared with server
for ele in random.choices(string.ascii_uppercase + string.digits, k = 20):
    str1+=ele
record_key=str1

time.sleep(1)
data=scs(secureClientSocket,record_key)

key=record_key
if data.startswith("sendrecieve"):
    pass
elif not data.startswith("sendrecieve"):
    raise Exception("Message recieved from the wrong host or port")
m1=data.split("'")

if ("b'" + m1[1] + "'") != str(hmac.new(key.encode(), m1[2].encode(), hashlib.sha1).digest()):
    raise Exception("Different keys on sender and reciever")
mes=m1[2]


print ("Message Recieved:",mes)
cls(secureClientSocket)


