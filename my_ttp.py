import random
import os
from datetime import datetime
from OpenSSL import crypto
import socket
import ssl
#creating Pubkeys,CA directories
if not os.path.exists('PubKeys') and not os.path.exists('CA'):
    os.makedirs('PubKeys')
    os.makedirs('CA')
    print("CA directory and Pubkeys directory are created")
#writing CA key to Pubkey folder,
def save(file, ca_cert,ca_key):
    # Save certificate
    with open(root_ca_path, "wt") as f:
        f.write(crypto.dump_certificate(file, ca_cert).decode("utf-8"))

    # Save private key
    with open(key_path, "wt") as f:
        f.write(crypto.dump_privatekey(file, ca_key).decode("utf-8"))

    # Save public key
    with open('Pubkeys/ca.key', "wt") as f:
        f.write(crypto.dump_publickey(file, ca_key).decode("utf-8"))
#setting the serial number of certificate
def set_int():
    ca_cert=crypto.X509()
    ca_cert.set_version(2) # X509v3 (version value is zero-based i.e. 0 is for V1, 1 for V2 and 2 for V3)
    t=random.randrange(50000000, 100000001,1)
    ca_cert.set_serial_number(t)
    return ca_cert

#adding x509 extensions to CA certificate
def add_ext(cert):
    extensions2=[

                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert)]
    cert.add_extensions(extensions2)

    ext4=[crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=cert)]
    cert.add_extensions(ext4)


#adding x509 extensions to Client,server certificate
def addclient_ext(cert):
    cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),])



#creating socket to listen to server request
def socket1():
    ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ttp_socket.bind((HOST,PORT_TTP))
    ttp_socket.listen()
    server_conn,server_addr = ttp_socket.accept()
    return server_conn,server_addr,ttp_socket
#creating self signed CA certificate
def create_CA(root_ca_path, key_path):
    ''' Create CA and Key'''
    ca_cert=set_int()
    ca_subj = crypto.X509Name(ca_cert.get_subject())
    setattr(ca_subj, 'C', 'IN')
    setattr(ca_subj, 'ST', 'New Delhi')
    setattr(ca_subj, 'L', 'Rohini')
    setattr(ca_subj, 'O', 'IITD')
    setattr(ca_subj, 'OU', 'CSE IITD')
    setattr(ca_subj, 'CN', 'CSE IITD TTP')


    ca_cert.set_subject(ca_subj)
    ca_cert.set_issuer(ca_subj)
    ca_key=crypto.PKey()  # (RSA public key) OR (key pair)
    ca_key.generate_key(crypto.TYPE_RSA, 4096)
    ca_cert.set_pubkey(ca_key)
    add_ext(ca_cert)
    extensions=[
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'), ]
    ca_cert.add_extensions(extensions)

    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(365*24*60*60)

    ca_cert.sign(ca_key, 'sha256')
    save(crypto.FILETYPE_PEM, ca_cert,ca_key)
    return ca_cert
def write_fun(path,client_cert):
    with open(path, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode("utf-8"))
#checking validity of received certificate
def time():
    with open(root_ca_path, "r") as f1,open(key_path, "r") as f2:
        ca_cert=crypto.load_certificate(crypto.FILETYPE_PEM, f1.read())
        ca_key=crypto.load_privatekey(crypto.FILETYPE_PEM, f2.read())

    validity=(datetime.strptime(str(ca_cert.get_notAfter(), 'utf-8'), "%Y%m%d%H%M%SZ") - datetime.now()).days
    print("CA Certificate valid for {} days".format(validity))

    return ca_cert,ca_key
#creating certificates of client,server
def create_cert(ca_cert, ca_subj, ca_key, make_cn,user_key):
    ''' Create certificate '''


    make_cert=set_int()
    make_cert.gmtime_adj_notBefore(0)
    client_subj = make_cert.get_subject()
    client_subj.commonName = make_cn

    make_cert.set_issuer(ca_subj)
    make_cert.set_pubkey(user_key)
    addclient_ext(make_cert)
    ext1=[
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid", issuer=ca_cert),

        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
    ]
    make_cert.add_extensions(ext1)

    make_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=make_cert),
    ])
    make_cert.gmtime_adj_notAfter(365*24*60*60)

    make_cert.sign(ca_key, 'sha384')
    path="CA/"+make_cn + ".crt"
    write_fun(path,make_cert)

#opening socket to listen requests of server,client and creating their certificates
def process1(subject,pt1):
    server_conn, server_addr, ttp_socket=socket1()


    server_key=set(pt1)
    for _ in infinity():
        data=server_conn.recv(1024)
        if not data:
            break


        server_cn=data.decode()

    create_cert(ca_cert, subject, ca_key, server_cn, server_key)

    ttp_socket.close()

def set(pt):
       with open(pt, "r") as f:
              client_key=crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
       return client_key
def infinity():
    while True:
        yield



key_path = "CA/ca.key"
root_ca_path = "CA/ca.crt"

if os.path.exists(root_ca_path):
    print ("CA certificate has been found as {}".format(root_ca_path))
    ca_cert,ca_key=time()
elif not os.path.exists(root_ca_path):
    print ("Creating CA Certificate")
    create_CA(root_ca_path, key_path)
    print (" CA Certificate has been created")
    ca_cert,ca_key=time()


#SERVER INTERACTION
HOST = '127.0.0.1'
PORT_TTP = 54535
pt1="PubKeys/server.key"
print ("Connecting to server")

subject = ca_cert.get_subject()
process1(subject,pt1)
print ("Server Digital Certificate has been issued")


# CLIENT INTERACTION
PORT_TTP = 54536
pt2="PubKeys/client.key"
print ("Connecting to Client")
process1(subject,pt2)
print ("Client Digital Certificate has been issued")


