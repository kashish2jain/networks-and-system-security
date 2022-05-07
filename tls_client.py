#!/usr/bin/python3
import socket, ssl, sys, pprint
import os
hostname = sys.argv[1]
port = 443
cadir='/etc/ssl/certs'
import subprocess
import shlex
path='/etc/hosts'
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")
# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
do_handshake_on_connect=True)
ssock.do_handshake() # Start the handshake

domain = hostname.split("www.")[1:]

# d=domain[0]
cmd='dig facebook.com +short'
proc=subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
out,err=proc.communicate()
print(out)
with open('/etc/hosts', 'rt') as f:
    s = f.read() + out
    with open('/tmp/etc_hosts.tmp', 'wt') as outf:
        outf.write(s)

os.system('sudo mv /tmp/etc_hosts.tmp /etc/hosts')

pprint.pprint(ssock.getpeercert())
print(ssock.cipher())
# Send HTTP Request to Server
# hostname='https://in.yahoo.com/?p=us'
request="/o/oauth2/v2/auth"
server=hostname
# fullResuest="GET/ "+ " HTTP/1.0\r\n";
# fullResuest+="Host: " + server + "\r\n";
# fullResuest+="Accept: */*\r\n";
# fullResuest+="Connection: close\r\n\r\n";
# write(ssock, buffer(fullResuest));
# request = b"GET / HTTP/1.0\r\nHost: " + hostname.encode('utf-8') + b"\r\n"+b"Connection: close\r\n\r\n"
request= 'GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n'

ssock.sendall(request)
# # Read HTTP Response from Server
response = ssock.recv(2048)
while response:
    pprint.pprint(response.split(b"\r\n"))
    response = ssock.recv(2048)

hostname="www.yahoo.com"
# PARAMS = {'address':"dtu"}
# request = b"GET / HTTP/1.0\r\nHost: " + hostname.encode('utf-8') + b"\r\n\r\n"
# import requests
# r=requests.get(url = hostname)
# ssock.sendall(request)
# Read HTTP Response from Server
# response = ssock.recv(2048)
# while response:
#     pprint.pprint(response.split(b"\r\n"))
#     response = ssock.recv(2048)
# print(r)

input("After handshake. Press any key to continue ...")
# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()