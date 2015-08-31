#!/usr/bin/env python
import socket
from struct import *
import random
import sys

TCP_IP = '0.0.0.0'
TCP_PORT = 4551
BUFFER_SIZE = 1024

def encode(content, key):
	c = list(content)
	d = 0
	for i in xrange(len(content)):
		c[i] = chr(ord(c[i]) ^ ord(key[d]))
		d = (d+1) % len(key)
	return "".join(c)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
	s.bind((TCP_IP, TCP_PORT))
except socket.error as e:
	print "Bind failed: "+str(e[0])+" : "+e[1]
	sys.exit()

s.listen(0)

while True:
	conn, addr = s.accept()
	with open("level07.pak", mode='rb') as file:
		content = file.read()
	print "connected from:" + addr[0] + ":" + str(addr[1])
	print len(encode(pack("<I", len(content)) + content, "AAAAAAAA"))
	print conn.sendall(pack("<I", len(content)) + encode(content, "AAAAAAAA"))
	conn.close()

s.close()

