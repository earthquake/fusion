#!/usr/bin/env python
import socket

TCP_IP = '172.16.193.195'
TCP_PORT = 20004
BUFFER_SIZE = 1024

bof = "PLACE IT HERE"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
data = s.recv(BUFFER_SIZE)
print "received data:", data
s.send(bof)
data = s.recv(BUFFER_SIZE)
s.close()

print "received data:", data
