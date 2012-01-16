#!/usr/bin/env python
import traceback
import socket
import sys
import signal
import os
import struct
import ConfigParser
import select
from Queue import Queue
from dnslib.dns import DNSRecord, DNSQuestion
from threading import Thread
import time
import rewrite
from datetime import datetime, timedelta

def hexdump(src, length=8):
	result = []
   	digits = 4 if isinstance(src, unicode) else 2
	for i in xrange(0, len(src), length):
	   s = src[i:i+length]
	   hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
	   text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
	   result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
	return b'\n'.join(result)

class DNSProxy(Thread):
	def __init__(self, config_path):
		Thread.__init__(self)
		self.config = self.read_config(config_path)
		self.daemon = True
		self.start()
	
	def read_config(self, config_path):
		config = ConfigParser.RawConfigParser()
		config.add_section('server')
		config.set('server', 'ip', '127.0.0.1')
		config.set('server', 'port', 53)
		config.add_section('upstream')
		config.set('upstream', 'ip', '202.96.134.33')
		if config_path:
			config.read(config_path)
		else:
			print "read_config: using default configurations"
		return config
	
	def find_upstream_server(self, domain):
		return rewrite.upstream_server(domain)
	
	def read_client_socket(self):
		pkt, addr = self.client_sock.recvfrom(8192)
		if not pkt: return
	
		print "read_client_socket: received packet of length %d" % len(pkt)
		
		try:
			msg = DNSRecord.parse(pkt)
		except:
			traceback.print_exc(file=sys.stderr)
			return
		
		msg = rewrite.response_handler(msg)
		if not msg: return
		print msg
		
		if self.pending_requests.has_key(msg.header.id):
			req, addr, additional = self.pending_requests[msg.header.id]
			self.output_queue[self.master_sock].append((msg.pack(), addr))
			del self.pending_requests[msg.header.id]
		
	def read_master_socket(self):
		pkt, addr = self.master_sock.recvfrom(8192)
		if not pkt: return
		
		print "read_master_socket: received packet of length %d" % len(pkt)
		
		try:
			msg = DNSRecord.parse(pkt)
		except:
			traceback.print_exc(file=sys.stderr)
			return
		
		print msg
		
		response = rewrite.respond(msg)
		if response:
			self.output_queue[self.master_sock].append((response.pack(), addr))
		else:
			domain = str(msg.questions[0].qname) if len(msg.questions) else ""
			self.output_queue[self.client_sock].append((msg.pack(), (self.find_upstream_server(domain), 53)))
			self.pending_requests[msg.header.id] = (msg, addr, {"timestamp": datetime.now()})
	
	def write_socket(self, sock):
		while True:
			try: pkt, addr = self.output_queue[sock].pop(0)
			except IndexError: break
			sock.sendto(pkt, addr)
	
	def _run(self):
		print "DNSProxy starting up."
		self.master_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		self.master_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.master_sock.setblocking(0)
		
		bind_ip = self.config.get("server", "ip")
		bind_port = self.config.getint("server", "port")
		self.master_sock.bind((bind_ip, bind_port))
		
		self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		self.client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.client_sock.setblocking(0)
		
		self.output_queue = {self.client_sock:list(), self.master_sock:list()}
		self.pending_requests = {}
		
		all_sockets = [self.master_sock, self.client_sock]
		lastcheck_timestamp = datetime.now()
		
		while True:
			write_sockets = filter(lambda socket: self.output_queue[socket], all_sockets)
			inputs, outputs, exceptions = select.select(all_sockets, write_sockets, all_sockets, 1)
			if self.client_sock in outputs: self.write_socket(self.client_sock)
			if self.master_sock in outputs: self.write_socket(self.master_sock)
			if self.client_sock in inputs: self.read_client_socket()
			if self.master_sock in inputs: self.read_master_socket()
			if exceptions: raise Exception("run: select() returned sockets with exceptions")
			
			if (lastcheck_timestamp + timedelta(seconds=3)) < datetime.now():
				for key in self.pending_requests.keys():
					pkt, addr, additional = self.pending_requests[key]
					if (additional["timestamp"] + timedelta(seconds=30)) < datetime.now():
						del self.pending_requests[key]
				lastcheck_timestamp = datetime.now()
		
	def run(self):
		while True:
			try:
				self._run()
			except (KeyboardInterrupt, SystemExit):
				self.cleanup()
				return
			except:
				traceback.print_exc(file=sys.stderr)
				self.cleanup()
				time.sleep(1)
	
	def cleanup(self):
		print "Cleaning up...."
		self.master_sock.close()
		self.master_sock = None
		self.client_sock.close()
		self.client_sock = None

def cleanup(*args):
	time.sleep(3)
	sys.exit(0)

if __name__ == "__main__":
	signal.signal(signal.SIGINT, cleanup)
	
	rewrite.initialize()
	
	proxy = DNSProxy("proxy.ini")

	# stupid hack to allow it to catch interruptions. better suggestions? 
	while True:
		time.sleep(60)
	