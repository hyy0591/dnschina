#!/usr/bin/env python
import traceback
import socket
import sys
import signal
import os
import struct
import select
from Queue import Queue
from dnslib.dns import *
import time
import pygeoip
from datetime import datetime, timedelta

geoip = pygeoip.GeoIP("GeoIP.dat")

def hexdump(src, length=8):
	result = []
   	digits = 4 if isinstance(src, unicode) else 2
	for i in xrange(0, len(src), length):
	   s = src[i:i+length]
	   hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
	   text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
	   result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
	return b'\n'.join(result)

class DNSProxy(object):
	def __init__(self, prefs):
		self.prefs = prefs
	
	def read_client_socket(self):
		pkt, addr = self.client_sock.recvfrom(8192)
		if not pkt: return
			
		try:
			msg = DNSRecord.parse(pkt)
		except:
			traceback.print_exc(file=sys.stderr)
			return
		
		if self.pending_requests.has_key(msg.header.id):
			query, clientaddr, _ = self.pending_requests[msg.header.id]
			
			if len(msg.rr) == 1:
				if msg.rr[0].rtype == 1:
					if str(msg.rr[0].rdata) in self.prefs["blackholes"]:
						# try first domestic DNS server, and if poisoned, try foreign one
						if geoip.country_code_by_addr(addr[0]) == "CN":
							# ignore and query foreign server
							self.output_queue[self.client_sock].append((query.pack(), (self.prefs["upstream_foreign"], 53)))
							return
						else:
							# simply ignore
							return
			
			msg = self.response_rewrite(msg, query=query)
			if not msg: return
			print msg
			
			self.output_queue[self.master_sock].append((msg.pack(), clientaddr))
			del self.pending_requests[msg.header.id]
		
	def read_master_socket(self):
		pkt, addr = self.master_sock.recvfrom(8192)
		if not pkt: return
				
		try:
			msg = DNSRecord.parse(pkt)
		except:
			traceback.print_exc(file=sys.stderr)
			return
		
		print msg
		
		response = self.respond(msg)
		if response:
			print response
			self.output_queue[self.master_sock].append((response.pack(), addr))
		else:
			domain = str(msg.questions[0].qname) if len(msg.questions) else ""
			self.output_queue[self.client_sock].append((msg.pack(), (self.prefs["upstream_domestic"], 53)))
			self.pending_requests[msg.header.id] = (msg, addr, {"timestamp": datetime.now()})
	
	def write_socket(self, sock):
		while True:
			try: pkt, addr = self.output_queue[sock].pop(0)
			except IndexError: break
			try: 
				sock.sendto(pkt, addr)
			except socket.error, msg:
				print "sock.sendto received error " + str(msg)
	
	def _run(self):
		print "DNSProxy starting up."
		self.master_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		self.master_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.master_sock.setblocking(0)
		
		self.master_sock.bind(prefs["listen_addr"])
		
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
				return
	
	def cleanup(self):
		print "Cleaning up...."
		if getattr(self, "master_sock", None):
			self.master_sock.close()
			self.master_sock = None
		if getattr(self, "client_sock", None):
			self.client_sock.close()
			self.client_sock = None

	def response_rewrite(self, response, query=None):
		cname_list = []
		a_list = []
		for rr in response.rr:
			if rr.rtype == 5:
				cname_list.append(str(rr.rdata))
			if rr.rtype == 1:
				a_list.append(str(rr.rdata))

		# local telecom 404 redirection
		if len(a_list) == 1 and a_list[0].startswith("121.10.40."): 
			response.rr = []

		# Akamai
		if len(a_list):
			for cname in cname_list:
				for c in self.prefs["cname_hosts"]:
			 		if cname.endswith(c):
						response.rr = [RR(a_list[0], 1,rdata=A(self.prefs["cname_hosts"][c])), ]
		return response
	
	def respond(self, request):
		response = None
		if len(request.questions) == 1 and request.questions[0].qtype in [28, 1]: # both A and AAAA are fine
			domain = str(request.questions[0].qname)
			if self.prefs["hosts"].has_key(domain): response = request.reply(self.prefs["hosts"][domain], rtype=1)
			for i in self.prefs["blocked_suffixes"]:
				if domain.endswith(i): response = request.reply("0.0.0.0", rtype=1)
			for i in self.prefs["suffix_hosts"]:
				if domain.endswith(i): response = request.reply(self.prefs["suffix_hosts"][i], rtype=1)
		return response

def cleanup(*args):
	proxy.cleanup()
	sys.exit(0)

if __name__ == "__main__":	
	prefs = {
		"upstream_domestic" : "202.96.134.33", 
		"upstream_foreign" : "8.8.8.8", 
		"listen_addr" : ("127.0.0.1", 53), 
	}
	
	# GFW
	prefs["blackholes"] = [
		'243.185.187.30', 
		'243.185.187.39', 
		'46.82.174.68', 
		'78.16.49.15', 
		'93.46.8.89', 
		'37.61.54.158', 
		'159.24.3.173', 
		'203.98.7.65', 
		'8.7.198.45', 
		'159.106.121.75', 
		'59.24.3.173'
	]
	
	prefs["hosts"] = {
		"localhost"					:		"127.0.0.1", 
	}
	
	prefs["blocked_suffixes"] = [
		'.google-analytics.com', 
		'.doubleclick.net', 
	]
	
	prefs["suffix_hosts"] = {
		".googleapis.com"			:		"203.208.46.198", 
		".appspot.com"				:		"203.208.46.198",
		".googleusercontent.com"	:		"203.208.46.198", 
		".gstatic.com"				:		"203.208.46.198",
		".googlevendorcontent.com"	:		"203.208.46.198",
		".googlesyndication.com"	:		"203.208.46.198",
		".googlecode.com"			:		"203.208.46.198", 
		".ggpht.com"				:		"203.208.46.198",
		".phobos.apple.com"			:		"219.188.199.151", # Japan-ODN; "60.172.80.106" Shanghai-ChinaTelecom ; returns 403 on .phobos.apple.com
		".akamai.net"				:		"219.188.199.151",
		".mzstatic.com"				:		"219.188.199.151", # # Singapore:58.27.86.158 # Japan-KDDI:115.165.159.212 # HongKong-NTT:210.0.146.52 #Japan-ODN:210.175.5.158
		".akamaihd.net"				:		"219.188.199.151", 
	}
	
	prefs["cname_hosts"] = {
		".edgesuite.net"			:		"219.188.199.151", 
	}
	
	def load_hosts():
		import os.path
		if os.path.exists("hosts"):
			f = open("hosts", "r")
			content = f.readlines()
			f.close()
			
			for line in content:
				effective = line.split("#")[0].strip()
				components = effective.split()
				if len(components) >= 2: # ip host1 host2 host3 ...
					for host in components[1:]:
						# naively assume IP address is valid
						prefs["hosts"][host] = components[0]
		
	load_hosts()
	
	print "Total %d hosts" % len(prefs["hosts"])
	
	global proxy
	proxy = DNSProxy(prefs)
	signal.signal(signal.SIGINT, cleanup)
	proxy.run()