from dnslib.dns import *

def response_handler(response):
	if len(response.rr) == 1:
		if response.rr[0].rtype == 1:
			if str(response.rr[0].rdata) in ['243.185.187.30', '46.82.174.68', '78.16.49.15', '93.46.8.89', '37.61.54.158', '159.24.3.173', '203.98.7.65', '8.7.198.45', '159.106.121.75', ]:
				response.rr[0].rdata = RDMAP[QTYPE[response.q.qtype]]("0.0.0.0")
			
	return response

HOSTS = {}
BLOCK_SUFFIX = [".google-analytics.com", ]
GOOGLE_IP = "203.208.45.213"
GOOGLE_DOMAIN_SUFFIX = [".googleapis.com", ".appspot.com", ".googleusercontent.com", ".gstatic.com", ".googlevendorcontent.com", ".googlesyndication.com", ".googlecode.com", ".ggpht.com"]

def respond(request):
	if len(request.questions) == 1 and request.questions[0].qtype == 1:
		domain = str(request.questions[0].qname)
		for i in BLOCK_SUFFIX:
			if domain.endswith(i): return request.reply("0.0.0.0")
		for i in GOOGLE_DOMAIN_SUFFIX:
			if domain.endswith(i): return request.reply(GOOGLE_IP)
		if HOSTS.has_key(domain): return request.reply(HOSTS[domain])
	return None

def read_hosts():
	f = open("hosts", "r")
	lines = f.readlines()
	for l in lines:
		c = l.split("#")[0].strip().split()
		if len(c) == 2:
			HOSTS[c[1]] = c[0]
	f.close()
	print "Loaded %d host records" % len(HOSTS)
		
def initialize():
	read_hosts()