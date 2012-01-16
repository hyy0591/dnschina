from dnslib.dns import *

def response_handler(response):
	if len(response.rr) == 1:
		if response.rr[0].rtype == 1:
			if str(response.rr[0].rdata) in ['243.185.187.30', '243.185.187.39', '46.82.174.68', '78.16.49.15', '93.46.8.89', '37.61.54.158', '159.24.3.173', '203.98.7.65', '8.7.198.45', '159.106.121.75', '59.24.3.173']:
	#			response.rr[0].rdata = RDMAP[QTYPE[response.q.qtype]]("0.0.0.0")
				return None
	cname_list = []
	a_list = []
	for rr in response.rr:
		if rr.rtype == 5:
			cname_list.append(str(rr.rdata))
		if rr.rtype == 1:
			a_list.append(str(rr.rdata))
	for cname in cname_list:
		if len(a_list) and cname.endswith(".edgesuite.net"):
			response.rr = [RR(a_list[0], 1,rdata=A(AKAMAI_DYNAMIC)), ]
		for i in AKAMAI_STREAM_SUFFIX:
			if len(a_list) and cname.endswith(i):
				response.rr = [RR(a_list[0], 1,rdata=A(AKAMAI_STREAM)), ]
	return response

def upstream_server(domain):
	for i in CHINA_DOMAIN_SUFFIX:
		if domain.endswith(i) : return "202.96.134.33"
	return "8.8.8.8"

HOSTS = {}
BLOCK_SUFFIX = [".google-analytics.com", ]
GOOGLE_IP = "203.208.45.213"
GOOGLE_DOMAIN_SUFFIX = [".googleapis.com", ".appspot.com", ".googleusercontent.com", ".gstatic.com", ".googlevendorcontent.com", ".googlesyndication.com", ".googlecode.com", ".ggpht.com"]
AKAMAI_CHINA = "60.172.80.106" # Shanghai-ChinaTelecom ; returns 403 on .phobos.apple.com
AKAMAI_DYNAMIC = "219.188.199.151" # Japan-ODN
AKAMAI_STREAM = "115.165.159.212" # Singapore:58.27.86.158 # Japan-KDDI:115.165.159.212 # HongKong-NTT:210.0.146.52 #Japan-ODN:210.175.5.158
AKAMAI_STATIC_SUFFIX = [".phobos.apple.com", ]
AKAMAI_DYNAMIC_SUFFIX = [".akamai.net", ".mzstatic.com", ".akamaihd.net"]
# AKAMAI_STREAM_SUFFIX = [".akamaistream.net", ".akafms.net", ".edgefcs.net"]
AKAMAI_STREAM_SUFFIX = [] # Akamai Streaming Server acceleration is disabled because I cannot find an awesome IP. 
CHINA_DOMAIN_SUFFIX = [".tudou.com", ".youku.com", ".sohu.com", ".taobao.com", ".tbcdn.com"]

def respond(request):
	response = None
	if len(request.questions) == 1 and request.questions[0].qtype in [28, 1]: # both A and AAAA are fine
		domain = str(request.questions[0].qname)
		if HOSTS.has_key(domain): response = request.reply(HOSTS[domain], rtype=1)
		for i in BLOCK_SUFFIX:
			if domain.endswith(i): response = request.reply("0.0.0.0", rtype=1)
		for i in GOOGLE_DOMAIN_SUFFIX:
			if domain.endswith(i): response = request.reply(GOOGLE_IP, rtype=1)
		for i in AKAMAI_STATIC_SUFFIX:
			if domain.endswith(i): response = request.reply(AKAMAI_DYNAMIC, rtype=1)
		for i in AKAMAI_DYNAMIC_SUFFIX:
			if domain.endswith(i): response = request.reply(AKAMAI_DYNAMIC, rtype=1)
		for i in AKAMAI_STREAM_SUFFIX:
			if domain.endswith(i): response = request.reply(AKAMAI_STREAM, rtype=1)
	return response

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