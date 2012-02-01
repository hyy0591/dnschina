#!/usr/bin/python
#
# A quick hack to probe for SSL Certificate Information
# Requres python & m2crypto  
# 
# 2007.09.26 - phreakmonkey.com / phreakmonkey at gmail 
#
# Returns information in the following format:
#
# IP | Cert CN | Cert DN | Issuer DN | SubjAltName | Expiration
#

import sys
import socket
import string
import json

from M2Crypto import SSL

def reportIP(IPaddress):
	ctx = SSL.Context()
	ctx.set_allow_unknown_ca(True)
	ctx.set_verify(SSL.verify_none, 1)
	conn = SSL.Connection(ctx)
	conn.postConnectionCheck = None
	timeout = SSL.timeout(15)
	conn.set_socket_read_timeout(timeout)
	conn.set_socket_write_timeout(timeout)
	try:
		sys.stderr.write('Connecting '+IPaddress+'. ')
		sys.stderr.flush()
		conn.connect((IPaddress, 443))
	except:
		print >>sys.stderr, IPaddress+"|{SSL_HANDSHAKE_FAILED}|"+"|"+"|"+"|"
		sys.stderr.write('failed.\n')
		sys.stderr.flush()
		return
	sys.stderr.write('Getting cert info. ')
	sys.stderr.flush()

	cert = conn.get_peer_cert()
	try:
		cissuer = cert.get_issuer().as_text()
	except:
		sys.stderr.write("Error:  No Valid Cert Presented\n");
		print >>sys.stderr, IPaddress+"|{NO_CERT_PRESENTED}|"+"|"+"|"+"|"
		sys.stderr.flush
		conn.close
		return

	sys.stderr.write('done\n')
	sys.stderr.flush()
		
	csubject = cert.get_subject().as_text()
	try:
		cAltName = cert.get_ext('subjectAltName').get_value()
	except LookupError:
		cAltName = ""
	try:
		cCN = cert.get_subject().CN
	except AttributeError:
		cCN = ""
	try:
		cExpiry = str(cert.get_not_after())
	except AttributeError:
		cExpiry = ""
	conn.close
	ret = {}
	ret["ip"] = IPaddress
	ret["cn"] = cCN
	# ret["subject"] = csubject
	ret["issuer"] = cissuer.split("=")[-1]
	ret["alt"] = map(lambda x: x.split("DNS:")[-1], cAltName.split(", "))
	ret["expire"] = cExpiry
	
	print json.dumps(ret)
	return ret
	
if __name__ == "__main__":
	reportIP(sys.argv[1])
