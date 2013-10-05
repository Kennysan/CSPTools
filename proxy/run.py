#!/usr/bin/python

import argparse
import re
from CSPProxy import *

defaultcsp = [
    "default-src 'none';" +
    "script-src 'none';" +
    "object-src 'none';" +
    "img-src 'none';" +
    "media-src 'none';" +
    "style-src 'none';" +
    "frame-src 'none';" +
    "font-src 'none';" +
    "connect-src 'none';"
][0]

defaultopencsp = [
    "default-src *;" +
    "script-src none 'unsafe-inline' 'unsafe-eval';" +
    "object-src *;" +
    "img-src *" +
    "media-src *;" +
    "style-src * unsafe-inline;" +
    "frame-src *;" +
    "font-src *;" +
    "connect-src *;"
][0]

#Parse out arguments
parser = argparse.ArgumentParser(description='Automagically adds a CSP header to all requests served through the proxy')
parser.add_argument('-p', '--port', metavar='num', type=int, default=8080, help='Port to bind to', dest='port')
parser.add_argument('-r', '--report', metavar='uri', default='/csp.php', help='URI to send CSP reports to', dest='reporturi')
parser.add_argument('-f', '--log', metavar='file', default='csp.log', help='File to log reports to', dest='logfile')
parser.add_argument('-m', '--block', help='sets to proxy to use a blocking CSP', action='store_true')
parser.add_argument('-o', '--host', metavar='host', default='www\.example\.com', help='Host regexp to inject csp headers into', dest='hostre')
parser.add_argument('-c', '--csp', metavar='csp', default=defaultcsp, help='Set content security policy to use', dest='csp')
args = parser.parse_args()

log = open(args.logfile, 'a');
p = CSPProxy(args.csp, args.port, re.compile(args.hostre), args.reporturi, args.block, lambda r: log.write(r+"\n"))
try:
    p.run()
except:
    p.shutdown()
log.close()
