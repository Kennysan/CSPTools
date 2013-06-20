#!/usr/bin/python

import sys
import time
import threading
import argparse
import atexit
sys.path.append("CSP-Browser")
sys.path.append("CSP-Proxy")
sys.path.append("CSP-Parser")

from CSPBrowser import *
from CSPProxy import *
from CSPParser import *

parser = argparse.ArgumentParser(description="Auto runner for the CSP tools")
parser.add_argument('list', metavar='listfile', help='list of urls to visit', type=argparse.FileType('r'))
parser.add_argument('-o', '--host', metavar='host', default='example.com', help='Host regexp to inject csp headers into', dest='hostre')
args = parser.parse_args()

#Load list
list = args.list.readlines()
args.list.close()

port=8080
host='localhost'
log = []
csp = [
    "default-src 'none';" +
    "script-src 'none';" +
    "object-src 'none';" +
    "img-src 'none';" +
    "media-src 'none';" +
    "style-src 'none';" +
    "frame-src 'none';" +
    "font-src 'none';" +
    "xhr-src 'none';"
][0]

#Start proxy
print 'Starting proxy'
x = CSPProxy(csp, port, re.compile(args.hostre), '/csp.php', lambda r: log.append(r))
t = threading.Thread(target=lambda: x.run())
atexit.register(lambda: x.shutdown)
t.start()

#Go through the list
print 'Visiting urls'
b = CSPBrowser(port, host)
b.load(list)
b.run()
b.shutdown()

#Kill the proxy
print 'Shutting down proxy'
x.shutdown()
t.join()

#Parse the reports
print 'Parsing logs'
p = CSPParser(args.hostre)
p.load(log)
p.generate(False)
print p
