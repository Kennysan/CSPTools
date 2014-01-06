#!/usr/bin/python

import sys
import time
import threading
import argparse
import atexit
import re

from browser import CSPBrowser
from proxy import CSPProxy
from parser import CSPParser

parser = argparse.ArgumentParser(description="Auto runner for the CSP tools")
parser.add_argument('urls', metavar='listfile', help='list of urls to visit', type=argparse.FileType('r'))
parser.add_argument('-o', '--host', metavar='host', default='www\.example\.com', help='Host regexp to inject csp headers into', dest='hostre')
args = parser.parse_args()

#Load list
urls = args.urls.readlines()
args.urls.close()

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
    "connect-src 'none';"
][0]

#Start proxy
print 'Starting proxy'
x = CSPProxy.CSPProxy(csp, port, re.compile(args.hostre), '/csp.php', False,lambda r: log.append(r))
t = threading.Thread(target=lambda: x.run())
atexit.register(lambda: x.shutdown)
t.start()

#Go through the list
print 'Visiting urls'
b = CSPBrowser.CSPBrowser(port, host)
b.load(urls)
b.run()
b.shutdown()

#Kill the proxy
print 'Shutting down proxy'
x.shutdown()
t.join()

#Parse the reports
print 'Parsing logs'
p = CSPParser.CSPParser(args.hostre)
p.load(log)
p.generate(False)

#Print the generated CSP
print p
