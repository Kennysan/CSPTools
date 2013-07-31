#!/usr/bin/python

import sys
import argparse
from CSPBrowser import *

parser = argparse.ArgumentParser(description="Auto-visit target URLs")
parser.add_argument('-p', '--port', metavar='num', type=int, help='Port to listen on', dest='port')
parser.add_argument('-d', '--domain', metavar='d', help='IP address/hostname to listen on', dest='domain')
parser.add_argument('-u', '--url', metavar='u', action='append', help='url to visit', dest='url')
args = parser.parse_args()

if not args.url:
    args.url=[x.strip() for x in sys.stdin.readlines()]

ff = CSPBrowser(args.port, args.domain)
ff.load(args.url)
ff.run()
