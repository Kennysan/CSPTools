#!/usr/bin/python

import argparse
from CSPParser import *

parser = argparse.ArgumentParser(description="Log Parser")
parser.add_argument('log', metavar='logfile', help='log file to parse', type=argparse.FileType('r'))
parser.add_argument('-r', '--ignoreproto', help='Ignore protocols in CSP', action='store_true')
parser.add_argument('-o', '--host', help='Hostname of the site')
args = parser.parse_args()

cspparser = CSPParser(args.host)
cspparser.load(args.log.readlines())
args.log.close()
cspparser.generate(args.ignoreproto)
print cspparser
