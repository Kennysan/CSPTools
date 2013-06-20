#!/usr/bin/python

import json
import re
from urlparse import urlparse

#NOTE: Currently, the code skips any inline javascript

CSPV = ['none', 'script', 'object', 'img', 'media', 'style', 'frame', 'font', 'xhr', 'default']

class base:
    def __init__(self, scheme='', port=0, hostname=[], violation=''):
        self.scheme = scheme
        self.port = port
        self.hostname = hostname
        self.violation = violation

    def __bool__(self):
        return self.scheme != '' and self.port != 0 and self.hostname != []

    def __and__(self, obj):
        if(self and not obj): return testurl(self.scheme, self.port, self.hostname, self.violation)

        scheme = self.scheme if self.scheme == obj.scheme else ''
        port = self.port if self.port == obj.port else 0
        hostname = []
        for x, y in zip(self.hostname, obj.hostname):
            p = x if x==y else '*'
            hostname.append(p)
            if(p == '*'):
                break
        violation = self.violation if self.violation == obj.violation else ''
        return testurl(scheme, port, hostname, violation) if scheme and port and hostname else testurl('', 0, [], 'none')

class testurl(base):
    default_port = {'http':80,'https':443,'null':-1}
    slash_re = re.compile('/+')
    def __init__(self, scheme, port, hostname, violation):
        base.__init__(self, scheme, port, hostname, violation)

    def __str__(self):
        return self.origin()

    def origin(self, full=False, proto=True):
        #Needs work, the code currently assumes all domains consist of .+\..+ which is NOT true. (asd.co.nl)
        tmp = self.hostname[0:9001 if full else 2]
        tmp.reverse()
        return (self.scheme + '://' if proto else '') + '.'.join(tmp)

class bucket(base):
    def __init__(self, scheme, port, hostname, violation):
        base.__init__(self, scheme, port, hostname, violation)
        self.urls = []

class CSPParser:
    def __init__(self, host):
        self.hostre = re.compile('^(?:\w+://)?(.+)$')
        self.host = host

    def load(self, urls):
        self.urls = {}
        javascript_re = re.compile('^javascript:')
        violation_re = re.compile('^\w+')
        for line in urls:
            try:
                jsonreport = json.loads(line)['csp-report']
                str = jsonreport['blocked-uri']
                violation = violation_re.match(jsonreport['violated-directive']).group()
                if(javascript_re.match(str)): continue

                self.urls[str.partition('?')[0]] = violation if violation in CSPV else 'none'
            except: pass #print "Error loading: " + x

    def __str__(self):
        return ' '.join([type + '-src ' + ' '.join(self.results[type]) + ';' for type in self.results if self.results[type]])

    def generate(self, r):
        buckets = dict([(x, {}) for x in CSPV])
        urlobjs = []

        for x in self.urls:
            res = urlparse(x)
            scheme = 'null' if r else res.scheme
            if res.port != None:
                port = res.port or testurl.default_port[scheme]
            else:
                port = None
            if res.hostname != None:
                hostname = res.hostname.split('.')
                hostname.reverse()
                urlobjs.append(testurl(scheme, port, hostname, self.urls[x]))
            urlobjs = list(set(urlobjs))
        for x in urlobjs:
            subbuckets = buckets[x.violation]
            domain = x.origin()
            if(domain not in subbuckets):
                subbuckets[domain] = bucket(x.scheme, x.port, x.hostname, x.violation)
            subbuckets[domain].urls.append(x)

        self.results = dict([(x, []) for x in CSPV])

        for type in buckets:
            for domain in buckets[type]:
                intersect = None
                for x in buckets[type][domain].urls:
                    intersect = x & intersect
                self.results[type].append(intersect.origin(True, not r))
            if(len(self.results[type]) == 1 and self.host == self.hostre.match(self.results[type][0]).group(1)):
                self.results[type]=["'self'"]
        if(not self.results['default']):
            self.results['default']=["'self'"]
        return self.results
