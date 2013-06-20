#!/usr/bin/python

import signal
import sys
import threading
import os
import json
from libmproxy import proxy, flow
import re

#Todo
#	Local logging should be optional (opt-in/out?)
#defaultcsp = 'default-src \'none\'; script-src \'none\'; object-src \'none\'; img-src \'none\'; media-src \'none\'; style-src \'none\'; frame-src \'none\'; font-src \'none\'; xhr-src \'none\';'

#Create proxy
class CSPTestMaster(flow.FlowMaster):
    def __init__(self, server, state, policy, hostre, reporturi, callback=None):
        flow.FlowMaster.__init__(self, server, state)
        self.policy = policy
        self.hostre = hostre
        self.reporturi = reporturi
        self.callback = callback

    def run(self):
        flow.FlowMaster.run(self)

    def handle_request(self, r):
        f = flow.FlowMaster.handle_request(self, r)
        if f:
            r._ack()
            if r.path == self.reporturi:
                report=json.loads(r.content)['csp-report']
                print report['violated-directive'] + " : " + report['blocked-uri']
                if(self.callback):
                    self.callback(r.content)
        return f

    def handle_response(self, r):
        f = flow.FlowMaster.handle_response(self, r)
        if(self.hostre.search(r.request.host)):
            if r.headers["content-security-policy-report-only"]:
                r.headers["content-security-policy-report-only"] = [""]
            if r.headers["content-security-policy"]:
                r.headers["content-security-policy"] = [""]
            #if "content-security-policy" in r.headers:
            #    r.headers.pop("content-security-policy", None)
        	r.headers["content-security-policy-report-only"] = [
                self.policy +
                "report-uri " + self.reporturi
            ]
        if f:
            r._ack()
        return f

class CSPProxy:
    def __init__(self, policy, port, hostre, reporturi, callback):
        config = proxy.ProxyConfig(cacert = os.path.expanduser("~/.mitmproxy/mitmproxy-ca.pem"))
        state = flow.State()
        server = proxy.ProxyServer(config, port)
        self.proxy = CSPTestMaster(server, state, policy, hostre, reporturi, callback)

    def run(self):
        self.proxy.run()

    def shutdown(self):
        self.proxy.shutdown()
