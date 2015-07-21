CSP-Proxy
=========

This folder contains some tools to simplify CSP generation.

CSP-Browser - Given some input urls, will attempt to auto-browse through the URIs

CSP-Proxy - mitm proxy to transmit CSP Headers and catch browser-generated CSP reports

CSP-Parser - Parse out proxy logs into a cohesive CSP policy

Running
-------

1. Generate a list of urls for the proxy to visit
2. Execute with `./autorun.py <list> -o <hostname>`

Run with `--help` for additional options

Requirements
------------

You will need the following packages (install w/ apt, homebrew, or your
friendly neighborhood package manager):

* libffi-dev
* libxml2-dev
* libxslt-dev

And these Python package dependencies:

- mitmproxy
- selenium
- pyvirtualdisplay
