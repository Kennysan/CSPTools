#!/usr/bin/python

from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.keys import Keys
import selenium.webdriver.support.ui as ui
import re
import atexit

disp = Display(visible=0, size=(800,600))
atexit.register(lambda: disp.stop())
disp.start()

class CSPBrowser:
    schema = re.compile('^https?://', re.IGNORECASE)
    def __init__(self, port=None, domain=None):
        profile = webdriver.FirefoxProfile()
        if port != None and domain != None:
            profile.set_preference("network.proxy.type",1)
            profile.set_preference("network.proxy.http", domain)
            profile.set_preference("network.proxy.http_port", port)
            profile.update_preferences()
        self.driver = webdriver.Firefox(firefox_profile=profile)	    

    def load(self, urllist):
        self.urllist = []
        for url in urllist:
            if not self.schema.match(url):
                url = 'http://' + url
            self.urllist.append(url)

    def run(self):
        for url in self.urllist:
            print url
            if (not len(url)): continue
            #print "Visiting: " + url
            self.driver.get(url)
            self.driver.get('about:blank')

    def shutdown(self):
        self.driver.close()