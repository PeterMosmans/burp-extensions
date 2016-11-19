"""
blackhole_hosts - Burp extension to drop requests to certain hosts.

Copyright (C) 2016 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import print_function

import os
import re

from burp import IBurpExtender
from burp import IInterceptedProxyMessage
from burp import IProxyListener

from java.io import PrintWriter

TITLE = 'Blackhole Hosts'
VERSION = '0.4'
CONFIG_FILE = 'blackhole_hosts.txt'


class BurpExtender(IBurpExtender, IProxyListener):
    """
    Extend Burp.
    """
    def __init__(self):
        self.regexps = []
        self.stdout = None
        self.stderr = None

    def registerExtenderCallbacks(self, callbacks):
        """
        Pass to extensions a set of callback methods that can be used by extensions
        to perform various actions within Burp.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(TITLE)
        callbacks.registerProxyListener(self)
        input_file = CONFIG_FILE
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        try:
            if os.path.isfile(input_file) and os.stat(input_file).st_size:
                self.stdout.println('[*] reading ' + input_file)
                with open(input_file, 'r') as read_file:
                    for config_line in read_file.read().splitlines():
                        try:
                            self.regexps.append(re.compile(config_line))
                            self.stdout.println('[*] adding {0} to blackhole list'.
                                                format(config_line))
                        except:
                            self.stdout.println('[-] invalid regular expression: {0}'.
                                                format(config_line))
            else:
                self.stderr.println('[-] could not read {0} from {1}'.
                                    format(input_file, os.getcwd()))
        except IOError as exception:
            self.stderr.println('[-] could not read {0} ({1}'.format(input_file,
                                                                     exception))
        self.stdout.println('[+] {0} - version {1} loaded'.format(TITLE, VERSION))
        return

    def processProxyMessage(self, messageIsRequest, message):
        """
        Process intercepted Proxy message.

        @messageIsRequest: boolean whether method is invoked for a request or response.
        @message: IInterceptedProxyMessage
        """
        if messageIsRequest:
            messageInfo = message.getMessageInfo()
            for regexp in self.regexps:
                host = messageInfo.getHttpService().getHost()
                if regexp.match(host):
                    self.stdout.println('Dropping request for {0} - {1}'.
                                        format(host,
                                               self._helpers.analyzeRequest(messageInfo).getUrl()))
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP)
                    break
        return
