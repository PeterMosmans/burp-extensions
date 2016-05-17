"""
add_http_header - Burp extension to add one or more HTTP headers

Copyright (C) 2016 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""


import os

from burp import IBurpExtender
from burp import ISessionHandlingAction

TITLE = 'Add custom HTTP headers'
VERSION = '1.0'
HEADER_FILE = 'headers.txt'


class BurpExtender(IBurpExtender, ISessionHandlingAction):
    def __init__(self):
        self.add_headers = ''

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(TITLE)
        callbacks.registerSessionHandlingAction(self)
        input_file = HEADER_FILE
        try:
            if os.path.isfile(input_file) and os.stat(input_file).st_size:
                print('[+] reading ' + input_file)
                with open(input_file, 'r') as read_file:
                    self.add_headers = read_file.read()
                print(self.add_headers.strip())
            else:
                print('[-] could not read {0} (current directory is {1})'.
                      format(input_file, os.getcwd()))
        except IOError as exception:
            print('[-] could not read {0} ({1}'.format(input_file, exception))
        print('[+] {0} - version {1} loaded'.format(TITLE, VERSION))
        return

    def performAction(self, currentRequest, macroItems):
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = requestInfo.getHeaders()
        for request in headers:
            if 'HTTP/' in request:
                URI = request.split(' ')[1]
        print('Adding HTTP headers for ' + URI)
        for header in self.add_headers.splitlines():
            headers.add(header)
        reqBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        message = self._helpers.buildHttpMessage(headers, reqBody)
        currentRequest.setRequest(message)
        return
