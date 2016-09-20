## Blackhole Hosts
Blackhole Hosts is an extension that drops proxy requests to certain hosts. This allows you to effectively blackhole hosts, while not modifying Burp's scope.

It is a Python extension, and therefore needs Jython.

### Usage
Create a textfile called `blackhole_hosts.txt` in the startup folder of Burp. Add one host (or regular expression) per line.

Example:
```
www.google.com*
clients*.google.com
www.gstatic.com
analytics.getpostman.com
www.google-analytics.com
app.getsentry.com
```

As soon as the extension is loaded it will read the configuration file and show the loaded rules in the extension's Output tab. Blocked requests will also be shown.

If the extension cannot load the configuration file or encounters other errors, it will be shown in the error tab.


### Current version
0.1

### Author
Peter Mosmans


