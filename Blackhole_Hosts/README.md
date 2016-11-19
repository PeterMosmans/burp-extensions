## Blackhole Hosts
Blackhole Hosts is an extension that drops proxy requests to certain hosts, and logs those dropped requests. This allows you to effectively blackhole hosts, while not modifying Burp's (included or excluded) scope.

It is a Python extension, and therefore needs Jython.

### Usage
Create a textfile called `blackhole_hosts.txt` in the startup folder of Burp. Add one host (or regular expression) per line.

Example:
```
.*\.2o7\.net
.*\.google\..*
.*\.blueconic\.net
.*\.facebook\.[com|net]
.*\.gstatic\.com
.*\.pingvp\.com
.*\.salesforceliveagent\.com
analytics\.getpostman\.com
app\.getsentry\.com
col\.eum-appdynamics\.com
glancecdn\.net
w\.usabilla\.com
```

As soon as the extension is loaded it will read the configuration file and show the loaded rules in the extension's Output tab. Blocked requests will also be shown.

If the extension cannot load the configuration file or encounters other errors, it will be shown in the error tab.


### Current version
0.3

### Author
Peter Mosmans


