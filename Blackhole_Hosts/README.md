## Blackhole Hosts
Blackhole Hosts is an extension that drops proxy requests to certain hosts. This allows you to effectively blackhole hosts, while not modifying Burp's scope.

It is a Python extension, and therefore needs Jython.

### Configuration
Create a textfile called `blackhole_hosts.txt` in the root folder of Burp, and add each host per line. You can also use regular expressions.

Example:
```
www.google.com*
clients*.google.com
www.gstatic.com
analytics.getpostman.com
www.google-analytics.com
app.getsentry.com
```

