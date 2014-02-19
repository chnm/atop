# Atop (Apache Top)

*Requirements*

This tool is basically a wrapper script around the 'links' command that pulls info from Apache's default system-status functionality.

* Apache with system-status module enable and functioning
* links
* netstat


*Options*

a = sort all threads by time
c = sort by CPU, no GCRK_
i = list IPs connected to Apache (uses Apache Server Status)
k = sort by K (Keep alives)
n = list IPs connected to server (uses netstat)
o = sort open connections by CPU
p = sort only POST threads by time
r = raw apache status output (good with limit of at least 50)
s = search for a term, returns raw Apache Server Status results
w = sort by inactive workers
q = quit
