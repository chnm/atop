# Atop (Apache Top)

## Info

This tool is basically a BASH wrapper script around the "links" command that pulls info from the Apache default mod_status functionality and displays the results on the command line, similar to the "top" command.


## Requirements


* Apache with mod_status module enabled and functioning, ExtendedStatus directive in httpd.conf active
* links program installed
* netstat program installed
* Apache status page available at http://localhost/server-status


## Usage

Run the script on the command line:

````
./atop
````

You can also pass the script a number to limit the lines of results returned (good for viewing on small screens). The default is 300 lines.

````
./atop 50
````

This would limit the results to 50 lines.

See here for a blog post on using atop: <a href="http://mossiso.com/2014/04/02/atop-apache-top-for-keeping-tabs-on-the-web-servers.html">http://mossiso.com/2014/04/02/atop-apache-top-for-keeping-tabs-on-the-web-servers.html</a>


## Command Options

````
a = sort all threads by time
c = sort by CPU, no GCRK_
i = list IPs connected to port 80 (uses Apache Server Status)
k = sort by K (Keep alives)
l = list IPs connected to all ports (uses netstat)
n = list IPs connected to port 80 (uses netstat)
o = sort open connections by CPU
p = sort only POST threads by time
r = raw apache status output (good with limit of at least 50)
s = search for a term, returns raw Apache Server Status results
w = sort by inactive workers
q = quit
````

## Archived
RRCHNM archived this repository in March 2022. Prior to archiving, last code activity was July 2014. If you need more information or to unarchive this repository, please contact us at webmaster at chnm.gmu.edu

## Similar Programs

Two other great options exist, written in python or perl.

* https://github.com/fr3nd/apache-top
* https://github.com/JeremyJones/Apachetop
