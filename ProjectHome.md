### WHAT ###

A tool that uses local source tree to make requests to the url and search for path inclusion error messages. It's a common problem in PHP web applications that we've been hating to see. We hope this tool triggers no path disclosure flaws any more. See our article about path disclosure.

http://yehg.net/lab/pr0js/view.php/path_disclosure_vulnerability.txt

Report bugs/suggestions to inspathx at yehg dot net.


### WHY ###

Web application developers sometimes fail to add safe checks against
authentications, file inclusion ..etc are prone
to reveal possible sensitive information when
those applications' URLs are directly requested.
Sometimes, it's a clue to Local File Inclusion vulnerability.
For open-source applications, source code can be downloaded and
checked to find such information.

This script will do this job.
  1. First you have to download source archived file of your desired OSS.
  1. Second, extract it.
  1. Third, feed its path to inspath

The inspath takes

> -d, --dir /source/app           set source code directory/source path definition file of application [Required](Required.md)

> -u, --url http://site.com/      set url [if -g option is not specified](Required.md)

> -t, --threads 10                set thread number(default: 10)

> -l, --language php              set language [php,asp,aspx,jsp,jspx,cfm,all] (default all - means scan all)

> -x, --extension php             set file extensions (php4,php5,...)  default regex: php4,php5,php6,php,asp,aspx,jsp
,jspx,cfm

> -m, --method TYPE               http method get/post (default: get)

> -h, --headers HEADERS           add http header

> -q, --data DATA                 http get/post data

> -n, --null-cookie               add null session cookie (no need to specify cookie name)

> -f, --follow                    follow http redirection

> -p, --param-array               identify parameters in target url,make 'em array (value: 1 for [.md](.md), 2 for [.md](.md)[.md](.md),
> 3 for [.md](.md)[.md](.md)[.md](.md), n .... [.md](.md)`*`n)  <note: --data value untouched>

> -r, --regexp REGEXP             specify your own regexp to search in returned responses

> -g, --gen FILE                  read source directory (-d) & generate file list so next time you can feed this file path in -d option instead of source directory.

> --rm                        remove source directory used to generate path file list.

> -c, --comment STRING            comment for path definition file to be used with -g and -d options. date is automatically appended.

> --x-p                       show only paths in console and write them to file with path\_vuln.txt surfix. This does not contain target url portion.

> --xp                         alias to --x-p

> -s, --search STRING          search path definition files in paths/ & paths\_vuln/ directories.

See the sample logs in sample\_logs folder - scan logs of latest mambo and wordpress applications

Similar terms: Full Path Disclosure, Internal Path Leakage


### SUPPORTED LANGUAGES ###

  * PHP
  * ASP(X)
  * JSP(X)
  * ColdFusion


### HOW ###

ruby inspathx.rb -u http://localhost/wordpress

ruby inspathx.rb -u http://localhost/wordpress -p 1

ruby inspathx.rb -d /sources/wordpress -u http://localhost/wordpress

ruby inspathx.rb -d /sources/wordpress -g paths/wordpress-3.0.4

ruby inspathx.rb -d paths/wordpress-3.0.4 -u http://localhost/wordpress

ruby inspathx.rb -d c:/sources/wordpress -u http://localhost/wordpress -t 20 -l php

ruby inspathx.rb -d /sources/jspnuke -u http://localhost/jspnuke -t 20 -l jsp -x jsp,jspx -n


See EXAMPLES for more information.


### DOWNLOAD/UPDATE ###

We love svn. Check it out at

svn checkout http://inspathx.googlecode.com/svn/trunk/ inspathx-read-only


### SAMPLE LOGS ###

Mambo 4.6.5
http://inspathx.googlecode.com/svn/trunk/sample_logs/localhost_mambo_.log

WordPress 3.0.1
http://inspathx.googlecode.com/svn/trunk/sample_logs/localhost_wp_.log


### REFERENCES ###

http://www.owasp.org/index.php/Full_Path_Disclosure

http://projects.webappsec.org/Information-Leakage

http://cwe.mitre.org/data/definitions/209.html


> 
---

Use portable bash versions if you wish:

http://www.pentesterscripting.com/discovery/web_requester

http://www.pentesterscripting.com/exploitation/bash_web_parameter_fuzzer