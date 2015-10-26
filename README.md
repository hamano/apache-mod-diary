mod_diary - simple blog system for Apache HTTPD Server
======================================================

[![Build Status](https://travis-ci.org/hamano/apache-mod-diary.svg)](https://travis-ci.org/hamano/apache-mod-diary)

# Demo Blog

http://www.cuspy.org/diary/

## Dependencies

 * discount
     - http://www.pell.portland.or.us/~orc/Code/discount/

 * ClearSilver
     - http://www.clearsilver.net/

For debian:

~~~
# apt-get install libmarkdown2-dev clearsilver-dev
~~~

# Build

~~~
% autoreconf -i
% ./configure --with-apxs=<APXS_PATH>
% make
# make install
~~~

Also you can specify dependency libraries path
~~~
% ./configure --with-apxs=<APXS_PATH> \
    --with-discount=<DISCOUNT_DIR> \
    --with-clearsilver=<CLEARSILVER_DIR>
~~~

# Configration

httpd.conf

~~~
LoadModule diary_module modules/mod_diary.so
<Location />
  SetHandler diary
  DiaryTitle "Example Diary"
  DiaryURI http://www.example.com/diary/
  DiaryPath /path/to/diary
</Location>
~~~

You can specify `DiaryTheme` if you want to use custom theme.

## Optional Settings

||default value|
|---|---|
|DiaryTheme|default|
|DiaryGithubFlavouredMarkdown|On|
|DiaryCalendar|On|

# Author

HAMANO Tsukasa <http://twitter.com/hamano>

