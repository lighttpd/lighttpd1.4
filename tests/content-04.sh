#!/bin/sh 

if pidof php > /dev/null; then
	echo -n
else
        printf "%-40s" "Getting PHP code"
        exit 77
fi

test x$srcdir = x && srcdir=.

docroot=/tmp/lighttpd/servers/123.example.org/pages/
reqfile=phpinfo.php
test -d $docroot || exit 77

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Content-Type 
GET /$reqfile HTTP/1.0
Host: 123.example.org

EOF

run_test_script

if test x$exitcode = x0; then
  # got the source of the php-file
  if cat $NAME.out | sed '1,/^.$/d' | cmp - $docroot/$reqfile; then
    exitcode=-1
  fi > /dev/null
fi

run_test_exit
