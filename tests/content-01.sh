#!/bin/sh 

test x$srcdir = x && srcdir=.

docroot=/tmp/lighttpd/servers/123.example.org/pages/
reqfile=12345.txt
test -d $docroot || exit 77

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Content-Type 
GET /$reqfile HTTP/1.0
Host: 123.example.org

Content-Type: text/plain
EOF

run_test_script

if test x$exitcode = x0; then
  
  if cat $NAME.out | sed '1,/^.$/d' | cmp - $docroot/$reqfile; then
    a=a
  else
    exitcode=-1
  fi
fi

run_test_exit
