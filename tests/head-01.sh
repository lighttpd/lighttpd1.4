#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
HEAD request should have no content
HEAD /index.html HTTP/1.0

Status: 200
EOF

run_test_script

if test x$exitcode = x0; then
  if test `cat $NAME.out | sed '1,/^.$/d' | wc -l` = 0; then
    a=a
  else
    exitcode=-1
  fi
fi

run_test_exit
