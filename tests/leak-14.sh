#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host: good name
GET / HTTP/1.0
Host: abc.de:1234

Status: 200
EOF

run_test
