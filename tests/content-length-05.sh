#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Content-Length < 0
POST /12345.txt HTTP/1.0
Host: 123.example.org
Content-Length: 

Status: 411
EOF

run_test
