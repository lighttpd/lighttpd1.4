#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host not set
GET / HTTP/1.0
Host: ../123.org/

Status: 400
EOF

run_test
