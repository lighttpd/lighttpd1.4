#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Broken Key-Value pairs
GET / HTTP/1.0
ABC a: jsajfsfdg

Status: 400
EOF

run_test
