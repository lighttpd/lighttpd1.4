#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host: good IP
GET / HTTP/1.0
Host: 192.168.2.10:1234

Status: 200
EOF

run_test
