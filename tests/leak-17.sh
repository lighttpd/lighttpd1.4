#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host: broken IP
GET / HTTP/1.0
Host: 192.168.2:1234

Status: 400
EOF

run_test
