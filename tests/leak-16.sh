#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host: broken name/ip
GET / HTTP/1.0
Host: a192.168.2.10:1234

Status: 400
EOF

run_test
