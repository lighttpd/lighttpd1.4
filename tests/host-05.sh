#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
IPv6
GET / HTTP/1.0
Host: [::1]:80

Status: 200
EOF

run_test
