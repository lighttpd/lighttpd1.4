#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host not set
GET / HTTP/1.0
Host: grisu.home.kneschke.de

Status: 200
EOF

run_test
