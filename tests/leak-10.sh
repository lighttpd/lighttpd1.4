#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host: leading dash
GET / HTTP/1.0
Host: -ab.de

Status: 400
EOF

run_test
