#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Broken Request Header
ASd

Status: 400
Protocol: HTTP/0.9
EOF

run_test
