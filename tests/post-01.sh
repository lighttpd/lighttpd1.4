#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
POST without Content-Length
POST / HTTP/1.0

Status: 411
EOF

run_test
