#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
HTTP/1.1, with missing host
GET / HTTP/1.1

Status: 400
EOF

run_test
