#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
HTTP/1.0 + absoluteURI
GET http://www.example.org/ HTTP/1.0

Status: 200
EOF

run_test
