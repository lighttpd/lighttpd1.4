#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Content-Length, HTML
GET /12345.txt HTTP/1.0
Host: 123.example.org

Status: 200
Content-Length: 6
EOF

run_test
