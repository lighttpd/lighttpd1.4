#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
redirect module test
GET /redirect/ HTTP/1.0

Status: 301
Location: http://localhost:2048/
EOF

run_test
