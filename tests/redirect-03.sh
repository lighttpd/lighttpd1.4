#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
redirect module test
GET /dummydir?foo HTTP/1.0

Status: 301
Location: http://localhost:2048/dummydir/?foo
EOF

run_test
