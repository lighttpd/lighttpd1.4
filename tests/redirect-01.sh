#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Internal Redirect
GET /dummydir HTTP/1.0

Status: 301
Location: http://localhost:2048/dummydir/
EOF

run_test
