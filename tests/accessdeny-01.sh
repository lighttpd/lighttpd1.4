#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
deny request for index.html~
GET /index.html~ HTTP/1.0

Status: 403
EOF

run_test
