#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
HTTP/1.0, host in URI
GET http://www.yahoo.com/ HTTP/1.0

Status: 200
EOF

run_test
