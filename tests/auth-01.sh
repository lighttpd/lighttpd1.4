#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
auth required, no token sent
GET /server-status HTTP/1.0

Status: 401
EOF

run_test
