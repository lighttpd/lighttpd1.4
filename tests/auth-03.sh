#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
auth required, good token
GET /server-config HTTP/1.0
Authorization: Basic amFuOmphbg==

Status: 200
EOF

run_test
