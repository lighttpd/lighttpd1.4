#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
auth required, wrong token
GET /server-status HTTP/1.0
Authorization: Basic amFuOmphb

Status: 401
EOF

run_test
