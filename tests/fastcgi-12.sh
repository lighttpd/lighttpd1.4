#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test


cat > $TMPFILE <<EOF
FastCGI-Authorizer - 403
GET /index.html?fail HTTP/1.0
Host: www.example.org
Conntection: close

Status: 403
EOF

run_test
