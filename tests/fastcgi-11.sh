#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test


cat > $TMPFILE <<EOF
FastCGI-Auth - ok
GET /index.html?ok HTTP/1.0
Host: www.example.org
Conntection: close

Status: 200
EOF

run_test
