#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
CGI + NPH
GET /nph-status.pl HTTP/1.0
Host: www.example.org

Status: 200
EOF

run_test

