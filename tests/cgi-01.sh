#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
CGI
GET /cgi.pl HTTP/1.0

Status: 200
EOF

run_test
