#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
CGI + pathinfo
GET /cgi-pathinfo.pl/foo HTTP/1.0

Status: 200
Content: /foo
EOF

run_test
