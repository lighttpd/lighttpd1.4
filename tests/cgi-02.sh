#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
CGI - SCRIPT_NAME (+pathinfo)
GET /cgi.pl/foo HTTP/1.0

Status: 200
Content: /cgi.pl
EOF

run_test
