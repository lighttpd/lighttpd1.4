#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Compression - gzip 
GET /index.html HTTP/1.0
Accept-Encoding: gzip

Status: 200
MUST: Vary Content-Encoding
EOF

run_test
