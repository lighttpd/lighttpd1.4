#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Compression - deflate 
GET /index.html HTTP/1.0
Accept-Encoding: deflate

Status: 200
Content-Length: 1288
MUST: Vary Content-Encoding
EOF

run_test
