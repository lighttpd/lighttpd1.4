#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Compression - gzip 
GET /index.txt HTTP/1.0
Accept-Encoding: gzip, deflate
Host: www.example.org

Status: 200
MIGHT: Content-Encoding Vary
EOF

run_test
