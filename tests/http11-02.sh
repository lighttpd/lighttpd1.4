#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
valid HTTP/1.1 request + req: Date
GET / HTTP/1.1
Host: weigon.dyndns.org

Status: 200
MUST: Date
EOF

run_test
