#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host set to weigon.dyndns.org
GET / HTTP/1.0
Host: weigon.dyndns.org

Status: 200
EOF

run_test
