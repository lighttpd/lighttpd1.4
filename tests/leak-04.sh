#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host: trailing dot
GET / HTTP/1.0
Host: .jsdh.sfdg.sdfg.:aasd

Status: 400
EOF

run_test
