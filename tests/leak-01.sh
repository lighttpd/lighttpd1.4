#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host: leading dot
GET / HTTP/1.0
Host: .jsdh.sfdg.sdfg.

Status: 400
EOF

run_test
