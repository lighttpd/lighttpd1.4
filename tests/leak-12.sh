#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Host: broken name
GET / HTTP/1.0
Host: .

Status: 400
EOF

run_test
