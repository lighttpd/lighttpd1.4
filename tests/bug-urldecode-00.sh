#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Check that %00 is decoded correctly
GET /%00 HTTP/1.0
Foo: foo
Foo: foo

Status: 404
EOF

run_test
