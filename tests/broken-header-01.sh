#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Header appears twice
GET / HTTP/1.0
Foo: foo
Foo: foo

Status: 200
EOF

run_test
