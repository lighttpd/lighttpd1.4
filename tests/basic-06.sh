#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Unknown Method
ABC / HTTP/1.0

Status: 501
EOF

run_test
