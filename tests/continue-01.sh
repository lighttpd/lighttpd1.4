#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
Continue Handling 
GET / HTTP/1.1
Connection: Close
Expect: 100-continue

Status: 417
EOF

run_test
