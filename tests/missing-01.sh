#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
missing file
GET /cjhdhfdjgfdg HTTP/1.0

Status: 404
EOF

run_test
