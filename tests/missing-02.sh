#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
missing file + get-vars
GET /cjhdhfdjgfdg?jdfjh=dnfdh HTTP/1.0

Status: 404
EOF

run_test
