#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

##
#
# apache sends 400 
#

cat > $TMPFILE <<EOF
Docroot protection
GET /../ HTTP/1.0

Status: 200
EOF

run_test
