#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

## 
# apache excepts broken request headers
#
#

cat > $TMPFILE <<EOF
broken requestline (4 fields)
GET http://www.yahoo.com/ HTTP/1.0 jsdh

Status: 400
EOF

run_test
