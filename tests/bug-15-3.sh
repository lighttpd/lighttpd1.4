#!/bin/sh

if id weigon > /dev/null; then
        echo -n
else
        printf "%-40s" "userdir"
        exit 77
fi


test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
userdir for ~weigon + redirect
GET /~weigon HTTP/1.0

Status: 301
Location: http://localhost:2048/~weigon/
EOF

run_test

