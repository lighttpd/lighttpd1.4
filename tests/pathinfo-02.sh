#!/bin/sh

if pidof php > /dev/null; then
        echo -n
else
        printf "%-40s" "PathInfo"
        exit 77
fi

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
PathInfo on a directory
GET /www/abc/def HTTP/1.0

Status: 404
EOF

run_test

