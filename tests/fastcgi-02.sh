#!/bin/sh

if pidof php > /dev/null; then
	echo -n
else
	printf "%-40s" "FastCGI - missing File"
	exit 77
fi

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
FastCGI - missing File
GET /phpinfajdhdo.php HTTP/1.1
Host: www.example.org

Status: 404
EOF

run_test
