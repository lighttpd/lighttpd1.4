#!/bin/sh

if pidof php > /dev/null; then
	echo -n
else
	printf "%-40s" "FastCGI PHPinfo"
	exit 77
fi

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
FastCGI + errorhandler
POST /indexfile/abc HTTP/1.0
Host: www.example.org
Content-Length: 0

Status: 404
Content: /indexfile/return-404.php
EOF

run_test

