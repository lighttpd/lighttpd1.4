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
FastCGI PHPinfo
GET /phpinfo.php HTTP/1.0
Host: www.example.org

Status: 200
EOF

run_test

