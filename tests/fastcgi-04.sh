#!/bin/sh

if pidof php > /dev/null; then
	echo -n
else
	printf "%-40s" "Redirect in PHP"
	exit 77
fi

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test


cat > $TMPFILE <<EOF
Redirect in PHP
GET /redirect.php HTTP/1.0
Host: www.example.org
Conntection: close

Status: 302
Location: http://www.example.org:2048/
EOF

run_test
