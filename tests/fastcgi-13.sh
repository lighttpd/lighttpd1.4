#!/bin/sh

if test -e /home/weigon/Documents/php-4.3.10/sapi/cgi/php > /dev/null; then
	echo -n
else
	printf "%-40s" "FastCGI PHPinfo"
	exit 77
fi

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test


cat > $TMPFILE <<EOF
FastCGI + local-spawning
GET /indexfile/index.php HTTP/1.0
Host: www.example.org
Conntection: close

Status: 200
EOF

run_test
