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
SERVER_NAME + unknown host, default
GET /phphost.php HTTP/1.0
Host: xxx.example.org
Conntection: close

Status: 200
Content: www.example.org
EOF

run_test
