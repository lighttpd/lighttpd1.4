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
PHP_SELF + PATH_INFO
GET /phpself.php/foo HTTP/1.0
Host: www.example.org
Conntection: close

Status: 200
Content: /phpself.php
EOF

run_test
