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
SERVER_NAME + \$HTTP, servername
GET /phphost.php HTTP/1.0
Host: zzz.example.org
Conntection: close

Status: 200
Content: zzz.example.org
EOF

run_test
