#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

##
# using a higher protocol is always allowed as we can 
# downgrade the protocol on our own in the response
#


cat > $TMPFILE <<EOF
Protocoll == HTTP/1.3
GET / HTTP/1.3
Host: testbase.home.kneschke.de

Status: 505
EOF

run_test
