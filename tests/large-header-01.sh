#!/bin/sh

test x$srcdir = x && srcdir=.

. $srcdir/testbase.sh

prepare_test

cat > $TMPFILE <<EOF
large request header
GET / HTTP/1.0
Hsgfsdjf: asdfhdf
hdhd: shdfhfdasd
hfhr: jfghsdfg
jfuuehdmn: sfdgjfdg
jvcbzufdg: sgfdfg
hrnvcnd: jfjdfg
jfusfdngmd: gfjgfdusdfg
nfj: jgfdjdfg
jfue: jfdfdg

Status: 200
EOF

run_test
