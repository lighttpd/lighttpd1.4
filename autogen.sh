#!/bin/sh
# Run this to generate all the initial makefiles, etc.

LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}
LIBTOOLIZE_FLAGS="--copy --force"
ACLOCAL=${ACLOCAL:-aclocal}
AUTOHEADER=${AUTOHEADER:-autoheader}
AUTOMAKE=${AUTOMAKE:-automake}
AUTOMAKE_FLAGS="--add-missing --copy"
AUTOCONF=${AUTOCONF:-autoconf}

ARGV0=$0

set -e

if [ -z "$*" ]; then
	echo "$ARGV0:	Note: \`./configure' will be run without arguments."
	echo "		If you wish to pass any to it, please specify them on the"
	echo "		\`$0' command line."
	echo
fi

run() {
	echo "$ARGV0: running \`$@'"
	$@
}

run $LIBTOOLIZE $LIBTOOLIZE_FLAGS
run $ACLOCAL $ACLOCAL_FLAGS
run $AUTOHEADER
run $AUTOMAKE $AUTOMAKE_FLAGS
run $AUTOCONF
run ./configure --enable-maintainer-mode "$@"
echo "Now type \`make' to compile."
