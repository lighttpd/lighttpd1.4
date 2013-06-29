#!/bin/sh
# Run this to generate all the initial makefiles, etc.

if which glibtoolize >/dev/null 2>&1; then
  LIBTOOLIZE=${LIBTOOLIZE:-glibtoolize}
else
  LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}
fi
ACLOCAL=${ACLOCAL:-aclocal}
AUTOHEADER=${AUTOHEADER:-autoheader}
AUTOMAKE=${AUTOMAKE:-automake}
AUTOCONF=${AUTOCONF:-autoconf}

ARGV0=$0

set -e


run() {
  echo "$ARGV0: running \`$@'"
  "$@"
}

run $LIBTOOLIZE --copy --force
run $ACLOCAL $ACLOCAL_FLAGS
run $AUTOHEADER
run $AUTOMAKE --add-missing --copy --foreign --force-missing
run $AUTOCONF
echo "Now type './configure ...' and 'make' to compile."
