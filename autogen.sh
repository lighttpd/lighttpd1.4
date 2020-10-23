#!/bin/sh
# Run this to generate all the initial makefiles, etc.

errtrace() {
   echo 1>&2 \
     "build requires autoconf automake libtool m4 pcre pcre-devel pkg-config"
}

trap errtrace ERR

set -e

if [ ! -f configure.ac -o ! -f COPYING ]; then
	echo "Doesn't look like you're in the source directory" >&2
	exit 1
fi

# old autoreconf/aclocal versions fail hard if m4 doesn't exist
mkdir -p m4
autoreconf --force --install
echo "Now type './configure ...' and 'make' to compile."
