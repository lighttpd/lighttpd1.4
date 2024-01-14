#!/bin/sh

set -e

if test "x${srcdir}" = "x"; then
	srcdir=.
fi

if test "x${top_builddir}" = "x"; then
	top_builddir=..
fi
top_builddir=${top_builddir%/tests/..}

echo "Testing in build directory: '${top_builddir}' and cwd: '$(pwd)'"

tmpdir="${top_builddir}/tests/tmp/lighttpd"

# create test-framework
rm -rf "${tmpdir}"
mkdir -p "${tmpdir}/servers/www.example.org/pages/"           \
         "${tmpdir}/servers/www.example.org/pages/~test ä_/"  \
         "${tmpdir}/servers/www.example.org/pages/subdir/"    \
         "${tmpdir}/servers/123.example.org/pages/"           \
         "${tmpdir}/servers/a.example.org/pages/a/"           \
         "${tmpdir}/servers/b.example.org/pages/b/"           \
         "${tmpdir}/logs/"                                    \
         "${tmpdir}/cache/"                                   \
         "${tmpdir}/cache/compress/"

# copy everything into the right places
cp "${srcdir}/docroot/"*.html \
   "${srcdir}/docroot/"*.pl \
   "${srcdir}/docroot/"*.fcgi \
   "${srcdir}/docroot/"*.txt \
   "${tmpdir}/servers/www.example.org/pages/"

# copy configs to alternate build root, if alternate build root is used
# (tests will fail to run from an alternate build root on platforms
#  on which cp -n is not supported, such as NetBSD and OpenBSD)
# (does not detect if srcdir or top_builddir are inconsistent with trailing '/')
[ "${srcdir}" = "." ] || [ "${srcdir}" = "${top_builddir}/tests" ] || \
cp    "${srcdir}/"*.conf \
      "${srcdir}/lighttpd.user" \
      "${srcdir}/lighttpd.htpasswd" \
      "${top_builddir}/tests/"

# create some content
touch "${tmpdir}/servers/www.example.org/pages/image.jpg" \
      "${tmpdir}/servers/www.example.org/pages/image.JPG" \
      "${tmpdir}/servers/www.example.org/pages/Foo.txt" \
      "${tmpdir}/servers/www.example.org/pages/a" \
      "${tmpdir}/servers/www.example.org/pages/index.html~" \
      "${tmpdir}/servers/www.example.org/pages/subdir/any.txt" \
      "${tmpdir}/servers/www.example.org/pages/subdir/access.txt" \
      "${tmpdir}/servers/www.example.org/pages/subdir/modification.txt"
echo "12345" > "${tmpdir}/servers/123.example.org/pages/12345.txt"
echo "12345" > "${tmpdir}/servers/123.example.org/pages/12345.html"
echo "12345" > "${tmpdir}/servers/123.example.org/pages/dummyfile.bla"
echo "12345" > "${tmpdir}/servers/123.example.org/pages/range.disabled"
cat - <<HERE > "${tmpdir}/servers/123.example.org/pages/100.txt"
123456789
123456789
123456789
123456789
123456789
123456789
123456789
123456789
123456789
abcdefghi
HERE

printf "%-40s" "preparing infrastructure"
[ -z "$MAKELEVEL" ] && echo

exit 0
