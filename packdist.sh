#!/bin/bash

SRCTEST=src/server.c
PACKAGE=lighttpd
BASEDOWNLOADURL="http://download.lighttpd.net/lighttpd/releases-1.4.x"
SNAPSHOTURL="http://download.lighttpd.net/lighttpd/snapshots-1.4.x"

if [[ "`id -un`" != "stbuehler" ]] && [[ -z "$AUTHOR" ]]; then
  export AUTHOR="gstrauss"
  export KEYID="AF16D0F0"
fi

AUTHOR="${AUTHOR:-stbuehler}"

# may take one argument for prereleases like
# ./packdist.sh [--nopack] rc1-r10

syntax() {
	echo "./packdist.sh [--nopack] [--help] [~rc1]" >&2
	exit 2
}

if [ ! -f ${SRCTEST} ]; then
	echo "Current directory is not the source directory"
	exit 1
fi

dopack=1

while [ $# -gt 0 ]; do
	case "$1" in
	"--nopack")
		dopack=0
		;;
	"--help")
		syntax
		;;
	"rc"*|"~rc"*)
		if [ -n "$append" ]; then
			echo "Only one append allowed" >&2
			syntax
		fi
		echo "Appending '$1'"
		append="$1"
		BASEDOWNLOADURL="${SNAPSHOTURL}"
		;;
	*)
		echo "Unknown option '$1'" >&2
		syntax
		;;
	esac
	shift
done

force() {
	"$@" || {
		echo "Command failed: $*"
		exit 1
	}
}

# summarize all changes since last release
genchanges() {
	(
		cat ../NEWS | sed "/^- ${version}/,/^-/p;d" | sed "/^- /d;/^$/d" | sed -e 's/^  \*/\*/'
	) > CHANGES
	return 0
}

# genereate links in old textile format "text":url
genlinks_changes() {
	local repourl ticketurl inf out
	repourl="http://redmine.lighttpd.net/projects/lighttpd/repository/revisions/"
	ticketurl="http://redmine.lighttpd.net/issues/"
	inf="$1"
	outf="$1".links
	(
		sed -e 's%\(http://[a-zA-Z0-9.:_/\-]\+\)%"\1":\1%g' |
		sed -e 's%#\([0-9]\+\)%"#\1":'"${ticketurl}"'\1%g' |
		sed -e 's%r\([0-9]\+\)%"r\1":'"${repourl}"'\1%g' |
		sed -e 's%\(CVE-[0-9\-]\+\)%"\1":http://cve.mitre.org/cgi-bin/cvename.cgi?name=\1%g' |
		cat
	) < "$inf" > "$outf"
}
genlinks_downloads() {
	local repourl ticketurl inf out
	repourl="http://redmine.lighttpd.net/projects/lighttpd/repository/revisions/"
	ticketurl="http://redmine.lighttpd.net/issues/"
	inf="$1"
	outf="$1".links
	(
		sed -e 's%\(http://[a-zA-Z0-9.:_/\-]\+\)%"\1":\1%g' |
		cat
	) < "$inf" > "$outf"
}

blog_post() {
	if [ -z "${append}" ]; then
		# release
		cat <<EOF
---
layout: post
title: ${version}
author: $AUTHOR
author_email: ${AUTHOR}@lighttpd.net
categories:
- download
tags:
- ${version}
- lighttpd
- releases
---
{% excerpt %}

TODO

h2. Important changes

TODO

h2. Downloads

EOF
		cat DOWNLOADS.links
		cat <<EOF

{% endexcerpt %}
h2. Changes from ${prevversion}

EOF
		cat CHANGES.links
	else
		# pre release
		cat <<EOF
---
layout: post
title: 'PRE-RELEASE: lighttpd ${version}${append}'
categories:
- lighttpd
tags:
- '1.4'
- ${version}
- lighttpd
- prerelease
---
{% excerpt %}
We would like to draw your attention to the latest pre-release of the stable 1.4 branch of lighttpd.

You can get the pre-release from these urls:
EOF
		cat DOWNLOADS.links
		cat <<EOF

Please test it as much as possible and provide us with feedback.
A lot of testing ensures a good release.

<!-- TODO: describe major changes -->

{% endexcerpt %}

h4. Changes from ${prevversion}

EOF
		cat CHANGES.links

		cat <<EOF

If you want to get the latest source for any branch, you can get it from our svn repository.
Documentation to do so can be obtained from this page: "DevelSubversion":http://redmine.lighttpd.net/projects/lighttpd/wiki/DevelSubversion
Bug reports or feature requests can be filed in our ticket system: "New Issue":http://redmine.lighttpd.net/projects/lighttpd/issues/new
Please make sure to check if there isn't a ticket already here: "Issues":http://redmine.lighttpd.net/projects/lighttpd/issues
Perhaps you also want to have a look at our "download site":http://download.lighttpd.net/lighttpd/

Thank you for flying light.
EOF
	fi
}

if [ ${dopack} = "1" ]; then
	force ./autogen.sh

	if [ -d distbuild ]; then
		# make distcheck may leave readonly files
		chmod u+w -R distbuild
		rm -rf distbuild
	fi

	force mkdir distbuild
	force cd distbuild

	force ../configure --prefix=/usr

	# force make
	# force make check

	force make -j 4 distcheck
	force fakeroot make dist
else
	force cd distbuild
fi

version=`./config.status -V | head -n 1 | cut -d' ' -f3`
name="${PACKAGE}-${version}"
if [ -n "${append}" ]; then
	cp "${name}.tar.gz" "${name}${append}.tar.gz"
	cp "${name}.tar.xz" "${name}${append}.tar.xz"
	name="${name}${append}"
fi

force sha256sum "${name}.tar."{gz,xz} > "${name}.sha256sum"

rm -f "${name}".tar.*.asc

force gpg ${KEYID:+-u "${KEYID}"} -a --output "${name}.tar.gz.asc" --detach-sig "${name}.tar.gz"
force gpg ${KEYID:+-u "${KEYID}"} -a --output "${name}.tar.xz.asc" --detach-sig "${name}.tar.xz"

(
	echo "* ${BASEDOWNLOADURL}/${name}.tar.gz"
	echo "** GPG signature: ${BASEDOWNLOADURL}/${name}.tar.gz.asc"
	echo "** SHA256: @$(sha256sum ${name}.tar.gz | cut -d' ' -f1)@"
	echo "* ${BASEDOWNLOADURL}/${name}.tar.xz"
	echo "** GPG signature: ${BASEDOWNLOADURL}/${name}.tar.xz.asc"
	echo "** SHA256: @$(sha256sum ${name}.tar.xz | cut -d' ' -f1)@"
	echo "* SHA256 checksums: ${BASEDOWNLOADURL}/${name}.sha256sum"
) > DOWNLOADS

(
	echo "* \"${name}.tar.gz\":${BASEDOWNLOADURL}/${name}.tar.gz (\"GPG signature\":${BASEDOWNLOADURL}/${name}.tar.gz.asc)"
	echo "** SHA256: @$(sha256sum ${name}.tar.gz | cut -d' ' -f1)@"
	echo "* \"${name}.tar.xz\":${BASEDOWNLOADURL}/${name}.tar.xz (\"GPG signature\":${BASEDOWNLOADURL}/${name}.tar.xz.asc)"
	echo "** SHA256: @$(sha256sum ${name}.tar.xz | cut -d' ' -f1)@"
	echo "* \"SHA256 checksums\":${BASEDOWNLOADURL}/${name}.sha256sum"
) > DOWNLOADS.links

force genchanges
force genlinks_changes CHANGES
#force genlinks_downloads DOWNLOADS

prevversion="${version%.*}.$((${version##*.} - 1))"

if [ -z "${append}" ]; then
	# only for Releases
	(
		cat <<EOF
h1. Release Info

* Version: ${version}
* Previous version: [[Release-${prevversion//./_}|${prevversion}]]
* Branch: 1.4
* Status: stable
* Release Purpose: bug fixes
* Release manager: $AUTHOR
* Released date: $(date +"%Y-%m-%d")

h1. Important changes from ${prevversion}

TODO

h1. Downloads

EOF
		cat DOWNLOADS
		cat <<EOF

h1. Changes from ${prevversion}

EOF
		cat CHANGES
		cat <<EOF

h1. External references

* http://www.lighttpd.net/$(date +"%Y/%-m/%-d")/${version}

EOF
	) > "Release-${version//./_}.page"

	cat "Release-${version//./_}.page"
fi

echo
echo -------
echo



blog_post > $(date +"%Y-%m-%d")-"${version}.textile"
cat $(date +"%Y-%m-%d")-"${version}.textile"

echo
echo -------
echo

echo wget "${BASEDOWNLOADURL}/${name}".'{tar.gz,tar.xz,sha256sum}; sha256sum -c '${name}'.sha256sum'
