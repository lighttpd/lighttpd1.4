#!/bin/sh
# build script used by jenkins

set -ex

build="${1:-autobuild}" # build system: coverity, autobuild, cmake, scons, ...
label="$2"              # label: {debian-{stable,testing},freebsd*}-{i386,amd64}
compiler="${3:-gcc}"    # might want to overwrite a compiler
# build=coverity:
# - create "cov-int" directory for upload (gets `tar`d)
# - access coverity binaries with export PATH="${COVERITY_PATH}"

case "${build}" in
"coverity")
	mkdir -p m4
	autoreconf --force --install
	./configure \
		--with-pic --enable-extra-warnings \
		--with-dbi --with-mysql --with-pgsql \
		--with-ldap --with-pcre2 \
		--with-zlib --with-zstd --with-brotli --with-bzip2 \
		--with-webdav-props --with-webdav-locks --with-gdbm \
		--with-memcached --with-lua --with-libev --with-libunwind \
		--with-krb5 \
		--with-nettle \
		--with-gnutls \
		--with-mbedtls \
		--with-nss \
		--with-openssl \
		--with-wolfssl
	make clean
	export PATH="${COVERITY_PATH}"
	cov-build --dir "cov-int" make
	;;
"autobuild")
	mkdir -p m4
	autoreconf --force --install
	./configure \
		--with-pic --enable-extra-warnings \
		--with-dbi --with-mysql --with-pgsql \
		--with-ldap --with-pcre2 \
		--with-zlib --with-zstd --with-brotli --with-bzip2 \
		--with-webdav-props --with-webdav-locks --with-gdbm \
		--with-memcached --with-lua --with-libev --with-libunwind \
		--with-krb5 --with-sasl \
		--with-nettle \
		--with-gnutls \
		--with-openssl
	make
	make check
	;;
"cmake")
	mkdir cmakebuild
	cd cmakebuild
	cmake \
		-DBUILD_EXTRA_WARNINGS=ON \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DWITH_PCRE2=ON \
		-DWITH_ZSTD=ON \
		-DWITH_BROTLI=ON \
		-DWITH_BZIP=ON \
		-DWITH_GDBM=ON \
		-DWITH_LDAP=ON \
		-DWITH_LIBEV=ON \
		-DWITH_LIBUNWIND=ON \
		-DWITH_LUA=ON \
		-DWITH_MEMCACHED=ON \
		-DWITH_DBI=ON \
		-DWITH_MYSQL=ON \
		-DWITH_PGSQL=ON \
		-DWITH_GNUTLS=ON \
		-DWITH_NETTLE=ON \
		-DWITH_OPENSSL=ON \
		-DWITH_WEBDAV_LOCKS=ON \
		-DWITH_WEBDAV_PROPS=ON \
		..
	make
	ctest -V
	;;
"scons")
	case "${label}" in
	debian*)
		# static linking needs some extra stuff on debian
		export LDFLAGS="-pthread"
		export LIBS="-ldl"
		;;
	esac
	# scons with_zlib=yes with_brotli=yes with_bzip2=yes with_openssl=yes -k check_fullstatic
	# scons with_zlib=yes with_brotli=yes with_bzip2=yes with_openssl=yes with_memcached=yes -k check_static check_dynamic
	scons with_pcre2=yes with_zlib=yes with_brotli=yes with_bzip2=yes with_openssl=yes -k check_fullstatic check_static check_dynamic
	;;
*)
	echo >&2 "Unknown build system: ${build}"
	exit 1
	;;
esac
