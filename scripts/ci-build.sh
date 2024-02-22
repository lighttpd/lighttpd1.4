#!/bin/sh
# build script used by jenkins

set -ex

build="${1:-autobuild}" # build system: coverity, autobuild, cmake, scons, ...
label="$2"              # label: {debian-{stable,testing},freebsd*}-{i386,amd64}
compiler="${3:-gcc}"    # might want to overwrite a compiler
# build=coverity:
# - create "cov-int" directory for upload (gets `tar`d)
# - access coverity binaries with export PATH="${COVERITY_PATH}"

# enable --with-wolfssl by default, but allow it to be disabled,
# e.g. on Alpine Linux where wolfssl package is not built including
# features required by lighttpd (--with-opensslextra --enable-lighty)
${WITH_WOLFSSL:=true}
[ -n "$NO_WOLFSSL" ] && unset WITH_WOLFSSL

${WITH_DBI:=true}
[ -n "$NO_DBI" ] && unset WITH_DBI

${WITH_GNUTLS:=true}
[ -n "$NO_GNUTLS" ] && unset WITH_GNUTLS

${WITH_KRB5:=true}
[ -n "$NO_KRB5" ] && unset WITH_KRB5

${WITH_MYSQL:=true}
[ -n "$NO_MYSQL" ] && unset WITH_MYSQL

${WITH_PAM:=true}
[ -n "$NO_PAM" ] && unset WITH_PAM

${WITH_PGSQL:=true}
[ -n "$NO_PGSQL" ] && unset WITH_PGSQL

${WITH_SASL:=true}
[ -n "$NO_SASL" ] && unset WITH_SASL

${WITH_UNWIND:=true}
[ -n "$NO_UNWIND" ] && unset WITH_UNWIND

sysname="$(uname -s)"

if [ "$sysname" = "Darwin" ]; then
    # keg-only package installs not linked into /usr/local
    #   brew install cyrus-sasl krb5 libpq
    export PKG_CONFIG_PATH="/usr/local/opt/cyrus-sasl/lib/pkgconfig:/usr/local/opt/krb5/lib/pkgconfig:/usr/local/opt/libpq/lib/pkgconfig"
fi

if [ "$sysname" = "FreeBSD" ]; then
    export CPPFLAGS=-I/usr/local/include
    export LDFLAGS=-L/usr/local/lib
fi

if [ "$sysname" = "NetBSD" ]; then
    export CPPFLAGS=-I/usr/pkg/include
    export LDFLAGS=-L/usr/pkg/lib
    export LD_LIBRARY_PATH=/usr/pkg/lib
fi

if [ "$sysname" = "OpenBSD" ]; then
    export CPPFLAGS=-I/usr/local/include
    export LDFLAGS=-L/usr/local/lib
    export PKG_CONFIG_LIBDIR=/usr/lib/pkgconfig:/usr/local/lib/pkgconfig:/usr/local/heimdal/lib/pkgconfig
fi

case "${build}" in
"autobuild"|"coverity")
	mkdir -p m4
	autoreconf --force --install
	./configure -C \
		--with-pic --enable-extra-warnings \
		${WITH_DBI:+--with-dbi} \
		${WITH_MYSQL:+--with-mysql} \
		${WITH_PGSQL:+--with-pgsql} \
		--with-ldap --with-pcre2 \
		--with-zlib --with-zstd --with-brotli --with-libdeflate \
		--with-lua \
		${WITH_UNWIND:+--with-libunwind} \
		${WITH_KRB5:+--with-krb5} \
		${WITH_PAM:+--with-pam} \
		${WITH_SASL:+--with-sasl} \
		--with-maxminddb \
		--with-nettle \
		${WITH_GNUTLS:+--with-gnutls} \
		--with-mbedtls \
		--with-nss \
		--with-openssl \
		${WITH_WOLFSSL:+--with-wolfssl} \
		--with-webdav-props
	case "${build}" in
	"autobuild")
		make -j 4
		make check
		;;
	"coverity")
		[ -z "${COVERITY_PATH}" ] || export PATH="${COVERITY_PATH}"
		cov-build --dir "cov-int" make
		;;
	esac
	;;
"cmake"|"cmake-asan")
	mkdir -p cmakebuild
	cd cmakebuild
	if [ "${build}" = "cmake-asan" ]; then
		asan_opts="-DBUILD_SANITIZE_ADDRESS=ON -DBUILD_SANITIZE_UNDEFINED=ON"
	else
		asan_opts=""
	fi
	cmake \
		-DBUILD_EXTRA_WARNINGS=ON \
		${asan_opts} \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DWITH_PCRE2=ON \
		-DWITH_ZLIB=ON \
		-DWITH_ZSTD=ON \
		-DWITH_BROTLI=ON \
		-DWITH_LIBDEFLATE=ON \
		-DWITH_LDAP=ON \
		${WITH_UNWIND:+-DWITH_LIBUNWIND=ON} \
		-DWITH_LUA=ON \
		-DWITH_MAXMINDDB=ON \
		${WITH_DBI:+-DWITH_DBI=ON} \
		${WITH_MYSQL:+-DWITH_MYSQL=ON} \
		${WITH_PGSQL:+-DWITH_PGSQL=ON} \
		${WITH_KRB5:+-DWITH_KRB5=ON} \
		${WITH_PAM:+-DWITH_PAM=ON} \
		${WITH_SASL:+-DWITH_SASL=ON} \
		${WITH_GNUTLS:+-DWITH_GNUTLS=ON} \
		-DWITH_MBEDTLS=ON \
		-DWITH_NETTLE=ON \
		-DWITH_NSS=ON \
		-DWITH_OPENSSL=ON \
		${WITH_WOLFSSL:+-DWITH_WOLFSSL=ON} \
		-DWITH_WEBDAV_PROPS=ON \
		..
	make -j 4 VERBOSE=1
	ctest -V
	;;
"meson")
	[ -d build ] || meson setup build
	meson configure --buildtype debugoptimized \
	  -Dbuild_extra_warnings=true \
	  -Dwith_brotli=enabled \
	  ${WITH_DBI:+-Dwith_dbi=enabled} \
	  ${WITH_GNUTLS:+-Dwith_gnutls=true} \
	  ${WITH_KRB5:+-Dwith_krb5=enabled} \
	  -Dwith_ldap=enabled \
	  -Dwith_libdeflate=enabled \
	  ${WITH_UNWIND:+-Dwith_libunwind=enabled} \
	  -Dwith_lua=true \
	  -Dwith_maxminddb=enabled \
	  -Dwith_mbedtls=true \
	  ${WITH_MYSQL:+-Dwith_mysql=enabled} \
	  -Dwith_nettle=true \
	  -Dwith_nss=true \
	  -Dwith_openssl=true \
	  ${WITH_PAM:+-Dwith_pam=enabled} \
	  -Dwith_pcre2=true \
	  ${WITH_PGSQL:+-Dwith_pgsql=enabled} \
	  ${WITH_SASL:+-Dwith_sasl=enabled} \
	  -Dwith_webdav_props=enabled \
	  ${WITH_WOLFSSL:+-Dwith_wolfssl=true} \
	  -Dwith_zlib=enabled \
	  -Dwith_zstd=enabled \
	  build
	cd build
	meson compile --verbose
	meson test --verbose
	;;
"scons")
	case "${label}" in
	debian*)
		# static linking needs some extra stuff on debian
		export LDFLAGS="-pthread"
		export LIBS="-ldl"
		;;
	esac
	scons -j 4 with_pcre2=yes with_zlib=yes with_openssl=yes with_brotli=yes -k check_static check_dynamic
	scons -j 4 with_pcre2=yes with_zlib=yes with_openssl=yes -k check_fullstatic
	;;
*)
	echo >&2 "Unknown build system: ${build}"
	exit 1
	;;
esac
