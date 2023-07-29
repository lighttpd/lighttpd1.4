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
"autobuild"|"coverity")
	mkdir -p m4
	autoreconf --force --install
	./configure -C \
		--with-pic --enable-extra-warnings \
		--with-dbi --with-mysql --with-pgsql \
		--with-ldap --with-pcre2 \
		--with-zlib --with-zstd --with-brotli --with-libdeflate \
		--with-lua --with-libunwind \
		--with-krb5 --with-pam --with-sasl \
		--with-maxminddb \
		--with-nettle \
		--with-gnutls \
		--with-mbedtls \
		--with-nss \
		--with-openssl \
		--with-wolfssl \
		--with-webdav-props --with-webdav-locks
	case "${build}" in
	"autobuild")
		make -j 2
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
		-DWITH_LIBUNWIND=ON \
		-DWITH_LUA=ON \
		-DWITH_MAXMINDDB=ON \
		-DWITH_DBI=ON \
		-DWITH_MYSQL=ON \
		-DWITH_PGSQL=ON \
		-DWITH_KRB5=ON \
		-DWITH_PAM=ON \
		-DWITH_SASL=ON \
		-DWITH_GNUTLS=ON \
		-DWITH_MBEDTLS=ON \
		-DWITH_NETTLE=ON \
		-DWITH_NSS=ON \
		-DWITH_OPENSSL=ON \
		-DWITH_WOLFSSL=ON \
		-DWITH_WEBDAV_LOCKS=ON \
		-DWITH_WEBDAV_PROPS=ON \
		..
	make -j 2
	ctest -V
	;;
"meson")
	[ -d build ] || meson setup build
	meson configure --buildtype debugoptimized \
	  -Dbuild_extra_warnings=true \
	  -Dwith_brotli=enabled \
	  -Dwith_dbi=enabled \
	  -Dwith_gnutls=true \
	  -Dwith_krb5=enabled \
	  -Dwith_ldap=enabled \
	  -Dwith_libdeflate=enabled \
	  -Dwith_libunwind=enabled \
	  -Dwith_lua=true \
	  -Dwith_maxminddb=enabled \
	  -Dwith_mbedtls=true \
	  -Dwith_mysql=enabled \
	  -Dwith_nettle=true \
	  -Dwith_nss=true \
	  -Dwith_openssl=true \
	  -Dwith_pam=enabled \
	  -Dwith_pcre2=true \
	  -Dwith_pgsql=enabled \
	  -Dwith_sasl=enabled \
	  -Dwith_webdav_locks=enabled \
	  -Dwith_webdav_props=enabled \
	  -Dwith_wolfssl=true \
	  -Dwith_zlib=enabled \
	  -Dwith_zstd=enabled \
	  build
	cd build
	meson compile
	meson test
	;;
"scons")
	case "${label}" in
	debian*)
		# static linking needs some extra stuff on debian
		export LDFLAGS="-pthread"
		export LIBS="-ldl"
		;;
	esac
	# scons -j 2 with_pcre2=yes with_zlib=yes with_brotli=yes with_openssl=yes -k check_fullstatic
	# scons -j 2 with_pcre2=yes with_zlib=yes with_brotli=yes with_openssl=yes -k check_static check_dynamic
	scons -j 2 with_pcre2=yes with_zlib=yes with_brotli=yes with_openssl=yes -k check_fullstatic check_static check_dynamic
	;;
*)
	echo >&2 "Unknown build system: ${build}"
	exit 1
	;;
esac
