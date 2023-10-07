project(
  'lighttpd',
  'c',
  version: '1.4.73',
  license: 'BSD-3-Clause',
  default_options: ['c_std=c11'],
  meson_version: '>=0.47.0',
)

subdir('doc')
subdir('src')
subdir('tests')

# setup (in build directory):
# $ meson $src

# compile:
# $ ninja

# full build:
# $ meson configure -D build_extra_warnings=true -D buildtype=debugoptimized -D with_brotli=enabled -D with_dbi=enabled -D with_krb5=enabled -D with_ldap=enabled -D with_libunwind=enabled -D with_lua=true -D with_mysql=enabled -D with_openssl=true -D with_pcre2=true -D with_pgsql=enabled -D with_sasl=enabled -D with_webdav_locks=enabled -D with_webdav_props=enabled -D with_xattr=true -D with_zlib=enabled -D with_zstd=enabled

# optimized build:
# $ meson configure -D b_lto=true -D buildtype=debugoptimized

# monolithic build (contains all plugins):
# $ meson configure -D build_static=true -D buildtype=minsize

# using https://wrapdb.mesonbuild.com/
# $ mkdir -p subprojects
# $ for i in liblzma libxml2 lua lz4 pcre pcre2 sqlite3 xxhash zlib zstd; do meson wrap install $i; done
# $ for i in liblzma libxml2 lua lz4 pcre pcre2 sqlite3 xxhash zlib zstd; do meson wrap update $i; done
# $ meson configure --wrap-mode=forcefallback ...
