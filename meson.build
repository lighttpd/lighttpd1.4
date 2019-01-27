project('lighttpd', 'c', version: '1.4.54', default_options : ['c_std=c11'])

subdir('src')
subdir('tests')

# setup (in build directory):
# $ meson $src

# compile:
# $ ninja

# full build:
# $ meson configure -D build_extra_warnings=true -D with_bzip=true -D with_dbi=true -D with_fam=true -D with_gdbm=true -D with_geoip=true -D with_krb5=true -D with_ldap=true -D with_libev=true -D with_libunwind=true -D with_lua=true -D with_memcached=true -D with_mysql=true -D with_openssl=true -D with_pcre=true -D with_pgsql=true -D with_sasl=true -D with_webdav_locks=true -D with_webdav_props=true -D with_xattr=true -D with_zlib=true

# optimized build:
# $ meson configure -D b_lto=true -D buildtype=debugoptimized

# monolitic build (contains all plugins):
# $ meson configure -D build_static=true
