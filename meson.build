project('lighttpd', 'c', version: '1.4.68', license: 'BSD-3-Clause',
  default_options : ['c_std=c11']
)

subdir('src')
subdir('tests')

# setup (in build directory):
# $ meson $src

# compile:
# $ ninja

# full build:
# $ meson configure -D build_extra_warnings=true -D buildtype=debugoptimized -D with_bzip=true -D with_dbi=true -D with_fam=true -D with_krb5=true -D with_ldap=true -D with_libev=true -D with_libunwind=true -D with_lua=true -D with_mysql=true -D with_openssl=true -D with_pcre2=true -D with_pgsql=true -D with_sasl=true -D with_webdav_locks=true -D with_webdav_props=true -D with_xattr=true -D with_zlib=true

# optimized build:
# $ meson configure -D b_lto=true -D buildtype=debugoptimized

# monolithic build (contains all plugins):
# $ meson configure -D build_static=true -D buildtype=minsize
