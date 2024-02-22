AM_CFLAGS = $(FAM_CFLAGS) $(LIBUNWIND_CFLAGS)

noinst_PROGRAMS=\
	t/test_common \
	t/test_configfile \
	t/test_mod

sbin_PROGRAMS=lighttpd lighttpd-angel
LEMON=$(top_builddir)/src/lemon$(BUILD_EXEEXT)

TESTS=\
	t/test_common$(EXEEXT) \
	t/test_configfile$(EXEEXT) \
	t/test_mod$(EXEEXT)

lemon$(BUILD_EXEEXT): lemon.c
	$(AM_V_CC)$(CC_FOR_BUILD) $(CPPFLAGS_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) -o $@ $(srcdir)/lemon.c

lighttpd_angel_SOURCES=lighttpd-angel.c

.PHONY: versionstamp parsers

versionstamp:
	@test -f versionstamp.h || touch versionstamp.h; \
	REVISION=""; \
	if test -z "$$REVISION" -a -d "$(top_srcdir)/.git" -a -x "`which git`"; then \
		REVISION="$$(cd "$(top_srcdir)"; LANG= LC_ALL=C git describe --always 2>/dev/null || echo)"; \
	fi; \
	if test -n "$$REVISION"; then \
		echo "#define REPO_VERSION \"-devel-$$REVISION\"" > versionstamp.h.tmp; \
	else \
		echo "#define REPO_VERSION \"\"" > versionstamp.h.tmp; \
	fi; \
	if ! diff versionstamp.h.tmp versionstamp.h >/dev/null 2>/dev/null; then \
		mv versionstamp.h.tmp versionstamp.h; \
	else \
		rm versionstamp.h.tmp; \
	fi

configparser.h: configparser.c
configparser.c: $(srcdir)/configparser.y $(srcdir)/lempar.c lemon$(BUILD_EXEEXT)
	rm -f configparser.h
	chmod u+w $(srcdir)/configparser.c 2>/dev/null || true
	$(LEMON) -q -T$(srcdir)/lempar.c $(srcdir)/configparser.y

parsers: configparser.c

BUILT_SOURCES = parsers versionstamp
MAINTAINERCLEANFILES = configparser.c configparser.h
CLEANFILES = versionstamp.h versionstamp.h.tmp lemon$(BUILD_EXEEXT)

common_src=base64.c buffer.c burl.c log.c \
	http_header.c http_kv.c keyvalue.c chunk.c  \
	http_chunk.c fdevent.c fdevent_fdnode.c gw_backend.c \
	stat_cache.c http_etag.c array.c \
	algo_md5.c algo_sha1.c algo_splaytree.c \
	configfile-glue.c \
	http-header-glue.c \
	http_cgi.c \
	http_date.c \
	plugin.c \
	reqpool.c \
	request.c \
	sock_addr.c \
	rand.c \
	fdlog_maint.c \
	fdlog.c \
	sys-setjmp.c \
	ck.c

common_src += fdevent_win32.c fs_win32.c

src = server.c response.c connections.c h1.c \
	sock_addr_cache.c \
	network.c \
	network_write.c \
	fdevent_impl.c \
	http_range.c \
	data_config.c \
	configfile.c configparser.c

builtin_mods = \
  mod_rewrite.c \
  mod_redirect.c \
  mod_access.c \
  mod_alias.c \
  mod_indexfile.c \
  mod_staticfile.c \
  mod_setenv.c \
  mod_expire.c \
  mod_simple_vhost.c \
  mod_evhost.c \
  mod_fastcgi.c \
  mod_scgi.c

if !LIGHTTPD_STATIC
src += $(builtin_mods)
endif

lib_LTLIBRARIES =

if NO_RDYNAMIC
# if the linker doesn't allow referencing symbols of the binary
# we have to put everything into a shared-lib and link it into
# everything
common_ldflags = -avoid-version -no-undefined
lib_LTLIBRARIES += liblightcomp.la
liblightcomp_la_SOURCES=$(common_src)
liblightcomp_la_CFLAGS=$(AM_CFLAGS) $(LIBEV_CFLAGS)
liblightcomp_la_LDFLAGS = $(common_ldflags) --export-all-symbols
liblightcomp_la_LIBADD = $(PCRE_LIB) $(CRYPTO_LIB) $(FAM_LIBS) $(LIBEV_LIBS) $(ATTR_LIB) $(WS2_32_LIB)
common_libadd = liblightcomp.la
if !LIGHTTPD_STATIC
common_src += mod_auth_api.c mod_vhostdb_api.c
endif
else
src += $(common_src)
common_ldflags = -avoid-version
common_libadd =
endif
common_module_ldflags = -module -export-dynamic $(common_ldflags)

if !LIGHTTPD_STATIC

lib_LTLIBRARIES += mod_h2.la
mod_h2_la_SOURCES = h2.c ls-hpack/lshpack.c algo_xxhash.c
mod_h2_la_LDFLAGS = $(common_module_ldflags)
mod_h2_la_LIBADD = $(common_libadd) $(XXHASH_LIBS)

if BUILD_WITH_MAXMINDDB
lib_LTLIBRARIES += mod_maxminddb.la
mod_maxminddb_la_SOURCES = mod_maxminddb.c
mod_maxminddb_la_LDFLAGS = $(common_module_ldflags)
mod_maxminddb_la_LIBADD = $(common_libadd) $(MAXMINDDB_LIB)
endif

lib_LTLIBRARIES += mod_webdav.la
mod_webdav_la_SOURCES = mod_webdav.c
mod_webdav_la_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS) $(SQLITE_CFLAGS) 
mod_webdav_la_LDFLAGS = $(common_module_ldflags)
mod_webdav_la_LIBADD = $(common_libadd) $(XML_LIBS) $(SQLITE_LIBS) $(ELFTC_LIB)

if BUILD_WITH_LUA
lib_LTLIBRARIES += mod_magnet.la
mod_magnet_la_SOURCES = mod_magnet.c mod_magnet_cache.c algo_hmac.c
mod_magnet_la_CFLAGS = $(AM_CFLAGS) $(LUA_CFLAGS)
mod_magnet_la_LDFLAGS = $(common_module_ldflags)
mod_magnet_la_LIBADD = $(common_libadd) $(LUA_LIBS) $(CRYPTO_LIB) -lm
endif

lib_LTLIBRARIES += mod_vhostdb.la
mod_vhostdb_la_SOURCES = mod_vhostdb.c
if !NO_RDYNAMIC
mod_vhostdb_la_SOURCES += mod_vhostdb_api.c
endif
mod_vhostdb_la_LDFLAGS = $(common_module_ldflags)
mod_vhostdb_la_LIBADD = $(common_libadd)

if BUILD_WITH_LDAP
lib_LTLIBRARIES += mod_vhostdb_ldap.la
mod_vhostdb_ldap_la_SOURCES = mod_vhostdb_ldap.c
mod_vhostdb_ldap_la_LDFLAGS = $(common_module_ldflags)
mod_vhostdb_ldap_la_LIBADD = $(LDAP_LIB) $(LBER_LIB) $(common_libadd)
endif

if BUILD_WITH_MYSQL
lib_LTLIBRARIES += mod_vhostdb_mysql.la
mod_vhostdb_mysql_la_SOURCES = mod_vhostdb_mysql.c
mod_vhostdb_mysql_la_LDFLAGS = $(common_module_ldflags)
mod_vhostdb_mysql_la_LIBADD = $(MYSQL_LIBS) $(common_libadd)
mod_vhostdb_mysql_la_CPPFLAGS = $(MYSQL_CFLAGS)
endif

if BUILD_WITH_PGSQL
lib_LTLIBRARIES += mod_vhostdb_pgsql.la
mod_vhostdb_pgsql_la_SOURCES = mod_vhostdb_pgsql.c
mod_vhostdb_pgsql_la_LDFLAGS = $(common_module_ldflags)
mod_vhostdb_pgsql_la_LIBADD = $(PGSQL_LIBS) $(common_libadd)
mod_vhostdb_pgsql_la_CPPFLAGS = $(PGSQL_CFLAGS)
endif

if BUILD_WITH_DBI
lib_LTLIBRARIES += mod_vhostdb_dbi.la
mod_vhostdb_dbi_la_SOURCES = mod_vhostdb_dbi.c
mod_vhostdb_dbi_la_LDFLAGS = $(common_module_ldflags)
mod_vhostdb_dbi_la_LIBADD = $(DBI_LIBS) $(common_libadd)
mod_vhostdb_dbi_la_CPPFLAGS = $(DBI_CFLAGS)
endif

lib_LTLIBRARIES += mod_cgi.la
mod_cgi_la_SOURCES = mod_cgi.c
mod_cgi_la_LDFLAGS = $(common_module_ldflags)
mod_cgi_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_dirlisting.la
mod_dirlisting_la_SOURCES = mod_dirlisting.c
mod_dirlisting_la_LDFLAGS = $(common_module_ldflags)
mod_dirlisting_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_userdir.la
mod_userdir_la_SOURCES = mod_userdir.c
mod_userdir_la_LDFLAGS = $(common_module_ldflags)
mod_userdir_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_rrdtool.la
mod_rrdtool_la_SOURCES = mod_rrdtool.c
mod_rrdtool_la_LDFLAGS = $(common_module_ldflags)
mod_rrdtool_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_proxy.la
mod_proxy_la_SOURCES = mod_proxy.c
mod_proxy_la_LDFLAGS = $(common_module_ldflags)
mod_proxy_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_sockproxy.la
mod_sockproxy_la_SOURCES = mod_sockproxy.c
mod_sockproxy_la_LDFLAGS = $(common_module_ldflags)
mod_sockproxy_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_ssi.la
mod_ssi_la_SOURCES = mod_ssi.c
mod_ssi_la_LDFLAGS = $(common_module_ldflags)
mod_ssi_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_ajp13.la
mod_ajp13_la_SOURCES = mod_ajp13.c
mod_ajp13_la_LDFLAGS = $(common_module_ldflags)
mod_ajp13_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_extforward.la
mod_extforward_la_SOURCES = mod_extforward.c
mod_extforward_la_LDFLAGS = $(common_module_ldflags)
mod_extforward_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_deflate.la
mod_deflate_la_SOURCES = mod_deflate.c
mod_deflate_la_LDFLAGS = $(BROTLI_CFLAGS) $(common_module_ldflags)
mod_deflate_la_LIBADD = $(Z_LIB) $(ZSTD_LIB) $(BZ_LIB) $(BROTLI_LIBS) $(DEFLATE_LIBS) $(common_libadd)

lib_LTLIBRARIES += mod_auth.la
mod_auth_la_SOURCES = mod_auth.c
if !NO_RDYNAMIC
mod_auth_la_SOURCES += mod_auth_api.c
endif
mod_auth_la_LDFLAGS = $(common_module_ldflags)
mod_auth_la_LIBADD = $(CRYPTO_LIB) $(common_libadd)

lib_LTLIBRARIES += mod_authn_file.la
mod_authn_file_la_SOURCES = mod_authn_file.c
mod_authn_file_la_LDFLAGS = $(common_module_ldflags)
mod_authn_file_la_LIBADD = $(CRYPT_LIB) $(CRYPTO_LIB) $(common_libadd)

if BUILD_WITH_DBI
lib_LTLIBRARIES += mod_authn_dbi.la
mod_authn_dbi_la_SOURCES = mod_authn_dbi.c
mod_authn_dbi_la_LDFLAGS = $(common_module_ldflags)
mod_authn_dbi_la_LIBADD = $(CRYPT_LIB) $(DBI_LIBS) $(CRYPTO_LIB) $(common_libadd)
mod_authn_dbi_la_CPPFLAGS = $(DBI_CFLAGS)
endif

if BUILD_WITH_KRB5
lib_LTLIBRARIES += mod_authn_gssapi.la
mod_authn_gssapi_la_SOURCES = mod_authn_gssapi.c
mod_authn_gssapi_la_LDFLAGS = $(common_module_ldflags)
mod_authn_gssapi_la_LIBADD = $(KRB5_LIB) $(common_libadd)
endif

if BUILD_WITH_LDAP
lib_LTLIBRARIES += mod_authn_ldap.la
mod_authn_ldap_la_SOURCES = mod_authn_ldap.c
mod_authn_ldap_la_LDFLAGS = $(common_module_ldflags)
mod_authn_ldap_la_LIBADD = $(LDAP_LIB) $(LBER_LIB) $(common_libadd)
endif

if BUILD_WITH_PAM
lib_LTLIBRARIES += mod_authn_pam.la
mod_authn_pam_la_SOURCES = mod_authn_pam.c
mod_authn_pam_la_LDFLAGS = $(common_module_ldflags)
mod_authn_pam_la_LIBADD = $(PAM_LIB) $(common_libadd)
endif

if BUILD_WITH_SASL
lib_LTLIBRARIES += mod_authn_sasl.la
mod_authn_sasl_la_SOURCES = mod_authn_sasl.c
mod_authn_sasl_la_LDFLAGS = $(common_module_ldflags)
mod_authn_sasl_la_LIBADD = $(SASL_LIBS) $(common_libadd)
mod_authn_sasl_la_CPPFLAGS = $(SASL_CFLAGS)
endif

if BUILD_WITH_OPENSSL
lib_LTLIBRARIES += mod_openssl.la
mod_openssl_la_SOURCES = mod_openssl.c
mod_openssl_la_LDFLAGS = $(common_module_ldflags)
mod_openssl_la_LIBADD = $(OPENSSL_LIBS) $(common_libadd)
mod_openssl_la_CPPFLAGS = $(OPENSSL_CFLAGS)
endif

if BUILD_WITH_MBEDTLS
lib_LTLIBRARIES += mod_mbedtls.la
mod_mbedtls_la_SOURCES = mod_mbedtls.c
mod_mbedtls_la_LDFLAGS = $(common_module_ldflags)
mod_mbedtls_la_LIBADD = $(MTLS_LIBS) $(common_libadd)
endif

if BUILD_WITH_GNUTLS
lib_LTLIBRARIES += mod_gnutls.la
mod_gnutls_la_SOURCES = mod_gnutls.c
mod_gnutls_la_LDFLAGS = $(common_module_ldflags)
mod_gnutls_la_LIBADD = $(GNUTLS_LIBS) $(common_libadd)
mod_gnutls_la_CPPFLAGS = $(GNUTLS_CFLAGS)
endif

if BUILD_WITH_NSS
lib_LTLIBRARIES += mod_nss.la
mod_nss_la_SOURCES = mod_nss.c
mod_nss_la_LDFLAGS = $(common_module_ldflags)
mod_nss_la_LIBADD = $(NSS_LIBS) $(common_libadd)
mod_nss_la_CPPFLAGS = $(NSS_CFLAGS)
endif

if BUILD_WITH_WOLFSSL
lib_LTLIBRARIES += mod_wolfssl.la
mod_wolfssl_la_SOURCES = mod_wolfssl.c
mod_wolfssl_la_LDFLAGS = $(common_module_ldflags)
mod_wolfssl_la_LIBADD = $(WOLFSSL_LIBS) $(common_libadd)
mod_wolfssl_la_CPPFLAGS = $(WOLFSSL_CFLAGS)
endif

lib_LTLIBRARIES += mod_status.la
mod_status_la_SOURCES = mod_status.c
mod_status_la_LDFLAGS = $(common_module_ldflags)
mod_status_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_accesslog.la
mod_accesslog_la_SOURCES = mod_accesslog.c
mod_accesslog_la_LDFLAGS = $(common_module_ldflags)
mod_accesslog_la_LIBADD = $(common_libadd)

lib_LTLIBRARIES += mod_wstunnel.la
mod_wstunnel_la_SOURCES = mod_wstunnel.c
mod_wstunnel_la_LDFLAGS = $(common_module_ldflags)
mod_wstunnel_la_LIBADD = $(common_libadd) $(CRYPTO_LIB)

endif # !LIGHTTPD_STATIC


hdr = base64.h buffer.h burl.h network.h log.h http_kv.h keyvalue.h \
	response.h request.h reqpool.h chunk.h h1.h h2.h \
	first.h http_chunk.h \
	algo_hmac.h \
	algo_md.h algo_md5.h algo_sha1.h algo_splaytree.h algo_xxhash.h \
	fdlog.h \
	ck.h \
	http_cgi.h http_date.h \
	http_header.h http_range.h \
	fdevent.h gw_backend.h connections.h base.h base_decls.h stat_cache.h \
	plugin.h plugins.h plugin_config.h \
	http_etag.h array.h \
	fdevent_impl.h network_write.h configfile.h \
	sock_addr_cache.h \
	configparser.h \
	rand.h \
	sys-crypto.h sys-crypto-md.h sys-dirent.h \
	sys-endian.h sys-mmap.h sys-setjmp.h \
	sys-socket.h sys-stat.h sys-strings.h \
	sys-time.h sys-unistd.h sys-wait.h \
	sock_addr.h \
	mod_auth_api.h \
	mod_magnet_cache.h \
	mod_vhostdb_api.h \
	ls-hpack/lshpack.h \
	ls-hpack/lsxpack_header.h \
	ls-hpack/huff-tables.h \
	compat/fastcgi.h \
	compat/sys/queue.h


DEFS= @DEFS@ -DHAVE_VERSIONSTAMP_H -DLIBRARY_DIR="\"$(libdir)\"" -DSBIN_DIR="\"$(sbindir)\""


if LIGHTTPD_STATIC

## static lighttpd server (used in conjunction with -DLIGHTTPD_STATIC)
## (order is not important)
lighttpd_SOURCES = \
  $(src) \
  mod_access.c \
  mod_accesslog.c \
  mod_ajp13.c \
  mod_alias.c \
  mod_auth.c \
  mod_auth_api.c \
  mod_authn_file.c \
  mod_cgi.c \
  mod_deflate.c \
  mod_dirlisting.c \
  mod_evhost.c \
  mod_expire.c \
  mod_extforward.c \
  mod_fastcgi.c \
  mod_indexfile.c \
  mod_proxy.c \
  mod_redirect.c \
  mod_rewrite.c \
  mod_rrdtool.c \
  mod_scgi.c \
  mod_setenv.c \
  mod_simple_vhost.c \
  mod_sockproxy.c \
  mod_ssi.c \
  mod_staticfile.c \
  mod_status.c \
  mod_userdir.c \
  mod_vhostdb.c \
  mod_vhostdb_api.c \
  mod_webdav.c
lighttpd_CPPFLAGS = \
  -DLIGHTTPD_STATIC \
  $(XML_CFLAGS) $(SQLITE_CFLAGS) \
  $(FAM_CFLAGS) $(LIBEV_CFLAGS) $(LIBUNWIND_CFLAGS)
lighttpd_LDADD = \
  $(common_libadd) \
  $(CRYPT_LIB) $(CRYPTO_LIB) $(XXHASH_LIBS) \
  $(XML_LIBS) $(SQLITE_LIBS) $(ELFTC_LIB) \
  $(PCRE_LIB) $(Z_LIB) $(ZSTD_LIB) $(BZ_LIB) $(BROTLI_LIBS) $(DEFLATE_LIBS) \
  $(DL_LIB) $(SENDFILE_LIB) $(ATTR_LIB) \
  $(FAM_LIBS) $(LIBEV_LIBS) $(LIBUNWIND_LIBS)
lighttpd_LDFLAGS = -export-dynamic

lighttpd_SOURCES += h2.c ls-hpack/lshpack.c algo_xxhash.c
lighttpd_LDADD += $(XXHASH_LIBS)
if BUILD_WITH_MAXMINDDB
lighttpd_SOURCES += mod_maxminddb.c
lighttpd_LDADD += $(MAXMINDDB_LIB)
endif
if BUILD_WITH_LUA
lighttpd_SOURCES += mod_magnet.c mod_magnet_cache.c algo_hmac.c
lighttpd_CPPFLAGS += $(LUA_CFLAGS)
lighttpd_LDADD += $(LUA_LIBS) -lm
endif
if BUILD_WITH_KRB5
lighttpd_SOURCES += mod_authn_gssapi.c
lighttpd_LDADD += $(KRB5_LIB)
endif
if BUILD_WITH_LDAP
lighttpd_SOURCES += mod_authn_ldap.c mod_vhostdb_ldap.c
lighttpd_LDADD += $(LDAP_LIB) $(LBER_LIB)
endif
if BUILD_WITH_PAM
lighttpd_SOURCES += mod_authn_pam.c
lighttpd_LDADD += $(PAM_LIB)
endif
if BUILD_WITH_MYSQL
lighttpd_SOURCES += mod_vhostdb_mysql.c
lighttpd_CPPFLAGS += $(MYSQL_CFLAGS)
lighttpd_LDADD += $(MYSQL_LIBS)
endif
if BUILD_WITH_PGSQL
lighttpd_SOURCES += mod_vhostdb_pgsql.c
lighttpd_CPPFLAGS += $(PGSQL_CFLAGS)
lighttpd_LDADD += $(PGSQL_LIBS)
endif
if BUILD_WITH_DBI
lighttpd_SOURCES += mod_authn_dbi.c mod_vhostdb_dbi.c
lighttpd_CPPFLAGS += $(DBI_CFLAGS)
lighttpd_LDADD += $(DBI_LIBS)
endif
if BUILD_WITH_OPENSSL
lighttpd_SOURCES += mod_openssl.c
lighttpd_CPPFLAGS += $(OPENSSL_CFLAGS)
lighttpd_LDADD += $(OPENSSL_LIBS)
endif
if BUILD_WITH_MBEDTLS
lighttpd_SOURCES += mod_mbedtls.c
lighttpd_LDADD += $(MTLS_LIBS)
endif
if BUILD_WITH_GNUTLS
lighttpd_SOURCES += mod_gnutls.c
lighttpd_CPPFLAGS += $(GNUTLS_CFLAGS)
lighttpd_LDADD += $(GNUTLS_LIBS)
endif
if BUILD_WITH_NSS
lighttpd_SOURCES += mod_nss.c
lighttpd_CPPFLAGS += $(NSS_CFLAGS)
lighttpd_LDADD += $(NSS_LIBS)
endif
if BUILD_WITH_WOLFSSL
lighttpd_SOURCES += mod_wolfssl.c
lighttpd_CPPFLAGS += $(WOLFSSL_CFLAGS)
lighttpd_LDADD += $(WOLFSSL_LIBS)
endif

else

## default lighttpd server
lighttpd_SOURCES = $(src)
lighttpd_CPPFLAGS = $(FAM_CFLAGS) $(LIBEV_CFLAGS)
lighttpd_LDADD = $(common_libadd) $(PCRE_LIB) $(DL_LIB) $(SENDFILE_LIB) $(ATTR_LIB) $(CRYPTO_LIB) $(XXHASH_LIBS) $(FAM_LIBS) $(LIBEV_LIBS) $(LIBUNWIND_LIBS) $(WS2_32_LIB)
lighttpd_LDFLAGS = -export-dynamic

endif

t_test_common_SOURCES = t/test_common.c \
                        t/test_array.c \
                        t/test_base64.c \
                        t/test_buffer.c \
                        t/test_burl.c \
                        t/test_http_header.c \
                        t/test_http_kv.c \
                        t/test_http_range.c \
                        t/test_keyvalue.c \
                        t/test_request.c \
                        log.c \
                        fdlog.c \
                        sock_addr.c \
                        ck.c
t_test_common_LDADD   = $(LIBUNWIND_LIBS) $(PCRE_LIB) $(WS2_32_LIB)

t_test_configfile_SOURCES = t/test_configfile.c buffer.c array.c data_config.c http_header.c http_kv.c log.c fdlog.c sock_addr.c ck.c
t_test_configfile_LDADD = $(PCRE_LIB) $(LIBUNWIND_LIBS) $(WS2_32_LIB)

t_test_mod_SOURCES = $(common_src) t/test_mod.c \
                     t/test_mod_access.c \
                     t/test_mod_alias.c \
                     t/test_mod_evhost.c \
                     t/test_mod_expire.c \
                     t/test_mod_indexfile.c \
                     t/test_mod_simple_vhost.c \
                     t/test_mod_ssi.c \
                     t/test_mod_staticfile.c \
                     t/test_mod_userdir.c
t_test_mod_CFLAGS  = $(AM_CFLAGS) $(LIBEV_CFLAGS)
t_test_mod_LDADD   = $(LIBUNWIND_LIBS) $(PCRE_LIB) $(CRYPTO_LIB) $(DL_LIB) $(FAM_LIBS) $(LIBEV_LIBS) $(ATTR_LIB) $(WS2_32_LIB)

noinst_HEADERS   = $(hdr)
EXTRA_DIST = \
	t/README \
	mod_skeleton.c \
	configparser.y \
	lemon.c \
	lempar.c \
	SConscript \
	CMakeLists.txt config.h.cmake \
	meson.build
