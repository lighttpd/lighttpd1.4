sbinddir = join_paths(get_option('prefix'), get_option('sbindir'))
moduledir = join_paths(get_option('prefix'), get_option('moduledir'))

include_base_paths = [
	'/usr/include',
	'/usr/local/include',
#	'/opt/local/include',
]

defs = [
	'-D_FILE_OFFSET_BITS=64',
	'-D_LARGEFILE_SOURCE',
	'-D_LARGE_FILES',
	'-D_GNU_SOURCE',
]

libws2_32 = []
if target_machine.system() == 'windows'
	libws2_32 = [ compiler.find_library('ws2_32') ]
	defs += [
		'-DNVALGRIND',
	]
endif


compiler = meson.get_compiler('c')
conf_data = configuration_data()

conf_data.set('HAVE_SYS_DEVPOLL_H', compiler.has_header('sys/devpoll.h'))
conf_data.set('HAVE_SYS_EPOLL_H', compiler.has_header('sys/epoll.h'))
conf_data.set('HAVE_SYS_EVENT_H', compiler.has_header('sys/event.h'))
conf_data.set('HAVE_SYS_LOADAVG_H', compiler.has_header('sys/loadavg.h'))
conf_data.set('HAVE_SYS_MMAN_H', compiler.has_header('sys/mman.h'))
conf_data.set('HAVE_SYS_POLL_H', compiler.has_header('sys/poll.h'))
conf_data.set('HAVE_SYS_PORT_H', compiler.has_header('sys/port.h'))
conf_data.set('HAVE_SYS_PRCTL_H', compiler.has_header('sys/prctl.h'))
conf_data.set('HAVE_SYS_RESOURCE_H', compiler.has_header('sys/resource.h'))
conf_data.set('HAVE_SYS_SENDFILE_H', compiler.has_header('sys/sendfile.h'))
conf_data.set('HAVE_SYS_SELECT_H', compiler.has_header('sys/select.h'))
conf_data.set('HAVE_SYS_TYPES_H', compiler.has_header('sys/types.h'))
conf_data.set('HAVE_SYS_UIO_H', compiler.has_header('sys/uio.h'))
conf_data.set('HAVE_SYS_UN_H', compiler.has_header('sys/un.h'))
conf_data.set('HAVE_SYS_WAIT_H', compiler.has_header('sys/wait.h'))
conf_data.set('HAVE_SYS_TIME_H', compiler.has_header('sys/time.h'))
conf_data.set('HAVE_UNISTD_H', compiler.has_header('unistd.h'))
conf_data.set('HAVE_PTHREAD_H', compiler.has_header('pthread.h'))
conf_data.set('HAVE_GETOPT_H', compiler.has_header('getopt.h'))
conf_data.set('HAVE_INTTYPES_H', compiler.has_header('inttypes.h'))
conf_data.set('HAVE_POLL_H', compiler.has_header('poll.h'))
conf_data.set('HAVE_PWD_H', compiler.has_header('pwd.h'))
conf_data.set('HAVE_STDDEF_H', compiler.has_header('stddef.h'))
conf_data.set('HAVE_STDINT_H', compiler.has_header('stdint.h'))
conf_data.set('HAVE_STRINGS_H', compiler.has_header('strings.h'))
conf_data.set('HAVE_SYSLOG_H', compiler.has_header('syslog.h'))

# check for fastcgi lib, for the tests only
conf_data.set('HAVE_FASTCGI_H', compiler.has_header('fastcgi.h'))
if not(conf_data.get('HAVE_FASTCGI_H'))
	conf_data.set('HAVE_FASTCGI_FASTCGI_H', compiler.has_header('fastcgi/fastcgi.h'))
endif

# will be needed for auth
conf_data.set('HAVE_CRYPT_H', compiler.has_header('crypt.h'))
if conf_data.get('HAVE_CRYPT_H')
	# check if we need libcrypt for crypt_r / crypt

	# crypt_r in default libs?
	if compiler.has_function('crypt_r', args: defs, prefix: '#include <crypt.h>')
		libcrypt = []
		conf_data.set('HAVE_CRYPT_R', 1)
	# crypt_r in -lcrypt ?
	elif compiler.has_function('crypt_r', args: defs + ['-lcrypt'], prefix: '#include <crypt.h>')
		libcrypt = [ compiler.find_library('crypt') ]
		conf_data.set('HAVE_CRYPT_R', 1)
	# crypt in default libs?
	elif compiler.has_function('crypt', args: defs, prefix: '#include <crypt.h>')
		libcrypt = []
		conf_data.set('HAVE_CRYPT', 1)
	# crypt in -lcrypt ?
	elif compiler.has_function('crypt', args: defs + ['-lcrypt'], prefix: '#include <crypt.h>')
		libcrypt = [ compiler.find_library('crypt') ]
		conf_data.set('HAVE_CRYPT', 1)
	endif
endif

conf_data.set('HAVE_SYS_INOTIFY_H', compiler.has_header('sys/inotify.h'))
if conf_data.get('HAVE_SYS_INOTIFY_H')
	conf_data.set('HAVE_INOTIFY_INIT', compiler.has_function('inotify_init', args: defs))
endif

conf_data.set('HAVE_SOCKLEN_T', compiler.has_type('socklen_t', args: defs, prefix: '#include <sys/socket.h>'))

conf_data.set('HAVE_SYS_RANDOM_H', compiler.has_header('sys/random.h'))
if conf_data.get('HAVE_SYS_RANDOM_H')
	conf_data.set('HAVE_GETENTROPY', compiler.has_function(
		'getentropy',
		args: defs,
		prefix: '#include <sys/random.h>'
	))
endif

conf_data.set('HAVE_LINUX_RANDOM_H', compiler.has_header('linux/random.h'))
if conf_data.get('HAVE_LINUX_RANDOM_H')
	conf_data.set('HAVE_GETRANDOM', compiler.has_function(
		'getrandom',
		args: defs,
		prefix: '#include <linux/random.h>'
	))
endif

conf_data.set('SIZEOF_LONG', compiler.sizeof('long', args: defs))
conf_data.set('SIZEOF_OFF_T', compiler.sizeof('off_t', args: defs))

conf_data.set('HAVE_ARC4RANDOM_BUF', compiler.has_function('arc4random_buf', args: defs))
conf_data.set('HAVE_CHROOT', compiler.has_function('chroot', args: defs))
conf_data.set('HAVE_EPOLL_CTL', compiler.has_function('epoll_ctl', args: defs))
conf_data.set('HAVE_FORK', compiler.has_function('fork', args: defs))
conf_data.set('HAVE_GETLOADAVG', compiler.has_function('getloadavg', args: defs))
conf_data.set('HAVE_GETRLIMIT', compiler.has_function('getrlimit', args: defs))
conf_data.set('HAVE_GETUID', compiler.has_function('getuid', args: defs))
conf_data.set('HAVE_GMTIME_R', compiler.has_function('gmtime_r', args: defs))
conf_data.set('HAVE_INET_NTOP', compiler.has_function('inet_ntop', args: defs))
conf_data.set('HAVE_JRAND48', compiler.has_function('jrand48', args: defs))
conf_data.set('HAVE_KQUEUE', compiler.has_function('kqueue', args: defs))
conf_data.set('HAVE_LOCALTIME_R', compiler.has_function('localtime_r', args: defs))
conf_data.set('HAVE_LSTAT', compiler.has_function('lstat', args: defs))
conf_data.set('HAVE_MADVISE', compiler.has_function('madvise', args: defs))
conf_data.set('HAVE_MEMCPY', compiler.has_function('memcpy', args: defs))
conf_data.set('HAVE_MEMSET', compiler.has_function('memset', args: defs))
conf_data.set('HAVE_MMAP', compiler.has_function('mmap', args: defs))
conf_data.set('HAVE_PATHCONF', compiler.has_function('pathconf', args: defs))
conf_data.set('HAVE_PIPE2', compiler.has_function('pipe2', args: defs))
conf_data.set('HAVE_POLL', compiler.has_function('poll', args: defs))
conf_data.set('HAVE_PORT_CREATE', compiler.has_function('port_create', args: defs))
conf_data.set('HAVE_PRCTL', compiler.has_function('prctl', args: defs))
conf_data.set('HAVE_PREAD', compiler.has_function('pread', args: defs))
conf_data.set('HAVE_POSIX_FADVISE', compiler.has_function('posix_fadvise', args: defs))
conf_data.set('HAVE_SELECT', compiler.has_function('select', args: defs))
conf_data.set('HAVE_SENDFILE', compiler.has_function('sendfile', args: defs))
conf_data.set('HAVE_SEND_FILE', compiler.has_function('send_file', args: defs))
conf_data.set('HAVE_SENDFILE64', compiler.has_function('sendfile64', args: defs))
conf_data.set('HAVE_SENDFILEV', compiler.has_function('sendfilev', args: defs))
conf_data.set('HAVE_SIGACTION', compiler.has_function('sigaction', args: defs))
conf_data.set('HAVE_SIGNAL', compiler.has_function('signal', args: defs))
conf_data.set('HAVE_SIGTIMEDWAIT', compiler.has_function('sigtimedwait', args: defs))
conf_data.set('HAVE_SRANDOM', compiler.has_function('srandom', args: defs))
conf_data.set('HAVE_STRPTIME', compiler.has_function('strptime', args: defs))
conf_data.set('HAVE_SYSLOG', compiler.has_function('syslog', args: defs))
conf_data.set('HAVE_WRITEV', compiler.has_function('writev', args: defs))
conf_data.set('HAVE_INET_ATON', compiler.has_function('inet_aton', args: defs))
conf_data.set('HAVE_ISSETUGID', compiler.has_function('issetugid', args: defs))
conf_data.set('HAVE_INET_PTON', compiler.has_function('inet_pton', args: defs))
conf_data.set('HAVE_MEMSET_S', compiler.has_function('memset_s', args: defs))
conf_data.set('HAVE_EXPLICIT_BZERO', compiler.has_function('explicit_bzero', args: defs))
conf_data.set('HAVE_EXPLICIT_MEMSET', compiler.has_function('explicit_memset', args: defs))

conf_data.set('HAVE_CLOCK_GETTIME', compiler.has_header_symbol('time.h', 'clock_gettime'))
clock_lib = []
if not(conf_data.get('HAVE_CLOCK_GETTIME'))
	if compiler.has_function('clock_gettime', args: defs + ['-lrt'], prefix: '#include <time.h>')
		conf_data.set('HAVE_CLOCK_GETTIME', true)
		clock_lib = [ compiler.find_library('rt') ]
	endif
endif

libelftc = []
if compiler.has_function('elftc_copyfile', args: defs + ['-lelftc'], prefix: '#include <libelftc.h>')
	conf_data.set('HAVE_ELFTC_COPYFILE', true)
	libelftc = [ compiler.find_library('elftc') ]
endif

conf_data.set('HAVE_IPV6', compiler.compiles('''
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>

	int main() {
		struct sockaddr_in6 s; struct in6_addr t=in6addr_any; int i=AF_INET6; s; t.s6_addr[0] = 0;
		return 0;
	}
''',
	name: 'IPv6 support',
	args: defs
))

conf_data.set('HAVE_WEAK_SYMBOLS', compiler.compiles('''
	__attribute__((weak)) void __dummy(void *x) { }
	int main() {
		void *x;
		__dummy(x);
	}
''',
	name: 'weak symbols',
	args: defs
))

conf_data.set('HAVE_STRUCT_TM_GMTOFF', compiler.compiles('''
	#include <time.h>
	int main(void) {
		struct tm t;
		t.tm_gmtoff = 0;
		return 0;
	}
''',
	name: 'struct tm gmt offset',
	args: defs
))

conf_data.set('LIGHTTPD_VERSION_ID', 10400)
conf_data.set_quoted('PACKAGE_NAME', meson.project_name())
conf_data.set_quoted('PACKAGE_VERSION', meson.project_version())
conf_data.set_quoted('LIBRARY_DIR', moduledir)

conf_data.set('LIGHTTPD_STATIC', get_option('build_static'))
libdl = []
if not(get_option('build_static'))
	if target_machine.system() != 'windows'
		libdl = [ compiler.find_library('dl') ]
		if not(compiler.has_function('dlopen', args: defs, dependencies: libdl, prefix: '#include <dlfcn.h>'))
			error('Couldn\'t find dlfcn.h or dlopen in lib dl')
		endif
	endif
endif

libbz2 = []
if get_option('with_bzip')
	libbz2 = [ compiler.find_library('bz2') ]
	if compiler.has_function('BZ2_bzCompress', args: defs, dependencies: libbz2, prefix: '#include <bzlib.h>')
		conf_data.set('HAVE_BZLIB_H', true)
		conf_data.set('HAVE_LIBBZ2', true)
	else
		error('Couldn\'t find bz2 header / library')
	endif
endif

if get_option('with_dbi')
	libdbi = dependency('dbi', required: false)
	if libdbi.found()
		libdbi = [ libdbi ]
	else
		libdbi = [ compiler.find_library('dbi') ]
		if not(compiler.has_function('dbi_conn_connect', args: defs, dependencies: libdbi, prefix: '#include <dbi/dbi.h>'))
			error('Couldn\'t find dbi/dbi.h or dbi_conn_connect in lib dbi')
		endif
	endif
	conf_data.set('HAVE_DBI', true)
endif

libfam = []
if get_option('with_fam')
	libfam = [ compiler.find_library('fam') ]
	if not(compiler.has_function('FAMOpen2', args: defs, dependencies: libfam, prefix: '#include <fam.h>'))
		error('Couldn\'t find fam.h or FAMOpen2 in lib fam')
	endif
	conf_data.set('HAVE_FAM_H', true)
endif

libgeoip = []
if get_option('with_geoip')
	libgeoip = dependency('geoip', required: false)
	if libgeoip.found()
		libgeoip = [ libgeoip ]
	else
		libgeoip = [ compiler.find_library('GeoIP') ]
		if not(compiler.has_function('GeoIP_country_name_by_addr', args: defs, dependencies: libgeoip))
			error('Couldn\'t find GeoIP_country_name_by_addr in lib GeoIP')
		endif
	endif
endif

libgdbm = []
if get_option('with_gdbm')
	libgdbm = [ compiler.find_library('gdbm') ]
	if not(compiler.has_function('gdbm_open', args: defs, dependencies: libgdbm, prefix: '#include <gdbm.h>'))
		error('Couldn\'t find gdbm.h or gdbm_open in lib gdbm')
	endif
	conf_data.set('HAVE_GDBM_H', true)
	conf_data.set('HAVE_GDBM', true)
endif

libkrb5 = []
libgssapi_krb5 = []
if get_option('with_krb5')
	libkrb5 = dependency('krb5', required: false)
	if libkrb5.found()
		libkrb5 = [ libkrb5 ]
	else
		libkrb5 = [ compiler.find_library('krb5') ]
		if not(compiler.has_function('krb5_init_context', args: defs, dependencies: libkrb5))
			error('Couldn\'t find krb5_init_context in lib krb5')
		endif
	endif

	libgssapi_krb5 = dependency('krb5-gssapi', required: false)
	if libgssapi_krb5.found()
		libgssapi_krb5 = [ libgssapi_krb5 ]
	else
		libgssapi_krb5 = [ compiler.find_library('gssapi_krb5') ]
	endif

	conf_data.set('HAVE_KRB5', true)
endif

libldap = []
liblber = []
if get_option('with_ldap')
	libldap = [ compiler.find_library('ldap') ]
	if not(compiler.has_function('ldap_sasl_bind_s',
		args: defs,
		dependencies: libldap,
		prefix: '''
			#include <ldap.h>
		'''
	))
		error('Couldn\'t find ldap.h or ldap_bind in lib libldap')
	endif
	conf_data.set('HAVE_LDAP_H', true)
	conf_data.set('HAVE_LIBLDAP', true)
	liblber = [ compiler.find_library('lber') ]
	if not(compiler.has_function('ber_printf', args: defs, dependencies: liblber, prefix: '#include <lber.h>'))
		error('Couldn\'t find lber.h or ber_printf in lib liblber')
	endif
	conf_data.set('HAVE_LBER_H', true)
	conf_data.set('HAVE_LIBLBER', true)
endif

libpam = []
if get_option('with_pam')
	libpam = [ compiler.find_library('pam') ]
	if not(compiler.has_function('pam_start',
		args: defs,
		dependencies: libpam,
		prefix: '''
			#include <security/pam_appl.h>
		'''
	))
		error('Couldn\'t find security/pam_appl.h or pam_start in lib libpam')
	endif
	conf_data.set('HAVE_PAM', true)
endif

libev = []
if get_option('with_libev')
	libev = dependency('ev', required: false)
	if libev.found()
		libev = [ libev ]
	elif compiler.has_header('ev.h') and compiler.has_function('ev_time', args: defs + ['-lev'])
		libev = [ compiler.find_library('ev') ]
	else
		error('Couldn\'t find libev header / library')
	endif
	conf_data.set('HAVE_LIBEV', true)
endif

libunwind = []
if get_option('with_libunwind')
	libunwind = [ dependency('libunwind') ]
endif

liblua = []
if get_option('with_lua')
	found_lua = false
	foreach l: ['lua5.3', 'lua-5.3', 'lua5.2', 'lua-5.2', 'lua5.1', 'lua-5.1', 'lua']
		if not(found_lua)
			liblua = dependency(l, required: false)
			found_lua = liblua.found()
		endif
	endforeach
	if not(found_lua)
		error('Couldn\'t find any lua library')
	endif
	liblua = [ liblua ]
	conf_data.set('HAVE_LUA_H', true)
endif

libmemcached = []
if get_option('with_memcached')
	# manual search:
	# header: libmemcached/memcached.h
	# function: memcached (-lmemcached)
	libmemcached = [ dependency('libmemcached') ]
	conf_data.set('USE_MEMCACHED', true)
endif

libmysqlclient = []
if get_option('with_mysql')
	# manual search: extend include path with 'mysql/'
	# header: mysql.h
	# function: mysql_real_connect (-lmariadb)
	libmysqlclient = [ dependency('mariadb') ]
	#-# function: mysql_real_connect (-lmysqlclient)
	#-libmysqlclient = [ dependency('mysqlclient') ]
	conf_data.set('HAVE_MYSQL', true)
endif

libssl = []
libcrypto = []
if get_option('with_openssl')
	# manual search:
	# header: openssl/ssl.h
	# function: SSL_new (-lssl)
	# function: BIO_f_base64 (-lcrypto)
	libssl = [ dependency('libssl') ]
	libcrypto = [ dependency('libcrypto') ]
	conf_data.set('HAVE_OPENSSL_SSL_H', true)
	conf_data.set('HAVE_LIBSSL', true)
endif
if get_option('with_wolfssl') != 'false'
	# manual search:
	# header: wolfssl/ssl.h
	# function: wolfSSL_Init (-lwolfssl)
	p = get_option('with_wolfssl')
	if p == 'true'
		p = '/usr/local'
	endif
	i = include_directories(p+'/include', p+'/include/wolfssl')
	libwolfssl_includes_dep = [ declare_dependency(include_directories: i) ]
	libcrypto = [ compiler.find_library('libwolfssl', dirs: [ p+'/lib', p+'/lib64' ]) ]
	libcrypto += libwolfssl_includes_dep
	conf_data.set('HAVE_WOLFSSL_SSL_H', true)
endif

libpcre = []
if get_option('with_pcre')
	# manual search:
	# header: pcre.h
	# function: pcre_exec (-lpcre)
	libpcre = [ dependency('libpcre') ]
	conf_data.set('HAVE_PCRE_H', true)
	conf_data.set('HAVE_LIBPCRE', true)
endif

libpq = []
if get_option('with_pgsql')
	# manual search:
	# header: libpq-fe.h
	# function: PQsetdbLogin (-lpq)
	libpq = [ dependency('libpq') ]
	conf_data.set('HAVE_PGSQL', true)
endif

if get_option('with_sasl')
	libsasl = dependency('sasl2', required: false)
	if libsasl.found()
		libsasl = [ libsasl2 ]
	else
		libsasl = [ compiler.find_library('sasl2') ]
		if not(compiler.has_function('sasl_server_init', args: defs, dependencies: libsasl, prefix: '#include <sasl/sasl.h>'))
			error('Couldn\'t find sasl/sasl.h or sasl_server_init in libsasl2')
		endif
	endif
	conf_data.set('HAVE_SASL', true)
endif

#if get_option('with_valgrind')
#endif

libuuid = []
if get_option('with_webdav_locks')
	libuuid = dependency('uuid', required: false)
	if libuuid.found()
		libuuid = [ libuuid ]
	elif compiler.has_function('uuid_generate', args: defs, prefix: '#include <uuid/uuid.h>')
		# uuid_generate in libc, everything is fine, no lib needed
		libuuid = []
	else
		libuuid = compiler.find_library('uuid')
		if not(compiler.has_function('uuid_generate',
			args: defs,
			dependencies: libuuid,
			prefix: '#include <uuid/uuid.h>'
		))
			error('Couldn\'t find uuid/uuid.h or uuid_generate in lib c and uuid')
		endif
	endif
	conf_data.set('HAVE_LIBUUID', true)
	conf_data.set('HAVE_UUID_UUID_H', true)
endif

libxml2 = []
libsqlite3 = []
if get_option('with_webdav_props')
	libxml2 = dependency('libxml-2.0', required: false)
	if libxml2.found()
		libxml2 = [ libxml2 ]
	else
		libxml2_includes = []
		libxml2_includes_dep = []
		libxml2_found_header = compiler.has_header('libxml/tree.h')
		foreach i: include_base_paths
			if not(libxml2_found_header)
				message('Searching in ' + join_paths(i, 'libxml2'))
				i = include_directories(join_paths(i, 'libxml2'))
				if compiler.has_header('libxml/tree.h', include_directories: i)
					libxml2_found_header = true
					libxml2_includes = [ i ]
					libxml2_includes_dep = [ declare_dependency(include_directories: i) ]
				endif
			endif
		endforeach
		if not(libxml2_found_header)
			error('Couldn\'t find libxml/tree.h')
		endif
		libxml2 = [ compiler.find_library('xml2') ]
		if not(compiler.has_function('xmlParseChunk',
			args: defs,
			dependencies: libxml2,
			include_directories: libxml2_includes,
			prefix: '''
				#include <libxml/tree.h>
			'''
		))
			error('Couldn\'t find xmlParseChunk in lib xml2')
		endif
		# has_function doesn't like "internal dependencies"
		libxml2 += libxml2_includes_dep
	endif
	conf_data.set('HAVE_LIBXML_H', true)

	libsqlite3 = dependency('sqlite31', required: false)
	if libsqlite3.found()
		libsqlite3 = [ libsqlite3 ]
	else
		libsqlite3 = [ compiler.find_library('sqlite3') ]
		if not(compiler.has_function('sqlite3_reset',
			args: defs,
			dependencies: libsqlite3,
			prefix: '''
				#include <sqlite3.h>
			'''
		))
			error('Couldn\'t find sqlite3.h or sqlite3_reset in lib sqlite3')
		endif
	endif
	conf_data.set('HAVE_SQLITE3_H', true)
endif

libattr = []
if get_option('with_xattr')
	libattr = [ compiler.find_library('attr') ]
	if not(compiler.has_function('attr_get',
		args: defs,
		dependencies: libattr,
		prefix: '''
			#include <sys/types.h>
			#include <attr/attributes.h>
		'''
	))
		error('Couldn\'t find attr/attributes.h or attr_get in lib attr')
	endif
	conf_data.set('HAVE_ATTR_ATTRIBUTES_H', true)
	conf_data.set('HAVE_XATTR', true)
endif

libz = []
if get_option('with_zlib')
	libz = dependency('zlib', required: false)
	if libz.found()
		libz = [ libz ]
	else
		# windows alternative names? 'zlib', 'zdll'
		libz = [ compiler.find_library('z') ]
		if not(compiler.has_function('deflate', args: defs, dependencies: libz, prefix: '#include <zlib.h>'))
			error('Couldn\'t find z header / library')
		endif
	endif
	conf_data.set('HAVE_ZLIB_H', true)
	conf_data.set('HAVE_LIBZ', true)
endif

configure_file(
	output : 'config.h',
	configuration : conf_data,
)

common_src = [
	'algo_sha1.c',
	'array.c',
	'base64.c',
	'buffer.c',
	'burl.c',
	'chunk.c',
	'configfile-glue.c',
	'connections-glue.c',
	'crc32.c',
	'data_array.c',
	'data_config.c',
	'data_integer.c',
	'data_string.c',
	'etag.c',
	'fdevent_freebsd_kqueue.c',
	'fdevent_libev.c',
	'fdevent_linux_sysepoll.c',
	'fdevent_poll.c',
	'fdevent_select.c',
	'fdevent_solaris_devpoll.c',
	'fdevent_solaris_port.c',
	'fdevent.c',
	'gw_backend.c',
	'http_auth.c',
	'http_chunk.c',
	'http_header.c',
	'http_kv.c',
	'http_vhostdb.c',
	'http-header-glue.c',
	'joblist.c',
	'keyvalue.c',
	'log.c',
	'md5.c',
	'plugin.c',
	'rand.c',
	'request.c',
	'safe_memclear.c',
	'sock_addr.c',
	'splaytree.c',
	'stat_cache.c',
	'stream.c',
	'vector.c',
]
if target_machine.system() == 'windows'
	common_src += [ 'xgetopt.c' ]
endif
main_src = [
	'configfile.c',
	'connections.c',
	'inet_ntop_cache.c',
	'network_write.c',
	'network.c',
	'response.c',
	'server.c',
]

lemon = executable('lemon',
	sources: 'lemon.c',
	native: true,
)
# generator doesn't handle additional "input dependencies" like lempar.c
# => use custom_target
configparser = custom_target('configparser',
	input:  ['configparser.y', 'lempar.c'],
	output: ['configparser.c', 'configparser.h'],
	command: [lemon, '-q', 'o=@OUTDIR@', '@INPUT0@', '@INPUT1@'],
)
ssi_exprparser = custom_target('mod_ssi_exprparser',
	input:  ['mod_ssi_exprparser.y', 'lempar.c'],
	output: ['mod_ssi_exprparser.c', 'mod_ssi_exprparser.h'],
	command: [lemon, '-q', 'o=@OUTDIR@', '@INPUT0@', '@INPUT1@'],
)

common_cflags = defs + [
	'-DHAVE_CONFIG_H',
]

if compiler.get_id() == 'gcc' or compiler.get_id() == 'clang'
	common_cflags += [
		'-Wall',
		'-g',
		'-Wshadow',
		'-W',
		'-pedantic',
	]
	if get_option('build_extra_warnings')
		common_cflags += get_option('warn_cflags').split()
	endif
endif

common_flags = [ declare_dependency(
	compile_args: common_cflags,
	# tests also use common_flags, and need this
	include_directories: include_directories('.'),
) ]

lighttpd_flags = []
lighttpd_angel_flags = []
if target_machine.system() == 'windows'
	lighttpd_flags += [ declare_dependency(
		compile_args: [
			'-DLI_DECLARE_EXPORTS',
		],
	) ]
	if compiler.get_id() == 'gcc'
		libmsvcr70 = [ compiler.find_library('msvcr70') ]
		lighttpd_flags += libmsvcr70 + [ declare_dependency(
			link_args: [
				'-Wl,-subsystem,console',
			],
		) ]
		lighttpd_angel_flags += libmsvcr70 + [ declare_dependency(
			link_args: [
				'-Wl,-subsystem,console',
			],
		) ]
	endif
endif

if compiler.get_id() == 'gcc' or target_machine.system() != 'darwin'
	lighttpd_flags += [ declare_dependency(
		link_args: [
			'-Wl,-export-dynamic',
		],
	) ]
endif

executable('lighttpd-angel',
	sources: 'lighttpd-angel.c',
	dependencies: common_flags + lighttpd_angel_flags,
	c_args: ['-DSBIN_DIR="' + sbinddir + '"'],
	install: true,
	install_dir: sbinddir,
)

executable('lighttpd', configparser,
	sources: common_src + main_src,
	# libssl needed?
	dependencies: [ common_flags, lighttpd_flags
		, libattr
		, libcrypto
		, libdl
		, libev
		, libfam
		, libpcre
		, libunwind
		, libws2_32
	],
	install: true,
	install_dir: sbinddir,
)

test('test_array', executable('test_array',
	sources: ['t/test_array.c', 'array.c', 'data_array.c', 'data_integer.c', 'data_string.c', 'buffer.c'],
	dependencies: common_flags + libunwind,
	build_by_default: false,
))

test('test_buffer', executable('test_buffer',
	sources: ['t/test_buffer.c', 'buffer.c'],
	dependencies: common_flags + libunwind,
	build_by_default: false,
))

test('test_burl', executable('test_burl',
	sources: ['t/test_burl.c', 'burl.c', 'buffer.c', 'base64.c'],
	dependencies: common_flags + libunwind,
	build_by_default: false,
))

test('test_base64', executable('test_base64',
	sources: ['t/test_base64.c', 'buffer.c', 'base64.c'],
	dependencies: common_flags + libunwind,
	build_by_default: false,
))

test('test_configfile', executable('test_configfile',
	sources: [
		't/test_configfile.c',
		'buffer.c',
		'array.c',
		'data_config.c',
		'data_integer.c',
		'data_string.c',
		'http_header.c',
		'http_kv.c',
		'vector.c',
		'log.c',
		'sock_addr.c',
	],
	dependencies: common_flags + libpcre + libunwind,
	build_by_default: false,
))

test('test_keyvalue', executable('test_keyvalue',
	sources: [
		't/test_keyvalue.c',
		'burl.c',
		'buffer.c',
		'base64.c',
		'array.c',
		'data_integer.c',
		'data_string.c',
		'log.c',
	],
	dependencies: common_flags + libpcre + libunwind,
	build_by_default: false,
))

test('test_mod_access', executable('test_mod_access',
	sources: [
		't/test_mod_access.c',
		'configfile-glue.c',
		'buffer.c',
		'array.c',
		'data_config.c',
		'data_integer.c',
		'data_string.c',
		'http_header.c',
		'http_kv.c',
		'vector.c',
		'log.c',
		'sock_addr.c',
	],
	dependencies: common_flags + libpcre + libunwind,
	build_by_default: false,
))

test('test_mod_evhost', executable('test_mod_evhost',
	sources: [
		't/test_mod_evhost.c',
		'configfile-glue.c',
		'buffer.c',
		'array.c',
		'data_config.c',
		'data_integer.c',
		'data_string.c',
		'http_header.c',
		'http_kv.c',
		'vector.c',
		'log.c',
		'sock_addr.c',
	],
	dependencies: common_flags + libpcre + libunwind,
	build_by_default: false,
))

test('test_mod_simple_vhost', executable('test_mod_simple_vhost',
	sources: [
		't/test_mod_simple_vhost.c',
		'configfile-glue.c',
		'buffer.c',
		'array.c',
		'data_config.c',
		'data_integer.c',
		'data_string.c',
		'http_header.c',
		'http_kv.c',
		'vector.c',
		'log.c',
		'sock_addr.c',
	],
	dependencies: common_flags + libpcre + libunwind,
	build_by_default: false,
))

test('test_request', executable('test_request',
	sources: [
		't/test_request.c',
		'request.c',
		'buffer.c',
		'array.c',
		'data_integer.c',
		'data_string.c',
		'http_header.c',
		'http_kv.c',
		'log.c',
		'sock_addr.c',
	],
	dependencies: common_flags + libunwind,
	build_by_default: false,
))

modules = [
	[ 'mod_access', [ 'mod_access.c' ] ],
	[ 'mod_accesslog', [ 'mod_accesslog.c' ] ],
	[ 'mod_alias', [ 'mod_alias.c' ] ],
	[ 'mod_auth', [ 'mod_auth.c' ], [ libcrypto ] ],
	[ 'mod_authn_file', [ 'mod_authn_file.c' ], [ libcrypt, libcrypto ] ],
	[ 'mod_compress', [ 'mod_compress.c' ], libbz2 + libz ],
	[ 'mod_deflate', [ 'mod_deflate.c' ], libbz2 + libz ],
	[ 'mod_dirlisting', [ 'mod_dirlisting.c' ], libpcre ],
	[ 'mod_evasive', [ 'mod_evasive.c' ] ],
	[ 'mod_evhost', [ 'mod_evhost.c' ] ],
	[ 'mod_expire', [ 'mod_expire.c' ] ],
	[ 'mod_extforward', [ 'mod_extforward.c' ] ],
	[ 'mod_fastcgi', [ 'mod_fastcgi.c' ], libws2_32 ],
	[ 'mod_flv_streaming', [ 'mod_flv_streaming.c' ] ],
	[ 'mod_indexfile', [ 'mod_indexfile.c' ] ],
	[ 'mod_proxy', [ 'mod_proxy.c' ], libws2_32 ],
	[ 'mod_redirect', [ 'mod_redirect.c' ], libpcre ],
	[ 'mod_rewrite', [ 'mod_rewrite.c' ], libpcre ],
	[ 'mod_rrdtool', [ 'mod_rrdtool.c' ] ],
	[ 'mod_scgi', [ 'mod_scgi.c' ], libws2_32 ],
	[ 'mod_secdownload', [ 'mod_secdownload.c' ], libcrypto ],
	[ 'mod_setenv', [ 'mod_setenv.c' ] ],
	[ 'mod_simple_vhost', [ 'mod_simple_vhost.c' ] ],
	[ 'mod_sockproxy', [ 'mod_sockproxy.c' ] ],
	[ 'mod_ssi', [ ssi_exprparser, 'mod_ssi_expr.c', 'mod_ssi.c' ], libws2_32 ],
	[ 'mod_staticfile', [ 'mod_staticfile.c' ] ],
	[ 'mod_status', [ 'mod_status.c' ] ],
	[ 'mod_uploadprogress', [ 'mod_uploadprogress.c' ] ],
	[ 'mod_userdir', [ 'mod_userdir.c' ] ],
	[ 'mod_usertrack', [ 'mod_usertrack.c' ] ],
	[ 'mod_vhostdb', [ 'mod_vhostdb.c' ] ],
	[ 'mod_webdav', [ 'mod_webdav.c' ], libsqlite3 + libuuid + libxml2 + libelftc ],
	[ 'mod_wstunnel', [ 'mod_wstunnel.c' ], libcrypto ],
]

if target_machine.system() != 'windows'
	modules += [
		[ 'mod_cgi', [ 'mod_cgi.c' ] ],
	]
endif

if get_option('with_pcre') and (get_option('with_memcached') or get_option('with_gdbm'))
	modules += [
		[ 'mod_trigger_b4_dl', [ 'mod_trigger_b4_dl.c' ], libpcre + libmemcached + libgdbm ],
	]
endif

if get_option('with_lua')
	modules += [
		[ 'mod_cml', [ 'mod_cml.c', 'mod_cml_lua.c', 'mod_cml_funcs.c' ], liblua + libmemcached ],
		[ 'mod_magnet', [ 'mod_magnet.c', 'mod_magnet_cache.c' ], liblua ],
	]
endif

if get_option('with_maxminddb')
	modules += [
		[ 'mod_maxminddb', [ 'mod_maxminddb.c' ], libmaxminddb ],
	]
endif

if get_option('with_geoip')
	modules += [
		[ 'mod_geoip', [ 'mod_geoip.c' ], libgeoip ],
	]
endif

if get_option('with_mysql')
	modules += [
		[ 'mod_authn_mysql', [ 'mod_authn_mysql.c' ], libcrypt + libmysqlclient ],
		[ 'mod_mysql_vhost', [ 'mod_mysql_vhost.c' ], libmysqlclient ],
		[ 'mod_vhostdb_mysql', [ 'mod_vhostdb_mysql.c' ], libmysqlclient ],
	]
endif

if get_option('with_pgsql')
	modules += [
		[ 'mod_vhostdb_pgsql', [ 'mod_vhostdb_pgsql.c' ], libpq ],
	]
endif

if get_option('with_dbi')
	modules += [
		[ 'mod_vhostdb_dbi', [ 'mod_vhostdb_dbi.c' ], libdbi ],
	]
endif

if get_option('with_krb5')
	modules += [
		[ 'mod_authn_gssapi', [ 'mod_authn_gssapi.c' ], libkrb5 + libgssapi_krb5 ],
	]
endif

if get_option('with_ldap')
	modules += [
		[ 'mod_authn_ldap', [ 'mod_authn_ldap.c' ], libldap + liblber ],
		[ 'mod_vhostdb_ldap', [ 'mod_vhostdb_ldap.c' ], libldap + liblber ],
	]
endif

if get_option('with_openssl')
	modules += [
		[ 'mod_openssl', [ 'mod_openssl.c' ], libssl + libcrypto ],
	]
endif

if get_option('with_wolfssl') != 'false'
	modules += [
		[ 'mod_openssl', [ 'mod_openssl.c' ], libcrypto ],
	]
endif

if get_option('with_pam')
	modules += [
		[ 'mod_authn_pam', [ 'mod_authn_pam.c' ], libpam ],
	]
endif

if get_option('with_sasl')
	modules += [
		[ 'mod_authn_sasl', [ 'mod_authn_sasl.c' ], libsasl ],
	]
endif

foreach mod: modules
	mod_name = mod.get(0)
	mod_sources = mod.get(1)
	mod_deps = mod.length() > 2 ? mod.get(2) : []
	shared_module(mod_name,
		sources: mod_sources,
		dependencies: [ common_flags, mod_deps ],
		name_prefix: '',
		install: true,
		install_dir: moduledir,
	)
endforeach
