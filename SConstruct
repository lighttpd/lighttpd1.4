from __future__ import print_function
import os
import re
import string
import sys
from copy import copy
from stat import *

try:
	string_types = basestring
except NameError:
	string_types = str

package = 'lighttpd'
version = '1.4.75'

underscorify_reg = re.compile('[^A-Z0-9]')
def underscorify(id):
	return underscorify_reg.sub('_', id.upper())

def fail(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)
	sys.exit(-1)

class Autoconf:
	class RestoreEnvLibs:
		def __init__(self, env):
			self.env = env
			self.active = False

		def __enter__(self):
			if self.active:
				raise Exception('entered twice')
			self.active = True
			if 'LIBS' in self.env:
				#print("Backup LIBS: " + repr(self.env['LIBS']))
				self.empty = False
				self.backup_libs = copy(self.env['LIBS'])
			else:
				#print("No LIBS to backup")
				self.empty = True

		def __exit__(self, type, value, traceback):
			if not self.active:
				raise Exception('exited twice')
			self.active = False
			if self.empty:
				if 'LIBS' in self.env:
					del self.env['LIBS']
			else:
				#print("Restoring LIBS, now: " + repr(self.env['LIBS']))
				self.env['LIBS'] = self.backup_libs
				#print("Restoring LIBS, to: " + repr(self.env['LIBS']))

	def __init__(self, env):
		self.conf = Configure(env, custom_tests = {
			'CheckGmtOffInStructTm': Autoconf.__checkGmtOffInStructTm,
			'CheckIPv6': Autoconf.__checkIPv6,
			'CheckWeakSymbols': Autoconf.__checkWeakSymbols,
		})

	def append(self, *args, **kw):
		return self.conf.env.Append(*args, **kw)

	def Finish(self):
		return self.conf.Finish()

	@property
	def env(self):
		return self.conf.env

	def restoreEnvLibs(self):
		return Autoconf.RestoreEnvLibs(self.conf.env)

	def CheckType(self, *args, **kw):
		return self.conf.CheckType(*args, **kw)

	def CheckLib(self, *args, **kw):
		return self.conf.CheckLib(*args, autoadd = 0, **kw)

	def CheckLibWithHeader(self, *args, **kw):
		return self.conf.CheckLibWithHeader(*args, autoadd = 0, **kw)

	def CheckGmtOffInStructTm(self):
		return self.conf.CheckGmtOffInStructTm()

	def CheckIPv6(self):
		return self.conf.CheckIPv6()

	def CheckWeakSymbols(self):
		return self.conf.CheckWeakSymbols()

	def CheckCHeader(self, hdr):
		return self.conf.CheckCHeader(hdr)

	def haveCHeader(self, hdr):
		if self.CheckCHeader(hdr):
			# if we have a list of headers define HAVE_ only for last one
			target = hdr
			if not isinstance(target, string_types):
				target = target[-1]
			self.conf.env.Append(CPPFLAGS = [ '-DHAVE_' + underscorify(target) ])
			return True
		return False

	def haveCHeaders(self, hdrs):
		for hdr in hdrs:
			self.haveCHeader(hdr)

	def CheckFunc(self, func, header = None, libs = []):
		with self.restoreEnvLibs():
			self.env.Append(LIBS = libs)
			return self.conf.CheckFunc(func, header = header)

	def CheckFuncInLib(self, func, lib):
		return self.CheckFunc(func, libs = [lib])

	def haveFuncInLib(self, func, lib):
		if self.CheckFuncInLib(func, lib):
			self.conf.env.Append(CPPFLAGS = [ '-DHAVE_' + underscorify(func) ])
			return True
		return False

	def haveFunc(self, func, header = None, libs = []):
		if self.CheckFunc(func, header = header, libs = libs):
			self.conf.env.Append(CPPFLAGS = [ '-DHAVE_' + underscorify(func) ])
			return True
		return False

	def haveFuncs(self, funcs):
		for func in funcs:
			self.haveFunc(func)

	def haveTypes(self, types):
		for type in types:
			if self.conf.CheckType(type, '#include <sys/types.h>'):
				self.conf.env.Append(CPPFLAGS = [ '-DHAVE_' + underscorify(type) ])

	def CheckParseConfig(self, *args, **kw):
		try:
			self.conf.env.ParseConfig(*args, **kw)
			return True
		except OSError:
			return False
		except Exception as e:
			print(e.message, file=sys.stderr)
			return False

	def CheckParseConfigForLib(self, lib, *args, **kw):
		with self.restoreEnvLibs():
			self.env['LIBS'] = []
			if not self.CheckParseConfig(*args, **kw):
				return False
			self.env.Append(**{lib: self.env['LIBS']})
			return True

	@staticmethod
	def __checkGmtOffInStructTm(context):
		source = """
#include <time.h>
int main() {
	struct tm a;
	a.tm_gmtoff = 0;
	return 0;
}
"""
		context.Message('Checking for tm_gmtoff in struct tm...')
		result = context.TryLink(source, '.c')
		context.Result(result)

		return result

	@staticmethod
	def __checkIPv6(context):
		source = """
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
	struct sockaddr_in6 s; struct in6_addr t=in6addr_any; int i=AF_INET6; s; t.s6_addr[0] = 0;
	return 0;
}
"""
		context.Message('Checking for IPv6 support...')
		result = context.TryLink(source, '.c')
		context.Result(result)

		return result

	@staticmethod
	def __checkWeakSymbols(context):
		source = """
__attribute__((weak)) void __dummy(void *x) { }
int main() {
	void *x;
	__dummy(x);
}
"""
		context.Message('Checking for weak symbol support...')
		result = context.TryLink(source, '.c')
		context.Result(result)

		return result

	def checkProgram(self, withname, progname):
		withname = 'with_' + withname
		binpath = None

		if self.env[withname] != 1:
			binpath = self.env[withname]
		else:
			prog = self.env.Detect(progname)
			if prog:
				binpath = self.env.WhereIs(prog)

		if binpath:
			mode = os.stat(binpath)[ST_MODE]
			if S_ISDIR(mode):
				fail("* error: path `%s' is a directory" % (binpath))
			if not S_ISREG(mode):
				fail("* error: path `%s' is not a file or not exists" % (binpath))

		if not binpath:
			fail("* error: can't find program `%s'" % (progname))

		return binpath

VariantDir('sconsbuild/build', 'src', duplicate = 0)
VariantDir('sconsbuild/tests', 'tests', duplicate = 0)

vars = Variables()
vars.AddVariables(
	('prefix', 'prefix', '/usr/local'),
	('bindir', 'binary directory', '${prefix}/bin'),
	('sbindir', 'binary directory', '${prefix}/sbin'),
	('libdir', 'library directory', '${prefix}/lib'),
	PathVariable('CC', 'path to the c-compiler', None),
	BoolVariable('build_dynamic', 'enable dynamic build', 'yes'),
	BoolVariable('build_static', 'enable static build', 'no'),
	BoolVariable('build_fullstatic', 'enable fullstatic build', 'no'),

	BoolVariable('with_bzip2', 'enable bzip2 compression', 'no'),
	BoolVariable('with_brotli', 'enable brotli compression', 'no'),
	PackageVariable('with_dbi', 'enable dbi support', 'no'),
	BoolVariable('with_fam', 'enable FAM/gamin support', 'no'),
	BoolVariable('with_libdeflate', 'enable libdeflate compression', 'no'),
	BoolVariable('with_maxminddb', 'enable MaxMind GeoIP2 support', 'no'),
	BoolVariable('with_krb5', 'enable krb5 auth support', 'no'),
	BoolVariable('with_ldap', 'enable ldap auth support', 'no'),
	# with_libev not supported
	# with_libunwind not supported
	BoolVariable('with_lua', 'enable lua support', 'no'),
	PackageVariable('with_mysql', 'enable mysql support', 'no'),
	BoolVariable('with_openssl', 'enable openssl support', 'no'),
	PackageVariable('with_gnutls', 'enable GnuTLS support', 'no'),
	PackageVariable('with_mbedtls', 'enable mbedTLS support', 'no'),
	PackageVariable('with_nss', 'enable NSS crypto support', 'no'),
	PackageVariable('with_wolfssl', 'enable wolfSSL support', 'no'),
	BoolVariable('with_nettle', 'enable Nettle support', 'no'),
	BoolVariable('with_pam', 'enable PAM auth support', 'no'),
	PackageVariable('with_pcre2', 'enable pcre2 support', 'yes'),
	PackageVariable('with_pcre', 'enable pcre support', 'no'),
	PackageVariable('with_pgsql', 'enable pgsql support', 'no'),
	PackageVariable('with_sasl', 'enable SASL support', 'no'),
	BoolVariable('with_sqlite3', 'enable sqlite3 support (required for webdav props)', 'no'),
	BoolVariable('with_uuid', 'enable uuid support (obsolete flag; ignored)', 'no'),
	# with_valgrind not supported
	# with_xattr not supported
	PackageVariable('with_xml', 'enable xml support (required for webdav props)', 'no'),
	BoolVariable('with_xxhash', 'build with system-provided xxhash', 'no'),
	BoolVariable('with_zlib', 'enable deflate/gzip compression', 'no'),
	BoolVariable('with_zstd', 'enable zstd compression', 'no'),

	BoolVariable('with_all', 'enable all with_* features', 'no'),
)

env = Environment(
	ENV = dict(os.environ),  # make sure we have a dict here so .Clone() works properly
	variables = vars,
	CPPPATH = Split('#sconsbuild/build')
)

env.Help(vars.GenerateHelpText(env))

if env.subst('${CC}') != '':
	env['CC'] = env.subst('${CC}')

env['package'] = package
env['version'] = version
if env['CC'] == 'gcc':
	## we need x-open 6 and bsd 4.3 features
	## (add -std=gnu99 for ancient gcc compiler versions)
	env.Append(CCFLAGS = Split('-pipe -Wall -O2 -g -W -pedantic -Wunused -Wshadow'))

env.Append(CPPFLAGS = [
	'-D_TIME_BITS=64',
	'-D_FILE_OFFSET_BITS=64',
	'-D_LARGEFILE_SOURCE',
	'-D_LARGE_FILES',
	'-D_DEFAULT_SOURCE',
	'-D_GNU_SOURCE',
])

if env['with_all']:
	for feature in vars.keys():
		# only enable 'with_*' flags
		if not feature.startswith('with_'): continue
		# don't overwrite manual arguments
		if feature in vars.args: continue
		# now activate
		env[feature] = True

# cache configure checks
if 1:
	autoconf = Autoconf(env)

	if 'CFLAGS' in os.environ:
		autoconf.env.Append(CCFLAGS = os.environ['CFLAGS'])
		print(">> Appending custom build flags : " + os.environ['CFLAGS'])

	if 'LDFLAGS' in os.environ:
		autoconf.env.Append(LINKFLAGS = os.environ['LDFLAGS'])
		print(">> Appending custom link flags : " + os.environ['LDFLAGS'])

	if 'LIBS' in os.environ:
		autoconf.env.Append(APPEND_LIBS = os.environ['LIBS'])
		print(">> Appending custom libraries : " + os.environ['LIBS'])
	else:
		autoconf.env.Append(APPEND_LIBS = '')

	autoconf.env.Append(
		LIBBROTLI = '',
		LIBBZ2 = '',
		LIBCRYPT = '',
		LIBCRYPTO = '',
		LIBDBI = '',
		LIBDEFLATE = '',
		LIBDL = '',
		LIBGNUTLS = '',
		LIBGSSAPI_KRB5 = '',
		LIBKRB5 = '',
		LIBLBER = '',
		LIBLDAP = '',
		LIBLUA = '',
		LIBMBEDTLS = '',
		LIBMBEDX509 = '',
		LIBMBEDCRYPTO = '',
		LIBMYSQL = '',
		LIBNSS = '',
		LIBPAM = '',
		LIBPCRE = '',
		LIBPGSQL = '',
		LIBSASL = '',
		LIBSQLITE3 = '',
		LIBSSL = '',
		LIBSSLCRYPTO = '',
		LIBWOLFSSL = '',
		LIBX509 = '',
		LIBXML2 = '',
		LIBXXHASH = '',
		LIBZ = '',
		LIBZSTD = '',
	)

	autoconf.haveCHeaders([
		'arpa/inet.h',
		'crypt.h',
		'dlfcn.h',
		'fcntl.h',
		'getopt.h',
		'inttypes.h',
		'linux/random.h',
		'malloc.h',
		'poll.h',
		'pwd.h',
		'stdint.h',
		'stdlib.h',
		'string.h',
		'strings.h',
		'sys/epoll.h',
		'sys/inotify.h',
		'sys/loadavg.h',
		'sys/poll.h',
		'sys/prctl.h',
		'sys/procctl.h',
		'sys/sendfile.h',
		'sys/time.h',
		'sys/wait.h',
		'syslog.h',
		'unistd.h',
		'winsock2.h',

		# "have" the last header if we include others before?
		['sys/types.h', 'sys/time.h', 'sys/resource.h'],
		['sys/types.h', 'netinet/in.h'],
		['sys/types.h', 'sys/event.h'],
		['sys/types.h', 'sys/mman.h'],
		['sys/types.h', 'sys/select.h'],
		['sys/types.h', 'sys/socket.h'],
		['sys/types.h', 'sys/uio.h'],
		['sys/types.h', 'sys/un.h'],
	])

	autoconf.haveFuncs([
		'arc4random_buf',
		'chroot',
		'clock_gettime',
		'copy_file_range',
		'epoll_ctl',
		'explicit_bzero',
		'explicit_memset',
		'fork',
		'getentropy',
		'getloadavg',
		'getrandom',
		'getrlimit',
		'getuid',
		'gmtime_r',
		'inet_aton',
		'inet_pton',
		'issetugid',
		'jrand48',
		'kqueue',
		'localtime_r',
		'lstat',
		'madvise',
		'malloc_trim',
		'mallopt',
		'mempcpy',
		'memset_s',
		'mkostemp',
		'mmap',
		'pipe2',
		'poll',
		'posix_spawn',
		'posix_spawn_file_actions_addclosefrom_np',
		'posix_spawn_file_actions_addfchdir_np',
		'pread',
		'preadv',
		'preadv2',
		'pwrite',
		'pwritev',
		'select',
		'sendfile',
		'sigaction',
		'signal',
		'splice',
		'srandom',
		'strerror_r',
		'timegm',
		'writev',
	])
	if re.compile("sunos|solaris").search(env['PLATFORM']):
		autoconf.haveCHeaders([
			'port.h',
			'priv.h',
			'sys/devpoll.h',
			'sys/filio.h',
		])
		autoconf.haveFunc('port_create')
		autoconf.haveFunc('sendfilev')
		autoconf.haveFunc('setpflags')

	autoconf.haveTypes(Split('pid_t size_t off_t'))

	# have crypt_r/crypt, and is -lcrypt needed?
	if autoconf.CheckLib('crypt'):
		autoconf.env.Append(
			LIBCRYPT = 'crypt',
		)
		with autoconf.restoreEnvLibs():
			autoconf.env['LIBS'] = ['crypt']
			autoconf.haveFuncs(['crypt', 'crypt_r'])
	else:
		autoconf.haveFuncs(['crypt', 'crypt_r'])

	if autoconf.CheckType('socklen_t', '#include <unistd.h>\n#include <sys/socket.h>\n#include <sys/types.h>'):
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_SOCKLEN_T' ])

	if autoconf.CheckType('struct sockaddr_storage', '#include <sys/socket.h>\n'):
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_STRUCT_SOCKADDR_STORAGE' ])

	if autoconf.CheckLibWithHeader('elftc', 'libelftc.h', 'c', 'elftc_copyfile(0, 1);'):
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_ELFTC_COPYFILE' ],
			LIBS = [ 'elftc' ],
		)

	if autoconf.CheckLibWithHeader('rt', 'time.h', 'c', 'clock_gettime(CLOCK_MONOTONIC, (struct timespec*)0);'):
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_CLOCK_GETTIME' ],
			LIBS = [ 'rt' ],
		)

	if autoconf.CheckIPv6():
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_IPV6' ])

	if autoconf.CheckWeakSymbols():
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_WEAK_SYMBOLS' ])

	if autoconf.CheckGmtOffInStructTm():
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_STRUCT_TM_GMTOFF' ])

	if autoconf.CheckLibWithHeader('dl', 'dlfcn.h', 'C'):
		autoconf.env.Append(LIBDL = 'dl')

	if env['with_bzip2']:
		if not autoconf.CheckLibWithHeader('bz2', 'bzlib.h', 'C'):
			fail("Couldn't find bz2")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_BZLIB_H', '-DHAVE_LIBBZ2' ],
			LIBBZ2 = 'bz2',
		)

	if env['with_brotli']:
		if not autoconf.CheckParseConfigForLib('LIBBROTLI', 'pkg-config --static --cflags --libs libbrotlienc'):
			fail("Couldn't find libbrotlienc")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_BROTLI_ENCODE_H', '-DHAVE_BROTLI' ],
		)

	if env['with_dbi']:
		if not autoconf.CheckLibWithHeader('dbi', 'dbi/dbi.h', 'C'):
			fail("Couldn't find dbi")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_DBI' ],
			LIBDBI = 'dbi',
		)

	if env['with_fam'] and not autoconf.CheckCHeader('sys/inotify.h'):
		if not autoconf.CheckLibWithHeader('fam', 'fam.h', 'C'):
			fail("Couldn't find fam")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_FAM_H', '-DHAVE_LIBFAM' ],
			LIBS = [ 'fam' ],
		)
		autoconf.haveFunc('FAMNoExists')

	if env['with_libdeflate']:
		if not autoconf.CheckLibWithHeader('deflate', 'libdeflate.h', 'C'):
			fail("Couldn't find libdeflate")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_LIBDEFLATE' ],
			LIBDEFLATE = 'libdeflate',
		)

	if env['with_maxminddb']:
		if not autoconf.CheckLibWithHeader('maxminddb', 'maxminddb.h', 'C'):
			fail("Couldn't find maxminddb")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_MAXMINDDB' ],
			LIBMAXMINDDB = 'maxminddb',
		)

	if env['with_krb5']:
		if not autoconf.CheckLibWithHeader('krb5', 'krb5.h', 'C'):
			fail("Couldn't find krb5")
		if not autoconf.CheckLibWithHeader('gssapi_krb5', 'gssapi/gssapi_krb5.h', 'C'):
			fail("Couldn't find gssapi_krb5")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_KRB5' ],
			LIBKRB5 = 'krb5',
			LIBGSSAPI_KRB5 = 'gssapi_krb5',
		)

	if env['with_ldap']:
		if not autoconf.CheckLibWithHeader('ldap', 'ldap.h', 'C'):
			fail("Couldn't find ldap")
		if not autoconf.CheckLibWithHeader('lber', 'lber.h', 'C'):
			fail("Couldn't find lber")
		autoconf.env.Append(
			CPPFLAGS = [
				'-DHAVE_LDAP_H', '-DHAVE_LIBLDAP',
				'-DHAVE_LBER_H', '-DHAVE_LIBLBER',
			],
			LIBLDAP = 'ldap',
			LIBLBER = 'lber',
		)

	if env['with_lua']:
		found_lua = False
		for lua_name in ['lua54','lua5.4','lua-5.4','lua53','lua5.3','lua-5.3','lua52','lua5.2','lua-5.2','lua51','lua5.1','lua-5.1','lua']:
			print("Searching for lua: " + lua_name + " >= 5.0")
			if autoconf.CheckParseConfigForLib('LIBLUA', "pkg-config '" + lua_name + " >= 5.0' --cflags --libs"):
				autoconf.env.Append(CPPFLAGS = [ '-DHAVE_LUA_H' ])
				found_lua = True
				break
		if not found_lua:
			fail("Couldn't find any lua implementation")

	if env['with_mysql']:
		mysql_config = autoconf.checkProgram('mysql', 'mysql_config')
		if not autoconf.CheckParseConfigForLib('LIBMYSQL', mysql_config + ' --cflags --libs'):
			fail("Couldn't find mysql")
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_MYSQL' ])

	if env['with_nss']:
		nss_config = autoconf.checkProgram('nss', 'nss-config')
		if not autoconf.CheckParseConfigForLib('LIBNSS', nss_config + ' --cflags --libs'):
			fail("Couldn't find NSS")
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_NSS3_NSS_H' ])

	if env['with_openssl']:
		if not autoconf.CheckLibWithHeader('ssl', 'openssl/ssl.h', 'C'):
			fail("Couldn't find openssl")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_OPENSSL_SSL_H', '-DHAVE_LIBSSL'],
			LIBSSL = 'ssl',
			LIBSSLCRYPTO = 'crypto',
			LIBCRYPTO = 'crypto',
		)

	if env['with_wolfssl']:
		if type(env['with_wolfssl']) is str:
			autoconf.env.AppendUnique(
				CPPPATH = [ env['with_wolfssl'] + '/include',
					    env['with_wolfssl'] + '/include/wolfssl' ],
				LIBPATH = [ env['with_wolfssl'] + '/lib' ],
			)
		if not autoconf.CheckLibWithHeader('wolfssl', 'wolfssl/ssl.h', 'C'):
			fail("Couldn't find wolfssl")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_WOLFSSL_SSL_H' ],
			LIBWOLFSSL= 'wolfssl',
			LIBCRYPTO = 'wolfssl',
		)

	if env['with_mbedtls']:
		if not autoconf.CheckLibWithHeader('mbedtls', 'mbedtls/ssl.h', 'C'):
			fail("Couldn't find mbedtls")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_LIBMBEDCRYPTO' ],
			LIBMBEDTLS = 'mbedtls',
			LIBMBEDX509 = 'mbedx509',
			LIBMBEDCRYPTO = 'mbedcrypto',
			LIBCRYPTO = 'mbedcrypto',
		)

	if env['with_nettle']:
		if not autoconf.CheckLibWithHeader('nettle', 'nettle/nettle-types.h', 'C'):
			fail("Couldn't find Nettle")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_NETTLE_NETTLE_TYPES_H' ],
			LIBCRYPTO = 'nettle',
		)

	if env['with_gnutls']:
		if not autoconf.CheckLibWithHeader('gnutls', 'gnutls/crypto.h', 'C'):
			fail("Couldn't find gnutls")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_GNUTLS_CRYPTO_H' ],
			LIBGNUTLS = 'gnutls',
		)
		if not autoconf.env.exists('LIBCRYPTO'):
			autoconf.env.Append(
				LIBCRYPTO = 'gnutls',
			)

	if env['with_pam']:
		if not autoconf.CheckLibWithHeader('pam', 'security/pam_appl.h', 'C'):
			fail("Couldn't find pam")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_PAM' ],
			LIBPAM = 'pam',
		)

	if env['with_pcre2'] and not env['with_pcre']:
		pcre2_config = autoconf.checkProgram('pcre2', 'pcre2-config')
		if not autoconf.CheckParseConfigForLib('LIBPCRE', pcre2_config + ' --cflags --libs8'):
			fail("Couldn't find pcre2")
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_PCRE2_H', '-DHAVE_PCRE' ])
	elif env['with_pcre']:
		pcre_config = autoconf.checkProgram('pcre', 'pcre-config')
		if not autoconf.CheckParseConfigForLib('LIBPCRE', pcre_config + ' --cflags --libs'):
			fail("Couldn't find pcre")
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_PCRE_H', '-DHAVE_PCRE' ])

	if env['with_pgsql']:
		if not autoconf.CheckParseConfigForLib('LIBPGSQL', 'pkg-config libpq --cflags --libs'):
			fail("Couldn't find libpq")
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_PGSQL' ])

	if env['with_sasl']:
		if not autoconf.CheckLibWithHeader('sasl2', 'sasl/sasl.h', 'C'):
			fail("Couldn't find libsasl2")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_SASL' ],
			LIBSASL = 'sasl2',
		)

	if env['with_sqlite3']:
		if not autoconf.CheckLibWithHeader('sqlite3', 'sqlite3.h', 'C'):
			fail("Couldn't find sqlite3")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_SQLITE3_H', '-DHAVE_LIBSQLITE3' ],
			LIBSQLITE3 = 'sqlite3',
		)

	if env['with_xml']:
		xml2_config = autoconf.checkProgram('xml', 'xml2-config')
		if not autoconf.CheckParseConfigForLib('LIBXML2', xml2_config + ' --cflags --libs'):
			fail("Couldn't find xml2")
		autoconf.env.Append(CPPFLAGS = [ '-DHAVE_LIBXML_H', '-DHAVE_LIBXML2' ])

	if env['with_xxhash']:
		if not autoconf.CheckLibWithHeader('xxhash', 'xxhash.h', 'C'):
			fail("Couldn't find xxhash")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_XXHASH_H' ],
			LIBXXHASH = 'xxhash',
		)

	if env['with_zlib']:
		if not autoconf.CheckLibWithHeader('z', 'zlib.h', 'C'):
			fail("Couldn't find zlib")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_ZLIB_H', '-DHAVE_LIBZ' ],
			LIBZ = 'z',
		)

	if env['with_zstd']:
		if not autoconf.CheckLibWithHeader('zstd', 'zstd.h', 'C'):
			fail("Couldn't find zstd")
		autoconf.env.Append(
			CPPFLAGS = [ '-DHAVE_ZSTD_H', '-DHAVE_ZSTD' ],
			LIBZSTD = 'zstd',
		)

	env = autoconf.Finish()

if re.compile("cygwin|mingw|midipix").search(env['PLATFORM']):
	env.Append(COMMON_LIB = 'bin')
elif re.compile("darwin|aix").search(env['PLATFORM']):
	env.Append(COMMON_LIB = 'lib')
else:
	env.Append(COMMON_LIB = False)

versions = version.split('.')
version_id = int(versions[0]) << 16 | int(versions[1]) << 8 | int(versions[2])
env.Append(CPPFLAGS = [
		'-DLIGHTTPD_VERSION_ID=' + hex(version_id),
		'-DPACKAGE_NAME=\\"' + package + '\\"',
		'-DPACKAGE_VERSION=\\"' + version + '\\"',
		'-DLIBRARY_DIR="\\"${libdir}\\""',
		] )

SConscript('src/SConscript', exports = 'env', variant_dir = 'sconsbuild/build', duplicate = 0)
SConscript('tests/SConscript', exports = 'env', variant_dir = 'sconsbuild/tests')
