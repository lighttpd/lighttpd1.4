dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.
dnl
dnl Indentation rules:
dnl - closing braces not at the beginning of a line must match opening
dnl   braces earlier on that line
dnl - closing braces at the beginning of a line:
dnl   - must not be followed by anything else apart from "," or comments
dnl   - must match opening braces from another line and indented the
dnl     same as that other line
dnl - if one argument was put on a new line, all following arguments
dnl   must be on their own line too
dnl - if an argument uses more than one line and is not a single
dnl   function call, the argument should be on different lines than the
dnl   wrapping braces
AC_PREREQ(2.60)
AC_INIT([lighttpd], [1.4.55], [contact@lighttpd.net])
AC_CONFIG_SRCDIR([src/server.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([1.13 -Wall -Wno-portability -Wno-override foreign dist-xz tar-ustar serial-tests silent-rules subdir-objects])

dnl @synopsis TRY_CFLAGS [compiler flags]
dnl @summary check whether compiler supports given flags and adds them to CFLAGS
AC_DEFUN([TRY_CFLAGS],
[dnl
  AC_MSG_CHECKING([if $CC supports $1])
  AC_LANG_PUSH([C])
  ac_try_cflags_saved_cflags="${CFLAGS}"
  CFLAGS="${CFLAGS} $1"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])],
    [
      AC_MSG_ERROR([no])
      CFLAGS="${ac_try_cflags_saved_cflags}"
    ]
  )
  AC_LANG_POP([C])
])

dnl @synopsis TRY_LDFLAGS [linker flags]
dnl @summary check whether linker supports given flags and adds them to LDFLAGS
AC_DEFUN([TRY_LDFLAGS],
[dnl
  AC_MSG_CHECKING([if $LD supports $1])
  AC_LANG_PUSH([C])
  ac_try_ldflags_saved_ldflags="${LDFLAGS}"
  LDFLAGS="${LDFLAGS} $1"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])],
    [
      AC_MSG_ERROR([no])
      LDFLAGS="${ac_try_ldflags_saved_cflags}"
    ]
  )
  AC_LANG_POP([C])
])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AX_PROG_CC_FOR_BUILD
AC_PROG_LD
AC_PROG_INSTALL
AC_PROG_CPP
AC_PROG_MAKE_SET

AC_USE_SYSTEM_EXTENSIONS
AM_PROG_AR

dnl AC_CANONICAL_HOST
case "$host_os" in
*darwin*|*cygwin*|*aix*|*mingw*|*midipix* ) NO_RDYNAMIC=yes ;;
* ) NO_RDYNAMIC=no ;;
esac
AM_CONDITIONAL([NO_RDYNAMIC], [test "$NO_RDYNAMIC" = yes])

AM_CONDITIONAL([LIGHTTPD_STATIC], [test "$LIGHTTPD_STATIC" = yes])

AC_EXEEXT

dnl libtool
AC_DISABLE_STATIC
AC_ENABLE_SHARED

AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

dnl for solaris
CPPFLAGS="${CPPFLAGS} -D_REENTRANT"

dnl Checks for header files.

dnl check for:
dnl   inttypes.h => HAVE_INTTYPES_H
dnl   stdint.h => HAVE_STDINT_H
dnl and maybe more (which shouldn't be relied on)
AC_HEADER_STDC
dnl checks for sys/wait.h => HAVE_SYS_WAIT_H
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([\
  getopt.h \
  poll.h \
  port.h \
  pwd.h \
  stdlib.h \
  strings.h \
  sys/devpoll.h \
  sys/epoll.h \
  sys/event.h \
  sys/filio.h \
  sys/loadavg.h \
  sys/mman.h \
  sys/poll.h \
  sys/prctl.h \
  sys/resource.h \
  sys/select.h \
  sys/sendfile.h \
  sys/time.h \
  sys/uio.h \
  sys/un.h \
  syslog.h \
  uuid/uuid.h \
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

AC_CHECK_MEMBER([struct tm.tm_gmtoff],
  [AC_DEFINE([HAVE_STRUCT_TM_GMTOFF], [1], [gmtoff in struct tm])],
  [],
  [#include <time.h>]
)
AC_CHECK_TYPES([socklen_t],
  [], dnl defines HAVE_SOCKLEN_T
  [],
  [
    #include <sys/types.h>
    #include <sys/socket.h>
  ]
)

dnl openssl on solaris needs -lsocket -lnsl
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([gethostbyname], [nsl socket])

dnl On Haiku accept() and friends are in libnetwork
AC_SEARCH_LIBS([accept], [network])

dnl clock_gettime() needs -lrt with glibc < 2.17, and possibly other platforms
AC_SEARCH_LIBS([clock_gettime], [rt])

dnl FreeBSD elftc_copyfile()
save_LIBS=$LIBS
LIBS=
AC_SEARCH_LIBS([elftc_copyfile], [elftc], [
  AC_CHECK_HEADERS([libelftc.h], [
    ELFTC_LIB=$LIBS
    AC_DEFINE([HAVE_LIBELFTC], [1], [libelftc])
    AC_DEFINE([HAVE_ELFTC_COPYFILE], [1], [elftc_copyfile])
  ])
])
LIBS=$save_LIBS
AC_SUBST([ELFTC_LIB])

dnl need dlopen/-ldl to load plugins (when not on windows)
save_LIBS=$LIBS
LIBS=
AC_SEARCH_LIBS([dlopen], [dl], [
  AC_CHECK_HEADERS([dlfcn.h], [
    DL_LIB=$LIBS
    AC_DEFINE([HAVE_LIBDL], [1], [libdl])
    AC_DEFINE([HAVE_DLFCN_H], [1])
  ])
])
LIBS=$save_LIBS
AC_SUBST([DL_LIB])

dnl prepare pkg-config usage below
PKG_PROG_PKG_CONFIG

dnl checking for libev
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for libev support])
AC_ARG_WITH([libev],
  [AC_HELP_STRING([--with-libev@<:@=PATH@:>@],
    [Include libev support for fdevent handlers in PATH/include and PATH/lib]
  )],
  [WITH_LIBEV=$withval],
  [WITH_LIBEV=no]
)
AC_MSG_RESULT([$WITH_LIBEV])

LIBEV_CFLAGS=
LIBEV_LIBS=

if test "$WITH_LIBEV" != no; then
  PKG_CHECK_MODULES([LIBEV], [libev], [], [
    dnl no pkg-config for libev, searching manually:

    if test "$WITH_LIBEV" != yes; then
      LIBEV_CFLAGS="-I$WITH_LIBEV/include"
      LIBEV_LIBS="-L$WITH_LIBEV/lib -lev"
    else
      AC_CHECK_HEADERS([ev.h],
        [AC_CHECK_LIB([ev], [ev_time],
          [
            LIBEV_CFLAGS=
            LIBEV_LIBS="-lev"
          ],
          [AC_MSG_ERROR([libev not found])]
        )],
        [AC_MSG_ERROR([libev header not found])]
      )
    fi
  ])

  AC_DEFINE([HAVE_LIBEV], [1], [libev support])
fi

AC_SUBST([LIBEV_CFLAGS])
AC_SUBST([LIBEV_LIBS])

dnl Checks for mysql
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for MySQL support])
AC_ARG_WITH([mysql],
  [AC_HELP_STRING([--with-mysql@<:@=PATH@:>@],
    [Include MySQL support. PATH is the path to 'mysql_config']
  )],
  [WITH_MYSQL=$withval],
  [WITH_MYSQL=no]
)
AC_MSG_RESULT([$WITH_MYSQL])

MYSQL_CFLAGS=
MYSQL_LIBS=

if test "$WITH_MYSQL" != no; then
  if test "$WITH_MYSQL" = yes; then
    PKG_CHECK_MODULES([MYSQL],[mariadb],[
      MYSQL_CONFIG=$PKG_CONFIG
    ],[
      PKG_CHECK_MODULES([MYSQL],[mysqlclient],[
        MYSQL_CONFIG=$PKG_CONFIG
      ],[
        AC_PATH_PROG([MYSQL_CONFIG], [mysql_config])
      ])
    ])
  else
    MYSQL_CONFIG=$WITH_MYSQL
  fi

  if test "$MYSQL_CONFIG" != "$PKG_CONFIG"; then
    if test -z "$MYSQL_CONFIG"; then
      AC_MSG_ERROR([mysql_config is not found])
    fi
    if test ! -x "$MYSQL_CONFIG"; then
      AC_MSG_ERROR([mysql_config not exists or not executable, use --with-mysql=path-to-mysql_config])
    fi

    if "$MYSQL_CONFIG" | grep -- '--include' > /dev/null ; then
      MYSQL_CFLAGS=`"$MYSQL_CONFIG" --include | sed s/\'//g`
    else
      MYSQL_CFLAGS=`"$MYSQL_CONFIG" --cflags | sed s/\'//g`
    fi
    MYSQL_LIBS=`"$MYSQL_CONFIG" --libs | sed s/\'//g`
  fi

  AC_MSG_CHECKING([for MySQL includes at])
  AC_MSG_RESULT([$MYSQL_CFLAGS])

  AC_MSG_CHECKING([for MySQL libraries at])
  AC_MSG_RESULT([$MYSQL_LIBS])

  AC_DEFINE([HAVE_MYSQL], [1], [mysql support])
fi
AM_CONDITIONAL([BUILD_WITH_MYSQL], [test "$WITH_MYSQL" != no])

AC_SUBST([MYSQL_LIBS])
AC_SUBST([MYSQL_CFLAGS])

dnl Checks for pgsql
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for PgSQL support])
AC_ARG_WITH([pgsql],
  [AC_HELP_STRING([--with-pgsql@<:@=PATH@:>@],
    [Include PgSQL support. PATH is the path to 'pg_config']
  )],
  [WITH_PGSQL=$withval],
  [WITH_PGSQL=no]
)
AC_MSG_RESULT([$WITH_PGSQL])

PGSQL_CFLAGS=
PGSQL_LIBS=

if test "$WITH_PGSQL" != no; then
  if test "$WITH_PGSQL" = yes; then
    PKG_CHECK_MODULES([PGSQL],[libpq],[
      PGSQL_CONFIG=$PKG_CONFIG
    ],[
      AC_PATH_PROG([PGSQL_CONFIG], [pg_config])
    ])
  else
    PGSQL_CONFIG=$WITH_PGSQL
  fi

  if test "$PGSQL_CONFIG" != "$PKG_CONFIG"; then
    if test -z "$PGSQL_CONFIG"; then
      AC_MSG_ERROR([pg_config is not found])
    fi
    if test ! -x "$PGSQL_CONFIG"; then
      AC_MSG_ERROR([pg_config not exists or not executable, use --with-pgsql=path-to-pg_config])
    fi

    PGSQL_CFLAGS="-I`"$PGSQL_CONFIG" --includedir`"
    PGSQL_LIBS="-L`"$PGSQL_CONFIG" --libdir` -lpq"
  fi

  AC_MSG_CHECKING([for PgSQL includes at])
  AC_MSG_RESULT([$PGSQL_CFLAGS])

  AC_MSG_CHECKING([for PgSQL libraries at])
  AC_MSG_RESULT([$PGSQL_LIBS])

  AC_DEFINE([HAVE_PGSQL], [1], [pgsql support])
fi
AM_CONDITIONAL([BUILD_WITH_PGSQL], [test "$WITH_PGSQL" != no])

AC_SUBST([PGSQL_LIBS])
AC_SUBST([PGSQL_CFLAGS])

dnl Checks for libdbi library
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for LibDBI support])
AC_ARG_WITH([dbi],
  [AC_HELP_STRING([--with-dbi@<:@=PATH@:>@],
    [Include DBI support in PATH/include/dbi.h and PATH/lib]
  )],
  [WITH_DBI=$withval],
  [WITH_DBI=no]
)
AC_MSG_RESULT([$WITH_DBI])

DBI_INCLUDE=
DBI_LIBS=

if test "$WITH_DBI" != no; then
  if test "$WITH_DBI" != yes; then
    DBI_CFLAGS="-I$WITH_DBI/include"
    DBI_LIBS="-L$WITH_DBI/lib -ldbi"
  else
    AC_CHECK_HEADERS([dbi/dbi.h],
      [AC_CHECK_LIB([dbi], [dbi_version],
        [
          DBI_CFLAGS=
          DBI_LIBS="-ldbi"
        ],
        [AC_MSG_ERROR([LibDBI not found])]
      )],
      [AC_MSG_ERROR([LibDBI header not found])]
    )
  fi

  AC_DEFINE([HAVE_DBI], [1], [LibDBI support])
fi
AM_CONDITIONAL([BUILD_WITH_DBI], [test "$WITH_DBI" != no])

AC_SUBST([DBI_LIBS])
AC_SUBST([DBI_CFLAGS])

dnl Checks for libsasl2 library
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for LibSASL support])
AC_ARG_WITH([sasl],
  [AC_HELP_STRING([--with-sasl@<:@=PATH@:>@],
    [Include SASL support in PATH/include/sasl/sasl.h and PATH/lib]
  )],
  [WITH_SASL=$withval],
  [WITH_SASL=no]
)
AC_MSG_RESULT([$WITH_SASL])

SASL_INCLUDE=
SASL_LIBS=

if test "$WITH_SASL" != no; then
  if test "$WITH_SASL" != yes; then
    SASL_CFLAGS="-I$WITH_SASL/include"
    SASL_LIBS="-L$WITH_SASL/lib -lsasl2"
  else
    AC_CHECK_HEADERS([sasl/sasl.h],
      [AC_CHECK_LIB([sasl2], [sasl_server_init],
        [
          SASL_CFLAGS=
          SASL_LIBS="-lsasl2"
        ],
        [AC_MSG_ERROR([libsasl2 not found])]
      )],
      [AC_MSG_ERROR([SASL header not found])]
    )
  fi

  AC_DEFINE([HAVE_SASL], [1], [LibSASL support])
fi
AM_CONDITIONAL([BUILD_WITH_SASL], [test "$WITH_SASL" != no])

AC_SUBST([SASL_LIBS])
AC_SUBST([SASL_CFLAGS])


dnl Check for LDAP
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for LDAP support])
AC_ARG_WITH([ldap],
  [AC_HELP_STRING([--with-ldap], [enable LDAP support])],
  [WITH_LDAP=$withval],
  [WITH_LDAP=no]
)
AC_MSG_RESULT([$WITH_LDAP])

if test "$WITH_LDAP" != no; then
  AC_CHECK_LIB([ldap], [ldap_sasl_bind_s],
    [AC_CHECK_HEADERS([ldap.h],
      [
        LDAP_LIB=-lldap
        AC_DEFINE([HAVE_LIBLDAP], [1], [libldap])
        AC_DEFINE([HAVE_LDAP_H], [1])
      ],
      [AC_MSG_ERROR([ldap headers not found, install them or build without --with-ldap])]
    )],
    [AC_MSG_ERROR([ldap library not found, install it or build without --with-ldap])]
  )
  AC_SUBST([LDAP_LIB])
  AC_CHECK_LIB([lber], [ber_printf],
    [AC_CHECK_HEADERS([lber.h],
      [
        LBER_LIB=-llber
        AC_DEFINE([HAVE_LIBLBER], [1], [liblber])
        AC_DEFINE([HAVE_LBER_H], [1])
      ],
      [AC_MSG_ERROR([lber headers not found, install them or build without --with-ldap])]
    )],
    [AC_MSG_ERROR([lber library not found, install it or build without --with-ldap])]
  )
  AC_SUBST([LBER_LIB])
fi
AM_CONDITIONAL([BUILD_WITH_LDAP], [test "$WITH_LDAP" != no])

dnl Check for PAM
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING(for PAM support)
AC_ARG_WITH([pam],
  [AC_HELP_STRING([--with-pam],[enable PAM support])],
  [WITH_PAM=$withval],
  [WITH_PAM=no]
)
AC_MSG_RESULT([$withval])

if test "$WITH_PAM" != "no"; then
  AC_CHECK_LIB([pam], [pam_start],
    [AC_CHECK_HEADERS([security/pam_appl.h],[
      PAM_LIB=-lpam
      AC_DEFINE([HAVE_PAM], [1], [libpam])
      AC_DEFINE([HAVE_SECURITY_PAM_APPL_H], [1])
      ],
      [AC_MSG_ERROR([pam headers not found, install them or build without --with-pam])]
    )],
    [AC_MSG_ERROR([pam library not found, install it or build without --with-pam])]
  )
  AC_SUBST(PAM_LIB)
fi
AM_CONDITIONAL([BUILD_WITH_PAM], [test "$WITH_PAM" != no])

dnl Check for xattr
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for extended attributes support])
AC_ARG_WITH([attr],
  [AC_HELP_STRING([--with-attr], [enable extended attribute support])],
  [WITH_ATTR=$withval],
  [WITH_ATTR=no]
)
AC_MSG_RESULT([$WITH_ATTR])

if test "$WITH_ATTR" != no; then
  have_xattr=no
  # libattr (linux only?)
  AC_CHECK_LIB([attr], [attr_get], [
    AC_CHECK_HEADERS([attr/attributes.h], [
      ATTR_LIB=-lattr
      AC_DEFINE([HAVE_XATTR], [1], [libattr])
      AC_DEFINE([HAVE_ATTR_ATTRIBUTES_H], [1])
      have_xattr=yes
    ])
  ])
  AC_SUBST([ATTR_LIB])

  # (Free)BSD extattr
  AC_CHECK_FUNC([extattr_get_file], [
    AC_CHECK_HEADERS([sys/extattr.h], [
      AC_DEFINE([HAVE_EXTATTR], [1], [BSD extended attributes])
      AC_DEFINE([HAVE_SYS_EXTATTR_H], [1])
      have_xattr=yes
    ])
  ])

  if test "$have_xattr" = no; then
    AC_MSG_ERROR([no backend found implementing extended attributes])
  fi
fi

dnl Check for valgrind
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for valgrind])
AC_ARG_WITH([valgrind],
  [AC_HELP_STRING([--with-valgrind],
    [enable internal support for valgrind]
  )],
  [WITH_VALGRIND=$withval],
  [WITH_VALGRIND=no]
)
AC_MSG_RESULT([$WITH_VALGRIND])

if test "$WITH_VALGRIND" != no; then
  AC_CHECK_HEADERS([valgrind/valgrind.h], [], [
    AC_MSG_ERROR([valgrind headers not found. install them or build without --with-valgrind])
  ])
fi

dnl Checking for libunwind
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for libunwind])
AC_ARG_WITH([libunwind],
  [AC_HELP_STRING([--with-libunwind],
    [Include libunwind support for backtraces on assert failures]
  )],
  [WITH_LIBUNWIND=$withval],
  [WITH_LIBUNWIND=no]
)
AC_MSG_RESULT([$WITH_LIBUNWIND])

if test "$WITH_LIBUNWIND" != no; then
  PKG_CHECK_MODULES([LIBUNWIND], [libunwind], [], [
    AC_MSG_ERROR([libunwind not found. install it or build without --with-libunwind])
  ])
  AC_DEFINE([HAVE_LIBUNWIND], [1], [Have libunwind support])
fi

dnl Checking for kerberos5
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for kerberos5])
AC_ARG_WITH([krb5],
  [AC_HELP_STRING([--with-krb5@<:@=DIR@:>@], [Use Kerberos 5])],
  [WITH_KRB5=$withval],
  [WITH_KRB5=no]
)
AC_MSG_RESULT([$WITH_KRB5])

if test "$WITH_KRB5" != no; then
  if test "$WITH_KRB5" != yes; then
    krb5_append_CPPFLAGS=" -I$WITH_KRB5/include"
    krb5_append_LDFLAGS=" -L$WITH_KRB5/lib"
  fi
fi

AC_MSG_CHECKING([custom include directory for kerberos5])
AC_ARG_WITH([krb5-includes],
  [AC_HELP_STRING([--with-krb5-includes=DIR], [Kerberos includes])],
  [
    if test "$WITH_KRB5" = no; then
      AC_MSG_ERROR([build --with-krb5 to use --with-krb5-includes])
    fi
    krb5_append_CPPFLAGS=" -I$withval"
    AC_MSG_RESULT([$withval])
  ],
  [AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([custom lib directory for kerberos5])
AC_ARG_WITH([krb5-libs],
  [AC_HELP_STRING([--with-krb5-libs=DIR], [Kerberos libraries])],
  [
    if test "$WITH_KRB5" = no; then
      AC_MSG_ERROR([build --with-krb5 to use --with-krb5-libs])
    fi
    krb5_append_LDFLAGS=" -L$withval"
    AC_MSG_RESULT([$withval])
  ],
  [AC_MSG_RESULT([no])]
)

if test "$WITH_KRB5" != no; then
  CPPFLAGS="${CPPFLAGS}${krb5_append_CPPFLAGS}"
  LDFLAGS="${LDFLAGS}${krb5_append_LDFLAGS}"

  AC_CHECK_LIB([gssapi_krb5], [gss_acquire_cred],
    [AC_CHECK_HEADERS([gssapi/gssapi_krb5.h],
      [
        KRB5_LIB="-lkrb5 -lgssapi_krb5"
        AC_DEFINE([HAVE_KRB5], [1], [libgssapi_krb5])
      ],
      [AC_MSG_ERROR([gssapi_krb5 headers were not found, install them or build without --with-krb5])]
    )],
    [AC_MSG_ERROR([gssapi_krb5 libs were not found, install them or build without --with-krb5])]
  )
  case "$host_os" in
  *darwin*|*cygwin* ) KRB5_LIB="$KRB5_LIB -lcom_err" ;;
  * ) ;;
  esac
fi

AM_CONDITIONAL([BUILD_WITH_KRB5], [test "$WITH_KRB5" != no])
AC_SUBST([KRB5_LIB])

dnl Check for openssl
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for OpenSSL])
AC_ARG_WITH([openssl],
  [AC_HELP_STRING([--with-openssl@<:@=DIR@:>@],
    [Include openssl support (default no)]
  )],
  [WITH_OPENSSL=$withval],
  [WITH_OPENSSL=no]
)
AC_MSG_RESULT([$WITH_OPENSSL])

if test "$WITH_OPENSSL" != no; then
  if test "$WITH_OPENSSL" != yes; then
    openssl_append_CPPFLAGS=" -I$WITH_OPENSSL/include"
    openssl_append_LDFLAGS=" -L$WITH_OPENSSL/lib"
  fi
fi

AC_MSG_CHECKING([custom include directory for openssl])
AC_ARG_WITH([openssl-includes],
  [AC_HELP_STRING([--with-openssl-includes=DIR], [OpenSSL includes])],
  [
    if test "$WITH_OPENSSL" = no; then
      AC_MSG_ERROR([build --with-openssl to use --with-openssl-includes])
    fi
    openssl_append_CPPFLAGS=" -I$withval"
    AC_MSG_RESULT([$withval])
  ],
  [AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([custom lib directory for openssl])
AC_ARG_WITH([openssl-libs],
  [AC_HELP_STRING([--with-openssl-libs=DIR], [OpenSSL libraries])],
  [
    if test "$WITH_OPENSSL" = no; then
      AC_MSG_ERROR([build --with-openssl to use --with-openssl-libs])
    fi
    openssl_append_LDFLAGS=" -L$withval"
    AC_MSG_RESULT([$withval])
  ],
  [AC_MSG_RESULT([no])]
)

if test "$WITH_OPENSSL" != no; then
  if test "$WITH_KRB5" != no; then
    AC_DEFINE([USE_OPENSSL_KERBEROS], [1], [with kerberos])
  fi

  CPPFLAGS="${CPPFLAGS}${openssl_append_CPPFLAGS}"
  LDFLAGS="${LDFLAGS}${openssl_append_LDFLAGS}"

  AC_CHECK_HEADERS([openssl/ssl.h], [], [
    AC_MSG_ERROR([openssl headers not found. install them or build without --with-openssl])
  ])
  AC_CHECK_LIB([crypto], [BIO_f_base64],
    [CRYPTO_LIB="-lcrypto"],
    [AC_MSG_ERROR([openssl crypto library not found. install it or build without --with-openssl])]
  )
  AC_CHECK_LIB([ssl], [SSL_new],
    [SSL_LIB="-lssl -lcrypto"],
    [AC_MSG_ERROR([openssl ssl library not found. install it or build without --with-openssl])],
    [ -lcrypto "$DL_LIB" ]
  )

  AC_DEFINE([HAVE_LIBSSL], [], [Have libssl])
  AC_SUBST([SSL_LIB])
  AC_SUBST([CRYPTO_LIB])
fi

dnl Check for wolfSSL
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for wolfSSL])
AC_ARG_WITH([wolfssl],
  [AC_HELP_STRING([--with-wolfssl@<:@=DIR@:>@],
    [Include openssl support (default no)]
  )],
  [WITH_WOLFSSL=$withval],
  [WITH_WOLFSSL=no]
)
AC_MSG_RESULT([$WITH_WOLFSSL])

if test "$WITH_WOLFSSL" != no; then
  if test "$WITH_WOLFSSL" = yes; then
    WITH_WOLFSSL="/usr/local"
  fi

  CPPFLAGS="${CPPFLAGS} -I$WITH_WOLFSSL/include -I$WITH_WOLFSSL/include/wolfssl"
  LDFLAGS="${LDFLAGS} -L$WITH_WOLFSSL/lib"

  AC_CHECK_HEADERS([wolfssl/ssl.h], [], [
    AC_MSG_ERROR([wolfssl headers not found. install them or build without --with-wolfssl])
  ])
  AC_CHECK_LIB([wolfssl], [wolfSSL_Init],
    [CRYPTO_LIB="-lwolfssl"],
    [AC_MSG_ERROR([wolfssl crypto library not found. install it or build without --with-wolfssl])]
  )
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <wolfssl/options.h>
    #if !defined(HAVE_LIGHTY) && !defined(OPENSSL_ALL)
    #error HAVE_LIGHTY macro not defined
    #endif
  ]])], [], [AC_MSG_ERROR([wolfssl must be built with ./configure --enable-lighty])])
  SSL_LIB="-lwolfssl"

  AC_SUBST([SSL_LIB])
  AC_SUBST([CRYPTO_LIB])
fi

AM_CONDITIONAL([BUILD_WITH_OPENSSL],
               [test "$WITH_OPENSSL" != no || test "$WITH_WOLFSSL" != no])

if test "$WITH_OPENSSL" != no && test "$WITH_WOLFSSL" != no; then
  AC_MSG_ERROR([lighttpd should not be built with both --with-openssl and --with-wolfssl])
fi


dnl pcre support
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for perl regular expressions support])
AC_ARG_WITH([pcre],
  [AC_HELP_STRING([--with-pcre], [Enable pcre support (default yes)])],
  [WITH_PCRE=$withval],
  [WITH_PCRE=yes]
)
AC_MSG_RESULT([$WITH_PCRE])

if test "$WITH_PCRE" != no; then
  if test "$WITH_PCRE" != yes; then
    PCRE_LIB="-L$WITH_PCRE/lib -lpcre"
    CPPFLAGS="$CPPFLAGS -I$WITH_PCRE/include"
  else
    AC_PATH_PROG([PCRECONFIG], [pcre-config])
    if test -n "$PCRECONFIG"; then
      PCRE_LIB=`"$PCRECONFIG" --libs`
      CPPFLAGS="$CPPFLAGS `"$PCRECONFIG" --cflags`"
    fi
  fi

  if test -z "$PCRE_LIB"; then
    AC_MSG_ERROR([pcre-config not found, install the pcre-devel package or build with --without-pcre])
  fi

  AC_DEFINE([HAVE_LIBPCRE], [1], [libpcre])
  AC_DEFINE([HAVE_PCRE_H], [1], [pcre.h])
  AC_SUBST([PCRE_LIB])
fi

dnl zlib
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for zlib support])
AC_ARG_WITH([zlib],
  [AC_HELP_STRING([--with-zlib],
    [Enable zlib support for mod_compress]
  )],
  [WITH_ZLIB=$withval],
  [WITH_ZLIB=yes]
)
AC_MSG_RESULT([$WITH_ZLIB])

if test "$WITH_ZLIB" != no; then
  if test "$WITH_ZLIB" != yes; then
    Z_LIB="-L$WITH_ZLIB -lz"
    CPPFLAGS="$CPPFLAGS -I$WITH_ZLIB"
  else
    AC_CHECK_HEADERS([zlib.h], [],
      [AC_MSG_ERROR([zlib headers not found, install them or build without --with-zlib])]
    )
    AC_CHECK_LIB([z], [deflate],
      [Z_LIB=-lz],
      [AC_MSG_ERROR([zlib library not found, install it or build without --with-zlib])]
    )
  fi

  AC_DEFINE([HAVE_LIBZ], [1], [libz])
  AC_DEFINE([HAVE_ZLIB_H], [1])
  AC_SUBST([Z_LIB])
fi

dnl bzip2
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for bzip2 support])
AC_ARG_WITH([bzip2],
  [AC_HELP_STRING([--with-bzip2],
    [Enable bzip2 support for mod_compress]
  )],
  [WITH_BZIP2=$withval],
  [WITH_BZIP2=yes]
)
AC_MSG_RESULT([$WITH_BZIP2])

if test "$WITH_BZIP2" != no; then
  if test "$WITH_BZIP2" != yes; then
    BZ_LIB="-L$WITH_BZIP2 -lbz2"
    CPPFLAGS="$CPPFLAGS -I$WITH_BZIP2"
  else
    AC_CHECK_HEADERS([bzlib.h], [], [
      AC_MSG_ERROR([bzip2 headers not found, install them or build without --with-bzip2])
    ])
    AC_CHECK_LIB([bz2], [BZ2_bzCompress],
      [BZ_LIB=-lbz2],
      [AC_MSG_ERROR([bzip2 library not found, install it or build without --with-bzip2])]
    )
  fi

  AC_DEFINE([HAVE_LIBBZ2], [1], [libbz2])
  AC_DEFINE([HAVE_BZLIB_H], [1])
  AC_SUBST([BZ_LIB])
fi

dnl Check for fam/gamin
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for FAM])
AC_ARG_WITH([fam],
  [AC_HELP_STRING([--with-fam],
    [fam/gamin for reducing number of stat() calls]
  )],
  [WITH_FAM=$withval],
  [WITH_FAM=no]
)
AC_MSG_RESULT([$WITH_FAM])

if test "$WITH_FAM" != no; then
  if test "$WITH_FAM" != yes; then
    FAM_LIBS="-L$WITH_FAM -lfam"
    CPPFLAGS="$CPPFLAGS -I$WITH_FAM"
  else
    AC_CHECK_LIB([fam], [FAMOpen2], [
      AC_CHECK_HEADERS([fam.h], [FAM_LIBS=-lfam])
    ])
    dnl fam has no pkg-config so far, so just search for gamin as fallback
    if test -z "$FAM_LIBS"; then
      PKG_CHECK_MODULES([FAM], [gamin >= 0.1.0])
    fi
  fi

  if test -z "$FAM_LIBS"; then
    AC_MSG_ERROR([fam/gamin headers and/or libs were not found, install them or build without --with-fam])
  fi

  OLD_LIBS=$LIBS
  LIBS=$FAM_LIBS
  AC_CHECK_FUNCS([FAMNoExists])
  LIBS=$OLD_LIBS

  AC_DEFINE([HAVE_LIBFAM], [1], [libfam])
  AC_DEFINE([HAVE_FAM_H], [1], [fam.h])
  AC_SUBST([FAM_LIBS])
fi


dnl webdav props (xml2 and sqlite3)
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for properties in mod_webdav])
AC_ARG_WITH([webdav-props],
  [AC_HELP_STRING([--with-webdav-props], [properties in mod_webdav])],
  [WITH_WEBDAV_PROPS=$withval],
  [WITH_WEBDAV_PROPS=no]
)
AC_MSG_RESULT([$WITH_WEBDAV_PROPS])

if test "$WITH_WEBDAV_PROPS" != no; then
  AC_MSG_CHECKING([for libxml2])
  AC_ARG_WITH([libxml],
    [AC_HELP_STRING([--with-libxml],
      [libxml2 for properties in mod_webdav]
    )],
    [WITH_LIBXML=$withval],
    [WITH_LIBXML=yes]
  )
  AC_MSG_RESULT([$WITH_LIBXML])

  if test "$WITH_LIBXML" = no; then
    AC_MSG_ERROR([--with-webdav-props requires libxml])
  fi

  if test "$WITH_LIBXML" != yes; then
    XML_LIBS="-L$WITH_LIBXML/.libs -lxml2"
    XML_CFLAGS="-I$WITH_LIBXML/include"
  else
    PKG_CHECK_MODULES([XML], [libxml-2.0], [], [
      AC_MSG_ERROR([libxml2 not found, install it or build without --with-webdav-props])
    ])
  fi

  AC_DEFINE([HAVE_LIBXML2], [1], [libxml2])
  AC_DEFINE([HAVE_LIBXML_H], [1], [libxml.h])
  AC_SUBST([XML_LIBS])
  AC_SUBST([XML_CFLAGS])

  AC_MSG_CHECKING([for sqlite])
  AC_ARG_WITH([sqlite],
    [AC_HELP_STRING([--with-sqlite],
      [sqlite for properties in mod_webdav]
    )],
    [WITH_SQLITE=$withval],
    [WITH_SQLITE=yes]
  )
  AC_MSG_RESULT([$WITH_SQLITE])

  if test "$WITH_SQLITE" = no; then
    AC_MSG_ERROR([--with-webdav-props requires sqlite])
  fi

  if test "$WITH_SQLITE" != yes; then
    SQLITE_LIBS="-L$WITH_SQLITE/.libs -lsqlite3"
    SQLITE_CFLAGS="-I$WITH_SQLITE"
  else
    PKG_CHECK_MODULES([SQLITE], [sqlite3], [], [
      AC_MSG_ERROR([sqlite3 not found, install it or build without --with-webdav-props])
    ])
  fi

  AC_DEFINE([HAVE_SQLITE3], [1], [libsqlite3])
  AC_DEFINE([HAVE_SQLITE3_H], [1], [sqlite3.h])
  AC_SUBST([SQLITE_LIBS])
  AC_SUBST([SQLITE_CFLAGS])
fi


dnl webdav locks (uuid)
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for locks in mod_webdav])
AC_ARG_WITH([webdav-locks],
  [AC_HELP_STRING([--with-webdav-locks],
    [locks in mod_webdav (requires webdav properties)]
  )],
  [WITH_WEBDAV_LOCKS=$withval],
  [WITH_WEBDAV_LOCKS=no]
)
AC_MSG_RESULT([$WITH_WEBDAV_LOCKS])

if test "$WITH_WEBDAV_LOCKS" != no; then
  if test "$WITH_WEBDAV_PROPS" = no; then
    AC_MSG_ERROR([--with-webdav-locks requires --with-webdav-props])
  fi

  AC_MSG_CHECKING([for libuuid])
  AC_ARG_WITH([uuid],
    [AC_HELP_STRING([--with-uuid], [uuid for locks in mod_webdav])],
    [WITH_UUID=$withval],
    [WITH_UUID=yes]
  )
  AC_MSG_RESULT([$WITH_UUID])

  if test "$WITH_UUID" = no; then
    AC_MSG_ERROR([--with-webdav-locks requires uuid])
  fi

  if test "$WITH_UUID" != yes; then
    UUID_LIBS="-L$WITH_UUID -luuid"
    CPPFLAGS="$CPPFLAGS -I$WITH_UUID"
  else
    AC_CHECK_LIB([uuid], [uuid_unparse],
      [UUID_LIBS=-luuid],
      [AC_MSG_ERROR([uuid lib not found, install it or build without --with-webdav-locks])]
    )
    AC_CHECK_HEADERS([uuid/uuid.h], [],
      [AC_MSG_ERROR([uuid headers not found, install them or build without --with-webdav-locks])]
    )
  fi

  AC_DEFINE([HAVE_LIBUUID], [1], [libuuid])
  AC_DEFINE([HAVE_UUID_UUID_H], [1], [uuid/uuid.h is available])
  AC_SUBST([UUID_LIBS])
fi

dnl Check for gdbm
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for gdbm])
AC_ARG_WITH([gdbm],
  [AC_HELP_STRING([--with-gdbm], [gdbm storage for mod_trigger_b4_dl])],
  [WITH_GDBM=$withval],
  [WITH_GDBM=no]
)
AC_MSG_RESULT([$WITH_GDBM])

if test "$WITH_GDBM" != no; then
  if test "$WITH_GDBM" != yes; then
    GDBM_LIB="-L$WITH_GDBM -lgdbm"
    CPPFLAGS="$CPPFLAGS -I$WITH_GDBM"
  else
    AC_CHECK_LIB([gdbm], [gdbm_open],
      [GDBM_LIB=-lgdbm],
      [AC_MSG_ERROR([gdbm lib not found, install it or build without --with-gdbm])]
    )
    AC_CHECK_HEADERS([gdbm.h], [],
      [AC_MSG_ERROR([gdbm headers not found, install them or build without --with-gdbm])]
    )
  fi

  AC_DEFINE([HAVE_GDBM], [1], [libgdbm])
  AC_DEFINE([HAVE_GDBM_H], [1])
  AC_SUBST([GDBM_LIB])
fi
AM_CONDITIONAL([BUILD_WITH_GDBM], [test "$WITH_GDBM" != no])

dnl Check for GeoIP
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for GeoIP])
AC_ARG_WITH([geoip],
  [AC_HELP_STRING([--with-geoip], [IP-based geolocation lookup])],
  [WITH_GEOIP=$withval],
  [WITH_GEOIP=no]
)
AC_MSG_RESULT([$WITH_GEOIP])

if test "$WITH_GEOIP" != no; then
  if test "$WITH_GEOIP" != yes; then
    GEOIP_LIB="-L$WITH_GEOIP -lGeoIP"
    CPPFLAGS="$CPPFLAGS -I$WITH_GEOIP"
  else
    AC_CHECK_LIB([GeoIP], [GeoIP_country_name_by_addr],
      [GEOIP_LIB=-lGeoIP],
      [AC_MSG_ERROR([GeoIP lib not found, install it or build without --with-geoip])]
    )
    AC_CHECK_HEADERS([GeoIP.h], [],
      [AC_MSG_ERROR([GeoIP headers not found, install them or build without --with-geoip])]
    )
  fi

  AC_DEFINE([HAVE_GEOIP], [1], [libGeoIP])
  AC_DEFINE([HAVE_GEOIP_H], [1])
  AC_SUBST([GEOIP_LIB])
fi
AM_CONDITIONAL([BUILD_WITH_GEOIP], [test "$WITH_GEOIP" != no])

dnl Check for maxminddb
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for maxminddb])
AC_ARG_WITH([maxminddb],
  [AC_HELP_STRING([--with-maxminddb], [IP-based geolocation lookup])],
  [WITH_MAXMINDDB=$withval],
  [WITH_MAXMINDDB=no]
)
AC_MSG_RESULT([$WITH_MAXMINDDB])

if test "$WITH_MAXMINDDB" != no; then
  if test "$WITH_MAXMINDDB" != yes; then
    MAXMINDDB_LIB="-L$WITH_MAXMINDDB -lmaxminddb"
    CPPFLAGS="$CPPFLAGS -I$WITH_MAXMINDDB"
  else
    AC_CHECK_LIB([maxminddb], [MMDB_open],
      [MAXMINDDB_LIB=-lmaxminddb],
      [AC_MSG_ERROR([maxminddb lib not found, install it or build without --with-maxminddb])]
    )
    AC_CHECK_HEADERS([maxminddb.h], [],
      [AC_MSG_ERROR([maxminddb headers not found, install them or build without --with-maxminddb])]
    )
  fi

  AC_DEFINE([HAVE_MAXMINDDB], [1], [libmaxminddb])
  AC_DEFINE([HAVE_MAXMINDDB_H], [1])
  AC_SUBST([MAXMINDDB_LIB])
fi
AM_CONDITIONAL([BUILD_WITH_MAXMINDDB], [test "$WITH_MAXMINDDB" != no])

dnl Check for memcached
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for memcached])
AC_ARG_WITH([memcached],
  [AC_HELP_STRING([--with-memcached],
    [memcached storage for mod_trigger_b4_dl/mod_cml]
  )],
  [WITH_MEMCACHED=$withval],
  [WITH_MEMCACHED=no]
)
AC_MSG_RESULT([$WITH_MEMCACHED])

if test "$WITH_MEMCACHED" != no; then
  if test "$WITH_MEMCACHED" != yes; then
    MEMCACHED_LIB="-L$WITH_MEMCACHED -lMEMCACHED"
    CPPFLAGS="$CPPFLAGS -I$WITH_MEMCACHED"
  else
    AC_CHECK_LIB([memcached], [memcached],
      [ MEMCACHED_LIB=-lmemcached ],
      [AC_MSG_ERROR([memcached lib not found, install it or build without --with-memcached])]
    )
    AC_CHECK_HEADERS([libmemcached/memcached.h], [],
      [AC_MSG_ERROR([memcached headers not found, install them or build without --with-memcached])]
    )
  fi

  AC_DEFINE([USE_MEMCACHED], [1], [libmemcached])
  AC_SUBST([MEMCACHED_LIB])
fi
AM_CONDITIONAL([BUILD_WITH_MEMCACHED], [test "$WITH_MEMCACHED" != no])

BUILD_MOD_TRIGGER_B4_DL=no
if test "$WITH_MEMCACHED" != no || test "$WITH_GDBM" != no ; then
  BUILD_MOD_TRIGGER_B4_DL=yes
fi

AM_CONDITIONAL([BUILD_MOD_TRIGGER_B4_DL], [test "$BUILD_MOD_TRIGGER_B4_DL" != no])

dnl Check for lua
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([if lua-support is requested])
AC_ARG_WITH([lua],
  [AC_HELP_STRING([--with-lua], [lua engine for mod_magnet/mod_cml])],
  [WITH_LUA=$withval],
  [WITH_LUA=no]
)
AC_MSG_RESULT([$WITH_LUA])

if test "$WITH_LUA" != no; then
  found_lua=0
  if test "$WITH_LUA" != yes; then
    PKG_CHECK_MODULES([LUA], [$WITH_LUA >= 5.1],
      [found_lua=1],
      [AC_MSG_NOTICE([Couldn\'t find requested lua pkg-config module $WITH_LUA])]
    )
    if test "$found_lua" = "0"; then
      LUA_LIBS="-L$WITH_LUA -llua"
      LUA_CFLAGS="-I$WITH_LUA"
    fi
  else
    for luaname in lua5.3 lua-5.3 lua5.2 lua-5.2 lua5.1 lua-5.1 lua; do
      if test "$found_lua" = "0"; then
        PKG_CHECK_MODULES([LUA], [$luaname >= 5.1],
          [found_lua=1],
          [AC_MSG_NOTICE([Couldn\'t find $luaname])]
        )
      fi
    done
    if test "$found_lua" = "0"; then
      AC_MSG_ERROR([Couldn\'t find any lua pkg-config module])
    fi
  fi

  AC_DEFINE([HAVE_LUA], [1], [liblua])
  AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
  AC_SUBST([LUA_LIBS])
  AC_SUBST([LUA_CFLAGS])
fi
AM_CONDITIONAL([BUILD_WITH_LUA], [test "$WITH_LUA" != no])

dnl "--with-FEATURE" blocks end
AC_MSG_NOTICE([----------------------------------------])

dnl search for crypt_r and (fallback) for crypt
save_LIBS=$LIBS
LIBS=
found_crypt=no
AC_SEARCH_LIBS([crypt_r], [crypt],
  [
    AC_DEFINE([HAVE_CRYPT_R], [1], [crypt_r])
    AC_CHECK_HEADERS([crypt.h])
    CRYPT_LIB=$LIBS
    found_crypt=crypt_r
  ],
  [AC_SEARCH_LIBS([crypt], [crypt], [
    AC_DEFINE([HAVE_CRYPT], [1], [crypt])
    AC_CHECK_HEADERS([crypt.h])
    CRYPT_LIB=$LIBS
    found_crypt=crypt
  ])]
)
LIBS=$save_LIBS
AC_SUBST([CRYPT_LIB])

AC_MSG_CHECKING([crypt_r/crypt support])
AC_MSG_RESULT([$found_crypt])

dnl check whether sendfilev needs -lsendfile
AC_MSG_NOTICE([----------------------------------------])
save_LIBS=$LIBS
LIBS=
have_sendfilev=no
AC_SEARCH_LIBS([sendfilev], [sendfile], [
  if test -z "$LIBS"; then
    have_sendfilev=yes
  else
    have_sendfilev=$LIBS
  fi
  SENDFILE_LIB=$LIBS
  AC_DEFINE([HAVE_SENDFILEV], [1], [solaris sendfilev])
])
LIBS=$save_LIBS
AC_SUBST([SENDFILE_LIB])

AC_MSG_CHECKING([solaris sendfilev present])
AC_MSG_RESULT([$have_sendfilev])

AC_MSG_NOTICE([----------------------------------------])

case "$host_os" in
*mingw* ) LIBS="$LIBS -lwsock32" ;;
* ) ;;
esac

AC_CHECK_FUNCS([\
  arc4random_buf \
  chroot \
  clock_gettime \
  epoll_ctl \
  explicit_bzero \
  explicit_memset \
  fork \
  getloadavg \
  getrlimit \
  getuid \
  gmtime_r \
  inet_pton \
  issetugid \
  jrand48 \
  kqueue \
  localtime_r \
  lstat \
  madvise \
  memset \
  memset_s \
  mmap \
  pathconf \
  pipe2 \
  poll \
  port_create \
  select \
  send_file \
  sendfile \
  sendfile64 \
  sigaction \
  signal \
  srandom \
  writev \
])
AC_CHECK_HEADERS([sys/random.h], [AC_CHECK_FUNCS([getentropy])])
AC_CHECK_HEADERS([linux/random.h], [AC_CHECK_FUNCS([getrandom])])

AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([if weak symbols are supported])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([[
    __attribute__((weak)) void __dummy(void *x) { }
    void f(void *x) { __dummy(x); }
  ]])],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_WEAK_SYMBOLS], [1], [weak symbols are supported])
  ],
  [AC_MSG_RESULT([no])]
)

AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([for Large File System support])
AC_ARG_ENABLE([lfs],
  [AC_HELP_STRING([--enable-lfs],
    [Turn on Large File System (default)]
  )],
  [
    case "${enableval}" in
    yes) ENABLE_LFS=yes ;;
    no) ENABLE_LFS=no ;;
    *) AC_MSG_ERROR([bad value ${enableval} for --enable-lfs]) ;;
    esac
  ],
  [ ENABLE_LFS=yes ]
)
AC_MSG_RESULT([$ENABLE_LFS])
if test "$ENABLE_LFS" = yes; then
  CPPFLAGS="${CPPFLAGS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES"
fi

dnl check if sendfile works
if test "$ac_cv_func_sendfile" = yes; then
  AC_MSG_NOTICE([----------------------------------------])
  AC_MSG_CHECKING([if sendfile works])
  if test "$cross_compiling" = no; then
    AC_TRY_RUN(
      [
        #ifdef HAVE_SYS_SENDFILE_H
        #include <sys/sendfile.h>
        #endif /* HAVE_SYS_SENDFILE_H */
        #include <errno.h>
        int main() {
          int o = 0;
          if (-1 == sendfile(-1, 0, &o, 0) && errno == ENOSYS) return -1;
          return 0;
        }
      ],
      [AC_MSG_RESULT([yes])],
      [
        AC_MSG_RESULT([no])
        AC_DEFINE([HAVE_SENDFILE_BROKEN], [1], [broken sendfile])
      ]
    )
  fi
fi

dnl Check for IPv6 support
AC_MSG_NOTICE([----------------------------------------])
AC_ARG_ENABLE([ipv6],
  [AC_HELP_STRING([--disable-ipv6], [disable IPv6 support])],
  [
    case "${enableval}" in
    yes) ipv6=true ;;
    no) ipv6=false ;;
    *) AC_MSG_ERROR([bad value ${enableval} for --enable-ipv6]) ;;
    esac
  ],
  [ipv6=true]
)

if test "$ipv6" = true; then
  AC_CACHE_CHECK([for IPv6 support], [ac_cv_ipv6_support], [
    AC_TRY_LINK(
      [
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <netinet/in.h>
      ],
      [
        struct sockaddr_in6 s; struct in6_addr t=in6addr_any; int i=AF_INET6; s; t.s6_addr[0] = 0;
      ],
      [ac_cv_ipv6_support=yes],
      [ac_cv_ipv6_support=no]
    )
  ])

  if test "$ac_cv_ipv6_support" = yes; then
    AC_DEFINE([HAVE_IPV6], [1], [Whether to enable IPv6 support])
  else
    AC_MSG_ERROR([IPv6 seems broken.  Fix it or build with --disable-ipv6])
  fi
fi

# disable mmap by default
# lighttpd may always use mmap with files it owns (created tmp files)
AC_MSG_NOTICE([----------------------------------------])
AC_MSG_CHECKING([use mmap if available])
AC_ARG_ENABLE([mmap],
  [AC_HELP_STRING([--enable-mmap],
    [use mmap if available]
  )],
  [
    case "${enableval}" in
    yes) mmap=true ;;
    no) mmap=false ;;
    *) AC_MSG_ERROR([bad value ${enableval} for --enable-mmap]) ;;
    esac
  ],
  [mmap=false]
)
AC_MSG_RESULT([$mmap])

if test "$mmap" = true; then
  AC_DEFINE([ENABLE_MMAP], [1], [Use mmap if available])
fi

dnl check for fastcgi lib, for the tests only
AC_MSG_NOTICE([----------------------------------------])
fastcgi_found=no
AC_CHECK_LIB([fcgi], [FCGI_Accept], [
  AC_CHECK_HEADERS([fastcgi.h fastcgi/fastcgi.h], [
    fastcgi_found=yes
  ])
])

AM_CONDITIONAL([CHECK_WITH_FASTCGI], [test "$fastcgi_found" = yes])


AC_MSG_NOTICE([----------------------------------------])
dnl check for extra compiler options (warning options)
if test "${GCC}" = yes; then
  TRY_CFLAGS([-Wall -W -Wshadow -pedantic])
fi

AC_ARG_ENABLE([extra-warnings],
  [AC_HELP_STRING([--enable-extra-warnings],
    [enable extra warnings (gcc specific)]
  )],
  [
    case "${enableval}" in
    error) extrawarnings=error ;;
    yes) extrawarnings=true ;;
    no) extrawarnings=false ;;
    *) AC_MSG_ERROR([bad value ${enableval} for --enable-extra-warnings]) ;;
    esac
  ],
  [extrawarnings=false]
)

if test "$extrawarnings" = true || test "$extrawarnings" = error; then
  TRY_CFLAGS([-g -O2 -g2 -Wall -Wmissing-declarations -Wcast-align -Wsign-compare -Wnested-externs -Wpointer-arith -D_FORTIFY_SOURCE=2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security])
  TRY_LDFLAGS([-Wl,--as-needed])
  if test "$extrawarnings" = error; then
    AS_VAR_APPEND([CFLAGS], [" -Werror"])
    AS_VAR_APPEND([LDFLAGS], [" -Wl,--fatal-warnings"])
  fi
fi

dnl build version-id
LIGHTTPD_VERSION_ID=m4_format([0x%x%02x%02x], m4_unquote(m4_split(AC_PACKAGE_VERSION, [\.])))
AC_DEFINE_UNQUOTED([LIGHTTPD_VERSION_ID], [$LIGHTTPD_VERSION_ID], [lighttpd-version-id])

AC_CONFIG_FILES([\
  distribute.sh \
  doc/config/conf.d/Makefile \
  doc/config/Makefile \
  doc/config/vhosts.d/Makefile \
  doc/Makefile \
  doc/outdated/Makefile \
  doc/scripts/Makefile \
  doc/systemd/Makefile \
  Makefile \
  src/Makefile \
  tests/docroot/123/Makefile \
  tests/docroot/Makefile \
  tests/docroot/www/expire/Makefile \
  tests/docroot/www/go/Makefile \
  tests/docroot/www/indexfile/Makefile \
  tests/docroot/www/Makefile \
  tests/Makefile \
])
AC_OUTPUT

do_build="\
  mod_access \
  mod_accesslog \
  mod_alias \
  mod_auth \
  mod_authn_file \
  mod_cgi \
  mod_compress \
  mod_deflate \
  mod_dirlisting \
  mod_evhost \
  mod_expire \
  mod_extforward \
  mod_fastcgi \
  mod_flv_streaming \
  mod_indexfile \
  mod_proxy \
  mod_redirect \
  mod_rewrite \
  mod_rrdtool \
  mod_scgi \
  mod_secdownload \
  mod_setenv \
  mod_simple_vhost \
  mod_sockproxy \
  mod_ssi \
  mod_staticfile \
  mod_status \
  mod_userdir \
  mod_usertrack \
  mod_vhostdb \
  mod_webdav \
  mod_wstunnel \
"

lighty_track_feature() {
  if eval "$3"; then
    enable_feature="$enable_feature $1"
    do_build="$do_build $2"
  else
    disable_feature="$disable_feature $1"
    no_build="$no_build $2"
  fi
}

lighty_track_feature "regex-conditionals" "" \
  'test "$WITH_PCRE" != no'

lighty_track_feature "storage-gdbm" "" \
  'test "$WITH_GDBM" != no'

lighty_track_feature "storage-memcached" "" \
  'test "$WITH_MEMCACHED" != no'

lighty_track_feature "" "mod_trigger_b4_dl" \
  'test "$BUILD_MOD_TRIGGER_B4_DL" != no'

lighty_track_feature "mysql" "mod_authn_mysql mod_mysql_vhost mod_vhostdb_mysql" \
  'test "$WITH_MYSQL" != no'

lighty_track_feature "postgresql" "mod_vhostdb_pgsql" \
  'test "$WITH_PGSQL" != no'

lighty_track_feature "dbi" "mod_vhostdb_dbi" \
  'test "$WITH_DBI" != no'

lighty_track_feature "lua" "mod_cml mod_magnet" \
  'test "$WITH_LUA" != no'

lighty_track_feature "geoip" "mod_geoip" \
  'test "$WITH_GEOIP" != no'

lighty_track_feature "maxminddb" "mod_maxminddb" \
  'test "$WITH_MAXMINDDB" != no'

lighty_track_feature "compress-gzip compress-deflate" "" \
  'test "$WITH_ZLIB" != no'

lighty_track_feature "compress-bzip2" "" \
  'test "$WITH_BZIP2" != no'

lighty_track_feature "kerberos" "mod_authn_gssapi" \
  'test "$WITH_KRB5" != no'

lighty_track_feature "ldap" "mod_authn_ldap mod_vhostdb_ldap" \
  'test "$WITH_LDAP" != no'

lighty_track_feature "pam" "mod_authn_pam" \
  'test "$WITH_PAM" != no'

lighty_track_feature "network-openssl" "mod_openssl" \
  'test "$WITH_OPENSSL" != no || test "$WITH_WOLFSSL" != no'

lighty_track_feature "auth-crypt" "" \
  'test "$found_crypt" != no'

lighty_track_feature "network-ipv6" "" \
  'test "$ac_cv_ipv6_support" != no'

lighty_track_feature "large-files" "" \
  'test "$ENABLE_LFS" = yes'

lighty_track_feature "stat-cache-fam" "" \
  'test "$WITH_FAM" != no'

lighty_track_feature "webdav-properties" "" \
  'test "$WITH_WEBDAV_PROPS" != no'

lighty_track_feature "webdav-locks" "" \
  'test "$WITH_WEBDAV_LOCKS" != no'

dnl output

$ECHO
$ECHO "Plugins:"
$ECHO

$ECHO "enabled: "
for p in $do_build; do
  $ECHO "  $p"
done | sort

$ECHO "disabled: "
for p in $no_build; do
  $ECHO "  $p"
done | sort

$ECHO
$ECHO "Features:"
$ECHO

$ECHO "enabled: "
for p in $enable_feature; do
  $ECHO "  $p"
done | sort

$ECHO "disabled: "
for p in $disable_feature; do
  $ECHO "  $p"
done | sort

$ECHO
