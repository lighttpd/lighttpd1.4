# lighttpd.conf and conformance.pl expect this directory
testdir=/tmp/lighttpd/

if CHECK_WITH_FASTCGI
check_PROGRAMS=fcgi-auth

fcgi_auth_SOURCES=fcgi-auth.c
fcgi_auth_LDADD=-lfcgi
endif

TESTS=\
prepare.sh \
check.pl \
bug-03.sh \
bug-06.sh \
bug-12.sh \
large-header-01.sh \
compress-01.sh \
compress-02.sh \
compress-03.sh \
compress-04.sh \
fastcgi-10.sh \
fastcgi-11.sh \
fastcgi-12.sh \
fastcgi-13.sh \
cleanup.sh

CONFS=fastcgi-10.conf \
      fastcgi-11.conf \
      fastcgi-12.conf \
      fastcgi-13.conf \
      bug-06.conf \
      bug-12.conf

TESTS_ENVIRONMENT=$(srcdir)/wrapper.sh $(srcdir) $(top_builddir)

EXTRA_DIST=conformance.pl wrapper.sh testbase.sh lighttpd.conf \
	lighttpd.user \
	$(CONFS) \
	$(TESTS)
SUBDIRS=docroot

leak-check:
	for i in $(TESTS); do \
		$(srcdir)/$$i; \
		echo $$?; \
	done 

clean-local:
	rm -f *.out
