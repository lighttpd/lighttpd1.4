# lighttpd.conf and conformance.pl expect this directory
testdir=/tmp/lighttpd/

if CHECK_WITH_FASTCGI
check_PROGRAMS=fcgi-auth

fcgi_auth_SOURCES=fcgi-auth.c
fcgi_auth_LDADD=-lfcgi
endif

TESTS=\
prepare.sh \
run-tests.pl \
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
