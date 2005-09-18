# lighttpd.conf and conformance.pl expect this directory
testdir=$(srcdir)/tmp/lighttpd/

if CHECK_WITH_FASTCGI
check_PROGRAMS=fcgi-auth fcgi-responder

fcgi_auth_SOURCES=fcgi-auth.c
fcgi_auth_LDADD=-lfcgi

fcgi_responder_SOURCES=fcgi-responder.c
fcgi_responder_LDADD=-lfcgi
endif

TESTS=\
	prepare.sh \
	run-tests.pl \
	cleanup.sh

CONFS=fastcgi-10.conf \
      fastcgi-auth.conf \
      fastcgi-responder.conf \
      fastcgi-13.conf \
      bug-06.conf \
      bug-12.conf \
      core-var-include.t \
      var-include.conf \
      var-include-sub.conf \
      condition.conf \
      core-condition.t \
      core-request.t \
      core-response.t \
      core-keepalive.t \
      core.t \
      mod-access.t \
      mod-auth.t \
      mod-cgi.t \
      mod-compress.t \
      mod-fastcgi.t \
      mod-redirect.t \
      mod-userdir.t \
      mod-rewrite.t \
      request.t \
      mod-ssi.t \
      LightyTest.pm \
      mod-setenv.t 


TESTS_ENVIRONMENT=$(srcdir)/wrapper.sh $(srcdir) $(top_builddir) 

EXTRA_DIST=wrapper.sh lighttpd.conf \
	lighttpd.user \
	lighttpd.htpasswd \
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
