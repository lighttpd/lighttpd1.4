# lighttpd.conf and conformance.pl expect this directory
testdir=$(srcdir)/tmp/lighttpd/

if CHECK_WITH_FASTCGI
check_PROGRAMS=fcgi-auth fcgi-responder scgi-responder

fcgi_auth_SOURCES=fcgi-auth.c
fcgi_auth_LDADD=-lfcgi

fcgi_responder_SOURCES=fcgi-responder.c
fcgi_responder_LDADD=-lfcgi
endif

scgi_responder_SOURCES=scgi-responder.c

TESTS=\
	prepare.sh \
	run-tests.pl \
	cleanup.sh

CONFS=\
	404-handler.conf \
	cachable.t \
	condition.conf \
	core-404-handler.t \
	core-condition.t \
	core-keepalive.t \
	core-request.t \
	core-response.t \
	core-var-include.t \
	fastcgi-10.conf \
	fastcgi-responder.conf \
	LightyTest.pm \
	lowercase.conf \
	lowercase.t \
	mod-auth.conf \
	mod-auth.t \
	mod-cgi.t \
	mod-compress.conf \
	mod-compress.t \
	mod-extforward.conf \
	mod-extforward.t \
	mod-fastcgi.t \
	mod-proxy.t \
	mod-secdownload.conf \
	mod-secdownload.t \
	mod-setenv.t \
	mod-ssi.t \
	mod-userdir.t \
	proxy.conf \
	request.t \
	scgi-responder.conf \
	symlink.t \
	var-include-sub.conf \
	var-include.conf

TESTS_ENVIRONMENT=$(srcdir)/wrapper.sh $(srcdir) $(top_builddir)

EXTRA_DIST=\
	$(CONFS) \
	$(TESTS) \
	CMakeLists.txt \
	meson.build \
	lighttpd.conf \
	lighttpd.htpasswd \
	lighttpd.user \
	SConscript \
	wrapper.sh

SUBDIRS=docroot

leak-check:
	for i in $(TESTS); do \
		$(srcdir)/$$i; \
		echo $$?; \
	done

clean-local:
	rm -f *.out
