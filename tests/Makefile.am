# lighttpd.conf and conformance.pl expect this directory
testdir=$(srcdir)/tmp/lighttpd/

check_PROGRAMS=fcgi-responder scgi-responder

fcgi_responder_SOURCES=fcgi-responder.c
scgi_responder_SOURCES=scgi-responder.c

TESTS=\
	prepare.sh \
	run-tests.pl \
	cleanup.sh

CONFS=\
	condition.conf \
	core-condition.t \
	fastcgi-responder.conf \
	LightyTest.pm \
	mod-fastcgi.t \
	mod-scgi.t \
	proxy.conf \
	request.t \
	scgi-responder.conf \
	var-include-sub.conf

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
