# lighttpd.conf and conformance.pl expect this directory
testdir=/tmp/lighttpd/

check_PROGRAMS=fcgi-auth

fcgi_auth_SOURCES=fcgi-auth.c
fcgi_auth_LDADD=-lfcgi

TESTS=\
prepare.sh \
basic-01.sh \
basic-02.sh \
basic-03.sh \
basic-05.sh \
basic-06.sh \
basic-07.sh \
basic-08.sh \
basic-09.sh \
basic-10.sh \
basic-11.sh \
bug-urldecode-00.sh \
bug-03.sh \
bug-06.sh \
bug-12.sh \
bug-14.sh \
bug-15.sh \
bug-15-2.sh \
bug-15-3.sh \
broken-header-01.sh \
content-length-01.sh \
content-length-02.sh \
content-length-03.sh \
content-length-04.sh \
content-length-05.sh \
head-01.sh \
post-01.sh \
post-02.sh \
host-01.sh \
host-02.sh \
host-03.sh \
host-04.sh \
host-05.sh \
http11-01.sh \
http11-02.sh \
http11-03.sh \
missing-01.sh \
missing-02.sh \
large-header-01.sh \
accessdeny-01.sh \
cgi-01.sh \
cgi-02.sh \
cgi-03.sh \
compress-01.sh \
compress-02.sh \
compress-03.sh \
compress-04.sh \
fastcgi-01.sh \
fastcgi-02.sh \
fastcgi-03.sh \
fastcgi-04.sh \
fastcgi-05.sh \
fastcgi-06.sh \
fastcgi-07.sh \
fastcgi-08.sh \
fastcgi-09.sh \
fastcgi-10.sh \
fastcgi-11.sh \
fastcgi-12.sh \
fastcgi-13.sh \
auth-01.sh \
auth-02.sh \
auth-03.sh \
content-01.sh \
content-02.sh \
content-03.sh \
content-04.sh \
leak-01.sh \
leak-02.sh \
leak-03.sh \
leak-04.sh \
leak-05.sh \
leak-06.sh \
leak-07.sh \
leak-08.sh \
leak-09.sh \
leak-10.sh \
leak-11.sh \
leak-12.sh \
leak-13.sh \
leak-14.sh \
leak-15.sh \
leak-16.sh \
leak-17.sh \
redirect-01.sh \
redirect-02.sh \
redirect-03.sh \
pathinfo-01.sh \
pathinfo-02.sh \
broken-key-01.sh \
broken-key-02.sh \
broken-key-03.sh \
broken-key-04.sh \
continue-01.sh \
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
