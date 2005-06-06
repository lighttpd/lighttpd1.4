dist_man1_MANS=lighttpd.1 spawn-fcgi.1


DOCS=accesslog.txt \
authentication.txt \
cgi.txt \
compress.txt \
configuration.txt \
fastcgi-state.txt \
fastcgi.txt \
features.txt \
performance.txt \
plugins.txt \
proxy.txt \
redirect.txt \
rewrite.txt \
secdownload.txt \
security.txt \
simple-vhost.txt \
skeleton.txt \
ssi.txt \
ssl.txt \
state.txt \
rrdtool.txt \
alias.txt \
userdir.txt \
mysqlvhost.txt \
access.txt \
traffic-shaping.txt \
setenv.txt \
status.txt

HTMLDOCS=accesslog.html \
	 authentication.html \
	 cgi.html \
	 compress.html \
	 configuration.html \
	 fastcgi-state.html \
	 fastcgi.html \
	 features.html \
	 performance.html \
	 plugins.html \
	 proxy.html \
	 redirect.html \
	 rewrite.html \
	 secdownload.html \
	 security.html \
	 simple-vhost.html \
	 skeleton.html \
	 ssi.html \
	 ssl.html \
	 state.html \
	 rrdtool.html \
	 alias.html \
	 userdir.html \
	 mysqlvhost.html \
	 access.html \
	 traffic-shaping.html \
	 setenv.html \
	 status.html

EXTRA_DIST=lighttpd.conf lighttpd.user \
	rc.lighttpd rc.lighttpd.redhat sysconfig.lighttpd \
	rrdtool-graph.sh \
	state.dot fastcgi-state.dot \
	spawn-php.sh \
	newstyle.css \
	oldstyle.css \
	$(DOCS)
 
%.html: %.txt
	rst2html.py $^ > $@


html: $(HTMLDOCS)

#%.ps.gz: %.ps
#	gzip $^
	
#%.ps: %.dot
#	dot -Tps -o $@ $^   

clean-local:
	rm -f *.html

	
