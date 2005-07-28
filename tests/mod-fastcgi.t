#! /usr/bin/perl -w
BEGIN {
    # add current source dir to the include-path
    # we need this for make distcheck
   (my $srcdir = $0) =~ s#/[^/]+$#/#;
   unshift @INC, $srcdir;
}

use strict;
use Test::More tests => 43;
use LightyTest;

my $tf = LightyTest->new();

my $t;

SKIP: {
	skip "no PHP running on port 1026", 27 if $tf->pidof("php") == -1; 

	ok($tf->start_proc == 0, "Starting lighttpd") or die();

	$t->{REQUEST} = ( <<EOF
GET /phpinfo.php HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok($tf->handle_http($t) == 0, 'valid request');

	$t->{REQUEST}  = ( <<EOF
GET /phpinfofoobar.php HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } );
	ok($tf->handle_http($t) == 0, 'file not found');

	$t->{REQUEST}  = ( <<EOF
GET /go/ HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok($tf->handle_http($t) == 0, 'index-file handling');

	$t->{REQUEST}  = ( <<EOF
GET /redirect.php HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 302, 'Location' => 'http://www.example.org:2048/' } );
	ok($tf->handle_http($t) == 0, 'Status + Location via FastCGI');

	$t->{REQUEST}  = ( <<EOF
GET /phpself.php HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok($tf->handle_http($t) == 0, '$_SERVER["PHP_SELF"]');

	$t->{REQUEST}  = ( <<EOF
GET /phpself.php/foo HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/phpself.php' } );
	ok($tf->handle_http($t) == 0, '$_SERVER["PHP_SELF"]');

	$t->{REQUEST}  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
	ok($tf->handle_http($t) == 0, 'SERVER_NAME');

	$t->{REQUEST}  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: foo.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
	ok($tf->handle_http($t) == 0, 'SERVER_NAME');

	$t->{REQUEST}  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: vvv.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
	ok($tf->handle_http($t) == 0, 'SERVER_NAME');

	$t->{REQUEST}  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: zzz.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
	ok($tf->handle_http($t) == 0, 'SERVER_NAME');

	$t->{REQUEST}  = ( <<EOF
GET /cgi.php/abc HTTP/1.0
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok($tf->handle_http($t) == 0, 'PATHINFO');

	$t->{REQUEST}  = ( <<EOF
GET /www/abc/def HTTP/1.0
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } );
	ok($tf->handle_http($t) == 0, 'PATHINFO on a directory');

	$t->{REQUEST}  = ( <<EOF
GET /indexfile/ HTTP/1.0
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/indexfile/index.php' } );
	ok($tf->handle_http($t) == 0, 'PHP_SELF + Indexfile, Bug #3');

	$t->{REQUEST}  = ( <<EOF
GET /prefix.fcgi?var=SCRIPT_NAME HTTP/1.0
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/prefix.fcgi' } );
	ok($tf->handle_http($t) == 0, 'PATH_INFO, check-local off');

	$t->{REQUEST}  = ( <<EOF
GET /prefix.fcgi/foo/bar?var=SCRIPT_NAME HTTP/1.0
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/prefix.fcgi' } );
	ok($tf->handle_http($t) == 0, 'PATH_INFO, check-local off');

	$t->{REQUEST}  = ( <<EOF
GET /prefix.fcgi/foo/bar?var=PATH_INFO HTTP/1.0
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/foo/bar' } );
	ok($tf->handle_http($t) == 0, 'PATH_INFO, check-local off');

	
	ok($tf->stop_proc == 0, "Stopping lighttpd");


	$tf->{CONFIGFILE} = 'fastcgi-10.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();
	$t->{REQUEST}  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: zzz.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'zzz.example.org' } );
	ok($tf->handle_http($t) == 0, 'FastCGI + Host');

	ok($tf->stop_proc == 0, "Stopping lighttpd");
	
	$tf->{CONFIGFILE} = 'bug-06.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();
	$t->{REQUEST}  = ( <<EOF
GET /indexfile/ HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/indexfile/index.php' } );
	ok($tf->handle_http($t) == 0, 'Bug #6');

	ok($tf->stop_proc == 0, "Stopping lighttpd");

	$tf->{CONFIGFILE} = 'bug-12.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with bug-12.conf") or die();
	$t->{REQUEST}  = ( <<EOF
POST /indexfile/abc HTTP/1.0
Host: www.example.org
Content-Length: 0
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404, 'HTTP-Content' => '/indexfile/return-404.php' } );
	ok($tf->handle_http($t) == 0, 'Bug #12');

	ok($tf->stop_proc == 0, "Stopping lighttpd");
}

SKIP: {
	skip "no fcgi-auth found", 4 unless -x $tf->{BASEDIR}."/tests/fcgi-auth" || -x $tf->{BASEDIR}."/tests/fcgi-auth.exe"; 

	$tf->{CONFIGFILE} = 'fastcgi-auth.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();
	$t->{REQUEST}  = ( <<EOF
GET /index.html?ok HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok($tf->handle_http($t) == 0, 'FastCGI - Auth');

	$t->{REQUEST}  = ( <<EOF
GET /index.html?fail HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } );
	ok($tf->handle_http($t) == 0, 'FastCGI - Auth');

	ok($tf->stop_proc == 0, "Stopping lighttpd");
}

SKIP: {
	skip "no php found", 3 unless -x "/home/weigon/Documents/php-4.3.10/sapi/cgi/php"; 
	$tf->{CONFIGFILE} = 'fastcgi-13.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();
	$t->{REQUEST}  = ( <<EOF
GET /indexfile/index.php HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok($tf->handle_http($t) == 0, 'FastCGI + local spawning');

	ok($tf->stop_proc == 0, "Stopping lighttpd");
}


SKIP: {
	skip "no fcgi-responder found", 9 unless -x $tf->{BASEDIR}."/tests/fcgi-responder" || -x $tf->{BASEDIR}."/tests/fcgi-responder.exe"; 
	
	$tf->{CONFIGFILE} = 'fastcgi-responder.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();
	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?lf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
	ok($tf->handle_http($t) == 0, 'line-ending \n\n');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
	ok($tf->handle_http($t) == 0, 'line-ending \r\n\r\n');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?slow-lf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
	ok($tf->handle_http($t) == 0, 'line-ending \n + \n');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?slow-crlf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
	ok($tf->handle_http($t) == 0, 'line-ending \r\n + \r\n');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?die-at-end HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
	ok($tf->handle_http($t) == 0, 'killing fastcgi and wait for restart');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?die-at-end HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
	ok($tf->handle_http($t) == 0, 'killing fastcgi and wait for restart');


	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
	ok($tf->handle_http($t) == 0, 'regular response of after restart');


	ok($tf->stop_proc == 0, "Stopping lighttpd");
}

