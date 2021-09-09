#!/usr/bin/env perl
BEGIN {
	# add current source dir to the include-path
	# we need this for make distcheck
	(my $srcdir = $0) =~ s,/[^/]+$,/,;
	unshift @INC, $srcdir;
}

use strict;
use Test::More tests => 24;
use LightyTest;

my $tf = LightyTest->new();

my $t;

SKIP: {
	skip "no fcgi-responder found", 24
	  unless (   -x $tf->{BASEDIR}."/tests/fcgi-responder"
		  || -x $tf->{BASEDIR}."/tests/fcgi-responder.exe");

	my $ephemeral_port = LightyTest->get_ephemeral_tcp_port();
	$ENV{EPHEMERAL_PORT} = $ephemeral_port;

	$tf->{CONFIGFILE} = 'fastcgi-responder.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();

	$t->{REQUEST}  = ( <<EOF
GET /prefix.fcgi-nonexistent HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } ];
	ok($tf->handle_http($t) == 0, 'file not found');

	$t->{REQUEST}  = ( <<EOF
GET /prefix.fcgi?env=SCRIPT_NAME HTTP/1.0
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/prefix.fcgi' } ];
	ok($tf->handle_http($t) == 0, 'SCRIPT_NAME');

	$t->{REQUEST}  = ( <<EOF
GET /prefix.fcgi/foo/bar?env=SCRIPT_NAME HTTP/1.0
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/prefix.fcgi' } ];
	ok($tf->handle_http($t) == 0, 'SCRIPT_NAME w/ PATH_INFO');

	$t->{REQUEST}  = ( <<EOF
GET /prefix.fcgi/foo/bar?env=PATH_INFO HTTP/1.0
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/foo/bar' } ];
	ok($tf->handle_http($t) == 0, 'PATH_INFO');

	$t->{REQUEST} = ( <<EOF
GET /phpinfo.php HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
	ok($tf->handle_http($t) == 0, 'valid request');

	$t->{REQUEST}  = ( <<EOF
GET /get-server-env.php?env=USER HTTP/1.0
Host: bin-env.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 , 'HTTP-Content' => $ENV{USER} } ];
	ok($tf->handle_http($t) == 0, 'FastCGI + bin-copy-environment');

	$t->{REQUEST}  = ( <<EOF
GET /get-server-env.php?env=MAIL HTTP/1.0
Host: bin-env.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 , 'HTTP-Content' => '' } ];
	ok($tf->handle_http($t) == 0, 'FastCGI + bin-copy-environment');

SKIP: {
	skip "no crypt-des under openbsd", 2 if $^O eq 'openbsd';

	$t->{REQUEST}  = ( <<EOF
GET /get-server-env.php?env=REMOTE_USER HTTP/1.0
Host: auth.example.org
Authorization: Basic ZGVzOmRlcw==
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'des' } ];
	ok($tf->handle_http($t) == 0, '$_SERVER["REMOTE_USER"]');

	$t->{REQUEST}  = ( <<EOF
GET /get-server-env.php?env=AUTH_TYPE HTTP/1.0
Host: auth.example.org
Authorization: Basic ZGVzOmRlcw==
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'Basic' } ];
	ok($tf->handle_http($t) == 0, '$_SERVER["AUTH_TYPE"]');
}

	$t->{REQUEST}  = ( <<EOF
GET /index.html?auth-ok HTTP/1.0
Host: auth.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
	ok($tf->handle_http($t) == 0, 'FastCGI - Auth');

	$t->{REQUEST}  = ( <<EOF
GET /index.html?auth-fail HTTP/1.0
Host: auth.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
	ok($tf->handle_http($t) == 0, 'FastCGI - Auth');

	$t->{REQUEST}  = ( <<EOF
GET /expire/access.txt?auth-ok HTTP/1.0
Host: auth.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
	ok($tf->handle_http($t) == 0, 'FastCGI - Auth in subdirectory');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?auth-varfail HTTP/1.0
Host: auth.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
	ok($tf->handle_http($t) == 0, 'FastCGI - Auth Fail with FastCGI responder afterwards');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?auth-var HTTP/1.0
Host: auth.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'LighttpdTestContent' } ];
	ok($tf->handle_http($t) == 0, 'FastCGI - Auth Success with Variable- to Env expansion');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?lf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'line-ending \n\n');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'line-ending \r\n\r\n');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?slow-lf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'line-ending \n + \n');

	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?slow-crlf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'line-ending \r\n + \r\n');

	$t->{REQUEST}  = ( <<EOF
GET /abc/def/ghi?env=PATH_INFO HTTP/1.0
Host: wsgi.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/abc/def/ghi' } ];
	ok($tf->handle_http($t) == 0, 'PATH_INFO (wsgi)');

	$t->{REQUEST}  = ( <<EOF
GET /abc/def/ghi?env=SCRIPT_NAME HTTP/1.0
Host: wsgi.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '' } ];
	ok($tf->handle_http($t) == 0, 'SCRIPT_NAME (wsgi)');


    # skip timing-sensitive test during CI testing, but run for user 'gps'
    my $user = `id -un`;
    chomp($user) if $user;
    if (($user || "") eq "gps") {
	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?die-at-end HTTP/1.0
Host: www.example.org
EOF
 );
    }
    else {
	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
    }
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'killing fastcgi and wait for restart');

	# (might take lighttpd 1 sec to detect backend exit)
	for (my $c = 2*30; $c && 0 == $tf->listening_on($ephemeral_port); --$c) {
		select(undef, undef, undef, 0.05);
	}
	$t->{REQUEST}  = ( <<EOF
GET /index.fcgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'regular response of after restart');


	ok($tf->stop_proc == 0, "Stopping lighttpd");
}
