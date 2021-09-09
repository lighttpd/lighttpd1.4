#!/usr/bin/env perl
BEGIN {
	# add current source dir to the include-path
	# we need this for make distcheck
	(my $srcdir = $0) =~ s,/[^/]+$,/,;
	unshift @INC, $srcdir;
}

use strict;
use Test::More tests => 10;
use LightyTest;

my $tf = LightyTest->new();
my $t;

SKIP: {
	skip "no scgi-responder found", 10 unless -x $tf->{BASEDIR}."/tests/scgi-responder" || -x $tf->{BASEDIR}."/tests/scgi-responder.exe";

	my $ephemeral_port = LightyTest->get_ephemeral_tcp_port();
	$ENV{EPHEMERAL_PORT} = $ephemeral_port;

	$tf->{CONFIGFILE} = 'scgi-responder.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();

	$t->{REQUEST}  = ( <<EOF
GET /index.scgi?lf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'line-ending \n\n');

	$t->{REQUEST}  = ( <<EOF
GET /index.scgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'line-ending \r\n\r\n');

	$t->{REQUEST}  = ( <<EOF
GET /index.scgi?slow-lf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'line-ending \n + \n');

	$t->{REQUEST}  = ( <<EOF
GET /index.scgi?slow-crlf HTTP/1.0
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
GET /index.scgi?die-at-end HTTP/1.0
Host: www.example.org
EOF
 );
    }
    else {
	$t->{REQUEST}  = ( <<EOF
GET /index.scgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
    }
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'killing scgi and wait for restart');

	# (might take lighttpd 1 sec to detect backend exit)
	for (my $c = 2*30; $c && 0 == $tf->listening_on($ephemeral_port); --$c) {
		select(undef, undef, undef, 0.05);
	}
	$t->{REQUEST}  = ( <<EOF
GET /index.scgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } ];
	ok($tf->handle_http($t) == 0, 'regular response of after restart');


	ok($tf->stop_proc == 0, "Stopping lighttpd");
}
