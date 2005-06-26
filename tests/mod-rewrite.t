#! /usr/bin/perl -w
BEGIN {
    # add current source dir to the include-path
    # we need this for make distcheck
   (my $srcdir = $0) =~ s#/[^/]+$#/#;
   unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 5;
use LightyTest;

my $tf = LightyTest->new();
my $t;
   

SKIP: {
	skip "no PHP running on port 1026", 5 if $tf->pidof("php") == -1; 

	ok($tf->start_proc == 0, "Starting lighttpd") or die();

	$t->{REQUEST}  = ( <<EOF
GET /rewrite/foo HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '' } );
	ok($tf->handle_http($t) == 0, 'valid request');
    
	$t->{REQUEST}  = ( <<EOF
GET /rewrite/foo?a=b HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'a=b' } );
	ok($tf->handle_http($t) == 0, 'valid request');

	$t->{REQUEST}  = ( <<EOF
GET /rewrite/bar?a=b HTTP/1.0
Host: www.example.org
EOF
 );
	$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'bar&a=b' } );
	ok($tf->handle_http($t) == 0, 'valid request');

	ok($tf->stop_proc == 0, "Stopping lighttpd");
}
