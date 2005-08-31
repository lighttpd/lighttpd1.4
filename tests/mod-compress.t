#! /usr/bin/perl -w
BEGIN {
    # add current source dir to the include-path
    # we need this for make distcheck
   (my $srcdir = $0) =~ s#/[^/]+$#/#;
   unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 7;
use LightyTest;

my $tf = LightyTest->new();
my $t;
    
ok($tf->start_proc == 0, "Starting lighttpd") or die();

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: deflate
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '' } ];
ok($tf->handle_http($t) == 0, 'Vary is set');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: deflate
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', 'Content-Length' => '1288', '+Content-Encoding' => '' } ];
ok($tf->handle_http($t) == 0, 'deflate - Content-Length and Content-Encoding is set');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: gzip
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', '+Content-Encoding' => '' } ];
ok($tf->handle_http($t) == 0, 'gzip - Content-Length and Content-Encoding is set');

$t->{REQUEST}  = ( <<EOF
GET /index.txt HTTP/1.0
Accept-Encoding: gzip, deflate
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', '+Content-Encoding' => '' } ];
ok($tf->handle_http($t) == 0, 'gzip, deflate - Content-Length and Content-Encoding is set');

$t->{REQUEST}  = ( <<EOF
GET /index.txt HTTP/1.0
Accept-Encoding: gzip, deflate
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', '+Content-Encoding' => '', 'Content-Type' => "text/plain" } ];
ok($tf->handle_http($t) == 0, 'Content-Type is from the original file');


ok($tf->stop_proc == 0, "Stopping lighttpd");
