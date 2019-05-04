#!/usr/bin/env perl
BEGIN {
	# add current source dir to the include-path
	# we need this for make distcheck
	(my $srcdir = $0) =~ s,/[^/]+$,/,;
	unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 12;
use LightyTest;

my $tf = LightyTest->new();
my $t;

ok($tf->start_proc == 0, "Starting lighttpd") or die();


$t->{REQUEST}  = ( <<EOF
GET / HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Valid HTTP/1.0 Request') or die();

$t->{REQUEST}  = ( <<EOF
OPTIONS * HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'OPTIONS');

$t->{REQUEST}  = ( <<EOF
OPTIONS / HTTP/1.1
Host: www.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'OPTIONS');


## Low-Level Request-Header Parsing - URI

$t->{REQUEST}  = ( <<EOF
GET /index%2ehtml HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'URL-encoding');

$t->{REQUEST}  = ( <<EOF
GET /index.html%00 HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'URL-encoding, %00');

$t->{REQUEST}  = ( <<EOF
POST /12345.txt HTTP/1.0
Host: 123.example.org
Content-Length: 2147483648
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 413 } ];
ok($tf->handle_http($t) == 0, 'Content-Length > max-request-size');


print "\nContent-Type\n";
$t->{REQUEST}  = ( <<EOF
GET /image.jpg HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Type' => 'image/jpeg' } ];
ok($tf->handle_http($t) == 0, 'Content-Type - image/jpeg');

$t->{REQUEST}  = ( <<EOF
GET /image.JPG HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Type' => 'image/jpeg' } ];
ok($tf->handle_http($t) == 0, 'Content-Type - image/jpeg (upper case)');

$t->{REQUEST}  = ( <<EOF
GET /a HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Type' => 'application/octet-stream' } ];
ok($tf->handle_http($t) == 0, 'Content-Type - unknown');

$t->{REQUEST}  = ( <<EOF
GET /Foo.txt HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'uppercase filenames');


ok($tf->stop_proc == 0, "Stopping lighttpd");
