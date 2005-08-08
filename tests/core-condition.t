#! /usr/bin/perl -w
BEGIN {
    # add current source dir to the include-path
    # we need this for make distcheck
   (my $srcdir = $0) =~ s#/[^/]+$#/#;
   unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 6;
use LightyTest;

my $tf = LightyTest->new();
my $t;

$tf->{CONFIGFILE} = 'condition.conf';
ok($tf->start_proc == 0, "Starting lighttpd") or die();

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_1" } );
ok($tf->handle_http($t) == 0, 'config deny');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: test1.example.org
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_2" } );
ok($tf->handle_http($t) == 0, '2nd child of chaining');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: test2.example.org
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_3" } );
ok($tf->handle_http($t) == 0, '3rd child of chaining');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: test3.example.org
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_5" } );
ok($tf->handle_http($t) == 0, 'nesting');

ok($tf->stop_proc == 0, "Stopping lighttpd");

