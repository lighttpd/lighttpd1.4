#! /usr/bin/perl -w

use strict;
use IO::Socket;
use Test::More tests => 3;
use LightyTest;

my $tf = LightyTest->new();
my $t;
    
ok($tf->start_proc == 0, "Starting lighttpd") or die();

$t->{REQUEST}  = ( <<EOF
GET /redirect/ HTTP/1.0
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => 'http://localhost:2048/' } );
ok($tf->handle_http($t) == 0, 'external redirect');


ok($tf->stop_proc == 0, "Stopping lighttpd");

