#! /usr/bin/perl -w

use strict;
use IO::Socket;
use Test::More tests => 3;
use LightyTest;

my $tf = LightyTest->new();
my $t;
    
ok($tf->start_proc == 0, "Starting lighttpd") or die();

$t->{REQUEST}  = ( <<EOF
GET /index.html~ HTTP/1.0
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } );
ok($tf->handle_http($t) == 0, 'forbid access to ...~');

ok($tf->stop_proc == 0, "Stopping lighttpd");

