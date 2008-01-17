#!/usr/bin/env perl
BEGIN {
	# add current source dir to the include-path
	# we need this for make distcheck
	(my $srcdir = $0) =~ s,/[^/]+$,/,;
	unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 2;
use LightyTest;

my $tf = LightyTest->new();
my $t;

$tf->{CONFIGFILE} = 'mod-extforward.conf';

ok($tf->start_proc == 0, "Starting lighttpd") or die();

## check if If-Modified-Since, If-None-Match works

$t->{REQUEST} = ( <<EOF
GET /ip.pl HTTP/1.0
Host: www.example.org
X-Forwarded-For: 127.0.10.1
EOF
);
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '127.0.10.1' } ];
ok($tf->handle_http($t) == 0, 'expect 127.0.10.1');

$t->{REQUEST} = ( <<EOF
GET /ip.pl HTTP/1.0
Host: www.example.org
X-Forwarded-For: 127.0.10.1, 127.0.20.1
EOF
);
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '127.0.20.1' } ];
ok($tf->handle_http($t) == 0, 'expect 127.0.20.1');

ok($tf->stop_proc == 0, "Stopping lighttpd");
