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

my $tf_real = LightyTest->new();
my $tf_proxy = LightyTest->new();

my $t;

## we need two procs
## 1. the real webserver
## 2. the proxy server

$tf_real->{PORT} = 2048;
$tf_real->{CONFIGFILE} = 'lighttpd.conf';
$tf_real->{LIGHTTPD_PIDFILE} = '/tmp/lighttpd/lighttpd.pid';

$tf_proxy->{PORT} = 2050;
$tf_proxy->{CONFIGFILE} = 'proxy.conf';
$tf_proxy->{LIGHTTPD_PIDFILE} = '/tmp/lighttpd/lighttpd-proxy.pid';

ok($tf_real->start_proc == 0, "Starting lighttpd") or die();

ok($tf_proxy->start_proc == 0, "Starting lighttpd as proxy") or die();

$t->{REQUEST}  = ( <<EOF
GET /phpinfo.php HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok($tf_proxy->handle_http($t) == 0, 'valid request');

ok($tf_proxy->stop_proc == 0, "Stopping lighttpd proxy");

ok($tf_real->stop_proc == 0, "Stopping lighttpd");
