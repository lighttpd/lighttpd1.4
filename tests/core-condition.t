#!/usr/bin/env perl
BEGIN {
	# add current source dir to the include-path
	# we need this for make distcheck
	(my $srcdir = $0) =~ s,/[^/]+$,/,;
	unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 25;
use LightyTest;

my $tf = LightyTest->new();
my $t;

$ENV{"env_test"} = "good_env";

$tf->{CONFIGFILE} = 'condition.conf';
ok($tf->start_proc == 0, "Starting lighttpd") or die();

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_1" } ];
ok($tf->handle_http($t) == 0, 'config deny');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: test1.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_2" } ];
ok($tf->handle_http($t) == 0, '2nd child of chaining');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: test2.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_3" } ];
ok($tf->handle_http($t) == 0, '3rd child of chaining');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: test3.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_5" } ];
ok($tf->handle_http($t) == 0, 'nesting');

$t->{REQUEST}  = ( <<EOF
GET /subdir/index.html HTTP/1.0
Host: test4.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_7" } ];
ok($tf->handle_http($t) == 0, 'url subdir');

$t->{REQUEST}  = ( <<EOF
GET /subdir/../css/index.html HTTP/1.0
Host: test4.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_6" } ];
ok($tf->handle_http($t) == 0, 'url subdir with path traversal');

$t->{REQUEST}  = ( <<EOF
GET / HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Server' => 'lighttpd-1.4.x' } ];
ok($tf->handle_http($t) == 0, 'condition: handle if before else branches');

$t->{REQUEST}  = ( <<EOF
GET /show/other/server-tag HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Server' => 'special tag' } ];
ok($tf->handle_http($t) == 0, 'condition: handle if before else branches #2');


## config includes

$t->{REQUEST}  = ( "GET /index.html HTTP/1.0\r\nHost: www.example.org\r\n" );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => "/match_1" } ];
ok($tf->handle_http($t) == 0, 'basic test');

my $myvar = "good";
my $server_name = "test.example.org";
my $mystr = "string";
$mystr .= "_append";
my $tests = {
    "include"        => "/good_include",
      "concat"         => "/good_" . "concat",
      "servername1"    => "/good_" . $server_name,
      "servername2"    => $server_name . "/good_",
      "servername3"    => "/good_" . $server_name . "/",
      "var.myvar"      => "/good_var_myvar" . $myvar,
      "myvar"          => "/good_myvar" . $myvar,
      "env"            => "/" . $ENV{"env_test"},

    "number1"        => "/good_number" . "1",
      "number2"        => "1" . "/good_number",
      "array_append"   => "/good_array_append",
      "string_append"  => "/good_" . $mystr,
      "number_append"  => "/good_" . "2",

    "include_shell"  => "/good_include_shell_" . "456"
};

foreach my $test (keys %{ $tests }) {
	my $expect = $tests->{$test};
	$t->{REQUEST}  = ( <<EOF
GET /$test HTTP/1.0
Host: $server_name
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => $expect } ];
	ok($tf->handle_http($t) == 0, $test);
}

ok($tf->stop_proc == 0, "Stopping lighttpd");
