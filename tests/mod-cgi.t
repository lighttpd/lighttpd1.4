#!/usr/bin/env perl
BEGIN {
	# add current source dir to the include-path
	# we need this for make distcheck
	(my $srcdir = $0) =~ s,/[^/]+$,/,;
	unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 23;
use LightyTest;

my $tf = LightyTest->new();
my $t;

ok($tf->start_proc == 0, "Starting lighttpd") or die();

# mod-cgi
#
$t->{REQUEST}  = ( <<EOF
GET /cgi.pl HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'perl via cgi');

if ($^O ne "cygwin") {
    $t->{REQUEST}  = ( <<EOF
GET /cgi.pl%20%20%20 HTTP/1.0
EOF
 );
    $t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } ];
    ok($tf->handle_http($t) == 0, 'No source retrieval');
} else {
    ok(1, 'No source retrieval; skipped on cygwin; see response.c');
}

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl/foo?env=SCRIPT_NAME HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/cgi.pl' } ];
ok($tf->handle_http($t) == 0, 'perl via cgi + pathinfo');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?internal-redir HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'perl via cgi and internal redirect from CGI');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?xsendfile HTTP/1.0
Host: cgi.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Length' => 4348 } ];
ok($tf->handle_http($t) == 0, 'X-Sendfile');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?external-redir HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 302, 'Location' => 'http://www.example.org:2048/' } ];
ok($tf->handle_http($t) == 0, 'Status + Location via FastCGI');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl/?external-redir HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 302, 'Location' => 'http://www.example.org:2048/' } ];
ok($tf->handle_http($t) == 0, 'Trailing slash as path-info (#1989: workaround broken operating systems)');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?nph=30 HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 502 } ];
ok($tf->handle_http($t) == 0, 'NPH + perl, invalid status-code (#14)');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?nph=304 HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 304 } ];
ok($tf->handle_http($t) == 0, 'NPH + perl, setting status-code (#1125)');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?nph=200 HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'NPH + perl, setting status-code');

$t->{REQUEST} = ( <<EOF
GET /cgi.pl?env=GATEWAY_INTERFACE HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'CGI/1.1' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: GATEWAY_INTERFACE');

$t->{REQUEST} = ( <<EOF
GET /cgi.pl?query_string HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'query_string', 'Content-Type' => 'text/plain' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: QUERY_STRING');

$t->{REQUEST} = ( <<EOF
GET /cgi.pl?env=SCRIPT_NAME HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/cgi.pl' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: SCRIPT_NAME');

$t->{REQUEST} = ( <<EOF
GET /cgi.pl/path/info?env=SCRIPT_NAME HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/cgi.pl' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: SCRIPT_NAME w/ PATH_INFO');

$t->{REQUEST} = ( <<EOF
GET /cgi.pl/path/info?env=PATH_INFO HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/path/info' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: PATH_INFO');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=HTTP_XX_YY123 HTTP/1.0
xx-yy123: foo
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'foo' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: quoting headers with numbers');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=HTTP_HOST HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: HTTP_HOST');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=HTTP_HOST HTTP/1.1
Host: www.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, '+Content-Length' => '' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: HTTP_HOST');

# broken header crash
$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?crlfcrash HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 302, 'Location' => 'http://www.example.org/' } ];
ok($tf->handle_http($t) == 0, 'broken header via perl cgi');

$t->{REQUEST}  = ( <<EOF
GET /indexfile/ HTTP/1.0
Host: cgi.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/indexfile/index.pl' } ];
ok($tf->handle_http($t) == 0, 'index-file handling, Bug #3, Bug #6');

$t->{REQUEST}  = ( <<EOF
POST /indexfile/abc HTTP/1.0
Host: cgi.example.org
Content-Length: 0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404, 'HTTP-Content' => '/indexfile/index.pl' } ];
ok($tf->handle_http($t) == 0, 'server.error-handler-404, Bug #12');


ok($tf->stop_proc == 0, "Stopping lighttpd");

