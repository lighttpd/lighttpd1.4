#!/usr/bin/env perl
BEGIN {
	# add current source dir to the include-path
	# we need this for make distcheck
	(my $srcdir = $0) =~ s,/[^/]+$,/,;
	unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 164;
use LightyTest;

my $tf = LightyTest->new();
my $t;

ok($tf->start_proc == 0, "Starting lighttpd") or die();

## Basic Request-Handling

$t->{REQUEST}  = ( <<EOF
GET / HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Valid HTTP/1.0 Request') or ($tf->stop_proc, die());

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
GET /Foo.txt HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'uppercase filenames');

$t->{REQUEST}  = ( <<EOF
GET /foobar?foobar HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } ];
ok($tf->handle_http($t) == 0, 'file not found + querystring');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/plain' } ];
ok($tf->handle_http($t) == 0, 'GET, content == 12345, mimetype text/plain');

$t->{REQUEST}  = ( <<EOF
GET /12345.html HTTP/1.0
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/html' } ];
ok($tf->handle_http($t) == 0, 'GET, content == 12345, mimetype text/html');


$t->{REQUEST}  = ( <<EOF
POST / HTTP/1.0
Content-type: application/x-www-form-urlencoded
Content-length: 0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'POST request, empty request-body');

$t->{REQUEST}  = ( <<EOF
HEAD / HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '-HTTP-Content' => ''} ];
ok($tf->handle_http($t) == 0, 'HEAD request, no content');

$t->{REQUEST}  = ( <<EOF
HEAD /12345.html HTTP/1.0
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '-HTTP-Content' => '', 'Content-Type' => 'text/html', 'Content-Length' => '6'} ];
ok($tf->handle_http($t) == 0, 'HEAD request, mimetype text/html, content-length');

$t->{REQUEST}  = ( <<EOF
HEAD http://123.example.org/12345.html HTTP/1.1
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, '-HTTP-Content' => '', 'Content-Type' => 'text/html', 'Content-Length' => '6'} ];
ok($tf->handle_http($t) == 0, 'Hostname in first line, HTTP/1.1');

$t->{REQUEST}  = ( <<EOF
HEAD https://123.example.org/12345.html HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '-HTTP-Content' => '', 'Content-Type' => 'text/html', 'Content-Length' => '6'} ];
ok($tf->handle_http($t) == 0, 'Hostname in first line as https url');

$t->{REQUEST}  = ( <<EOF
HEAD /foobar?foobar HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404, '-HTTP-Content' => '' } ];
ok($tf->handle_http($t) == 0, 'HEAD request, file-not-found, query-string');

# (expect 200 OK instead of 100 Continue since request body sent with request)
# (if we waited to send request body, would expect 100 Continue, first)
$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Expect: 100-continue

123
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Continue, Expect');

# note Transfer-Encoding: chunked tests will fail with 411 Length Required if
#   server.stream-request-body != 0 in lighttpd.conf
$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

a
0123456789
0

EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'POST via Transfer-Encoding: chunked, lc hex');

$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

A
0123456789
0

EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'POST via Transfer-Encoding: chunked, uc hex');

$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

10
0123456789abcdef
0

EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'POST via Transfer-Encoding: chunked, two hex');

$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

a
0123456789
0
Test-Trailer: testing

EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'POST via Transfer-Encoding: chunked, with trailer');

$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

a; comment
0123456789
0

EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'POST via Transfer-Encoding: chunked, chunked header comment');

$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

az
0123456789
0

EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'POST via Transfer-Encoding: chunked; bad chunked header');

$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

a
0123456789xxxxxxxx
0

EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'POST via Transfer-Encoding: chunked; mismatch chunked header size and chunked data size');

$t->{REQUEST}  = ( <<EOF
POST /cgi.pl?post-len HTTP/1.1
Host: www.example.org
Connection: close
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

a ; xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
0123456789
0

EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'POST via Transfer-Encoding: chunked; chunked header too long');

## ranges

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=0-3
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 206, 'HTTP-Content' => '1234' } ];
ok($tf->handle_http($t) == 0, 'GET, Range 0-3');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=-3
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 206, 'HTTP-Content' => '45'."\n" } ];
ok($tf->handle_http($t) == 0, 'GET, Range -3');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=3-
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 206, 'HTTP-Content' => '45'."\n" } ];
ok($tf->handle_http($t) == 0, 'GET, Range 3-');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=0-1,3-4
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 206, 'HTTP-Content' => '12345' } ];
ok($tf->handle_http($t) == 0, 'GET, Range 0-1,3-4 (ranges merged)');

$t->{REQUEST}  = ( <<EOF
GET /100.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=0-1,97-98
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 206, 'HTTP-Content' => <<EOF
--fkj49sn38dcn3\r
Content-Type: text/plain\r
Content-Range: bytes 0-1/100\r
\r
12\r
--fkj49sn38dcn3\r
Content-Type: text/plain\r
Content-Range: bytes 97-98/100\r
\r
hi\r
--fkj49sn38dcn3--\r
EOF
 } ];
ok($tf->handle_http($t) == 0, 'GET, Range 0-1,97-98 (ranges not merged)');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=0-
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 206, 'Content-Range' => 'bytes 0-5/6' } ];
ok($tf->handle_http($t) == 0, 'GET, Range 0-');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=0--
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 416 } ];
ok($tf->handle_http($t) == 0, 'GET, Range 0--');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=-2-3
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 416 } ];
ok($tf->handle_http($t) == 0, 'GET, Range -2-3');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=-0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 416, 'HTTP-Content' => <<EOF
<!DOCTYPE html>
<html lang="en">
 <head>
  <meta charset="UTF-8" />
  <title>416 Range Not Satisfiable</title>
 </head>
 <body>
  <h1>416 Range Not Satisfiable</h1>
 </body>
</html>
EOF
 } ];
ok($tf->handle_http($t) == 0, 'GET, Range -0');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=25-
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 416, 'HTTP-Content' => <<EOF
<!DOCTYPE html>
<html lang="en">
 <head>
  <meta charset="UTF-8" />
  <title>416 Range Not Satisfiable</title>
 </head>
 <body>
  <h1>416 Range Not Satisfiable</h1>
 </body>
</html>
EOF
 } ];

ok($tf->handle_http($t) == 0, 'GET, Range start out of range');


$t->{REQUEST}  = ( <<EOF
GET /range.disabled HTTP/1.1
Host: 123.example.org
Range: bytes=0-
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'GET, Range with range-requests-disabled');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: 0
Range: bytes=0-3
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, 'HTTP-Content' => "12345\n" } ];
ok($tf->handle_http($t) == 0, 'GET, Range invalid range-unit (first)');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
Range: bytes=0-3
Range: 0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 206 } ];
ok($tf->handle_http($t) == 0, 'GET, Range ignore invalid range (second)');

$t->{REQUEST}  = ( <<EOF
OPTIONS / HTTP/1.0
Content-Length: 4

1234
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'OPTIONS with Content-Length');

$t->{REQUEST}  = ( <<EOF
OPTIONS rtsp://221.192.134.146:80 RTSP/1.1
Host: 221.192.134.146:80
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'OPTIONS for RTSP');

my $nextyr = (gmtime(time()))[5] + 1900 + 1;

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
If-Modified-Since2: Sun, 01 Jan $nextyr 00:00:03 GMT
If-Modified-Since: Sun, 01 Jan $nextyr 00:00:02 GMT
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 304 } ];
ok($tf->handle_http($t) == 0, 'Similar Headers (bug #1287)');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
If-Modified-Since: Sun, 01 Jan $nextyr 00:00:02 GMT
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 304, '-Content-Length' => '', 'Content-Type' => 'text/html' } ];
ok($tf->handle_http($t) == 0, 'Status 304 has no Content-Length (#1002)');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/plain' } ];
$t->{SLOWREQUEST} = 1;
ok($tf->handle_http($t) == 0, 'GET, slow \\r\\n\\r\\n (#2105)');
undef $t->{SLOWREQUEST};

$t->{REQUEST}  = ( <<EOF
GET /www/abc/def HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } ];
ok($tf->handle_http($t) == 0, 'pathinfo on a directory');


$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Connection: ,close
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/plain', 'Connection' => 'close' } ];
ok($tf->handle_http($t) == 0, 'Connection-header, leading comma');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Connection: close,,TE
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/plain', 'Connection' => 'close' } ];
ok($tf->handle_http($t) == 0, 'Connection-header, no value between two commas');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Connection: close, ,TE
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/plain', 'Connection' => 'close' } ];
ok($tf->handle_http($t) == 0, 'Connection-header, space between two commas');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Connection: close,
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/plain', 'Connection' => 'close' } ];
ok($tf->handle_http($t) == 0, 'Connection-header, comma after value');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.1
Connection: close, 
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/plain', 'Connection' => 'close' } ];
ok($tf->handle_http($t) == 0, 'Connection-header, comma and space after value');


## Low-Level Response-Header Parsing - HTTP/1.1

$t->{REQUEST}  = ( <<EOF
GET / HTTP/1.1
Host: www.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, '+Date' => '' } ];
ok($tf->handle_http($t) == 0, 'Date header');


## Low-Level Response-Header Parsing - Content-Length


$t->{REQUEST}  = ( <<EOF
GET /12345.html HTTP/1.0
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Length' => '6' } ];
ok($tf->handle_http($t) == 0, 'Content-Length for text/html');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Length' => '6' } ];
ok($tf->handle_http($t) == 0, 'Content-Length for text/plain');


## Low-Level Response-Header Parsing - Location

$t->{REQUEST}  = ( <<EOF
GET /subdir HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => '/subdir/' } ];
ok($tf->handle_http($t) == 0, 'internal redirect in directory');

$t->{REQUEST}  = ( <<EOF
GET /subdir?foo HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => '/subdir/?foo' } ];
ok($tf->handle_http($t) == 0, 'internal redirect in directory + querystring');

$t->{REQUEST}  = ( <<EOF
GET /~test%20ä_ HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => '/~test%20%C3%A4_/' } ];
ok($tf->handle_http($t) == 0, 'internal redirect in directory with special characters');

$t->{REQUEST}  = ( <<EOF
GET /~test%20ä_?foo HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => '/~test%20%C3%A4_/?foo' } ];
ok($tf->handle_http($t) == 0, 'internal redirect in directory with special characters + querystring');


## simple-vhost

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: no-simple.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Length' => '6' } ];
ok($tf->handle_http($t) == 0, 'disabling simple-vhost via conditionals');

$t->{REQUEST}  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: simple.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } ];
ok($tf->handle_http($t) == 0, 'simple-vhost via conditionals');


## keep-alive

$t->{REQUEST} = ( <<EOF
GET /12345.txt HTTP/1.0
Connection: keep-alive
Host: 123.example.org

GET /12345.txt HTTP/1.0
Host: 123.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } , { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Explicit HTTP/1.0 Keep-Alive');
undef $t->{RESPONSE};

$t->{REQUEST} = ( <<EOF
GET /12345.txt HTTP/1.0
Connection: keep-alive
Host: 123.example.org

GET /12345.txt HTTP/1.0
Host: 123.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } , { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Explicit HTTP/1.0 Keep-Alive');
undef $t->{RESPONSE};

$t->{REQUEST} = ( <<EOF
GET /12345.txt HTTP/1.0
Connection: keep-alive
Host: 123.example.org

GET /12345.txt HTTP/1.0
Host: 123.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } , { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Implicit HTTP/1.0 Keep-Alive');

$t->{REQUEST} = ( <<EOF
GET /12345.txt HTTP/1.1
Connection: keep-alive
Host: 123.example.org

GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } , { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Explicit HTTP/1.1 Keep-Alive');

$t->{REQUEST} = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org

GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } , { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Implicit HTTP/1.1 Keep-Alive');

$t->{REQUEST} = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org


GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } , { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Implicit HTTP/1.1 Keep-Alive w/ extra blank b/w requests');

$t->{REQUEST} = ( <<EOF
GET /12345.txt HTTP/1.1
Host: 123.example.org



GET /12345.txt HTTP/1.1
Host: 123.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200 } , { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'Implicit HTTP/1.1 Keep-Alive w/ excess blank b/w requests');


## 404 handlers

$t->{REQUEST}  = ( <<EOF
GET /static/notfound HTTP/1.0
Host: errors.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => "static not found\n" } ];
ok($tf->handle_http($t) == 0, '404 handler => static');

$t->{REQUEST}  = ( <<EOF
GET /dynamic/200/notfound HTTP/1.0
Host: errors.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => "found here\n" } ];
ok($tf->handle_http($t) == 0, '404 handler => dynamic(200)');

$t->{REQUEST}  = ( <<EOF
GET /dynamic/302/notfound HTTP/1.0
Host: errors.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 302, 'Location' => "http://www.example.org/" } ];
ok($tf->handle_http($t) == 0, '404 handler => dynamic(302)');

$t->{REQUEST}  = ( <<EOF
GET /dynamic/404/notfound HTTP/1.0
Host: errors.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404, 'HTTP-Content' => "Not found here\n" } ];
ok($tf->handle_http($t) == 0, '404 handler => dynamic(404)');

$t->{REQUEST}  = ( <<EOF
GET /dynamic/redirect_status/ HTTP/1.0
Host: errors.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404, 'HTTP-Content' => "REDIRECT_STATUS\n" } ];
ok($tf->handle_http($t) == 0, 'error handler => dynamic(REDIRECT_STATUS)');

$t->{REQUEST}  = ( <<EOF
GET /dynamic/nostatus/notfound HTTP/1.0
Host: errors.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => "found here\n" } ];
ok($tf->handle_http($t) == 0, '404 handler => dynamic(nostatus)');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?send404 HTTP/1.0
Host: errors.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404, 'HTTP-Content' => "send404\n" } ];
ok($tf->handle_http($t) == 0, '404 generated by CGI should stay 404');


## config conditions

$t->{REQUEST}  = ( <<EOF
GET /nofile.png HTTP/1.0
Host: referer.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } ];
ok($tf->handle_http($t) == 0, 'condition: Referer - no referer');

$t->{REQUEST}  = ( <<EOF
GET /nofile.png HTTP/1.0
Host: referer.example.org
Referer: http://referer.example.org/
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } ];
ok($tf->handle_http($t) == 0, 'condition: Referer - referer matches regex');

$t->{REQUEST}  = ( <<EOF
GET /image.jpg HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'condition: Referer - no referer');

$t->{REQUEST}  = ( <<EOF
GET /image.jpg HTTP/1.0
Host: www.example.org
Referer: http://referer.example.org/
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'condition: Referer - referer matches regex');

$t->{REQUEST}  = ( <<EOF
GET /image.jpg HTTP/1.0
Host: www.example.org
Referer: http://evil-referer.example.org/
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
ok($tf->handle_http($t) == 0, 'condition: Referer - referer doesn\'t match');

$t->{REQUEST} = ( <<EOF
GET /nofile HTTP/1.1
Host: bug255.example.org

GET /nofile HTTP/1.1
Host: bug255.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 403 },  { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 403 } ];
ok($tf->handle_http($t) == 0, 'remote ip cache (#255)');

$t->{REQUEST}  = ( <<EOF
GET /empty-ref.noref HTTP/1.0
Cookie: empty-ref
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
ok($tf->handle_http($t) == 0, 'condition: $HTTP["referer"] == "" and Referer is no set');

$t->{REQUEST}  = ( <<EOF
GET /empty-ref.noref HTTP/1.0
Cookie: empty-ref
Referer:
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
ok($tf->handle_http($t) == 0, 'condition: $HTTP["referer"] == "" and Referer is empty');

$t->{REQUEST}  = ( <<EOF
GET /empty-ref.noref HTTP/1.0
Cookie: empty-ref
Referer: foobar
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } ];
ok($tf->handle_http($t) == 0, 'condition: $HTTP["referer"] == "" and Referer: foobar');


## case-insensitive filesystem policy

## check if lower-casing works

$t->{REQUEST}  = ( <<EOF
GET /image.JPG HTTP/1.0
Host: lowercase-allow
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'uppercase access');

$t->{REQUEST}  = ( <<EOF
GET /image.jpg HTTP/1.0
Host: lowercase-allow
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'lowercase access');

## check that mod_auth works

$t->{REQUEST}  = ( <<EOF
GET /image.JPG HTTP/1.0
Host: lowercase-auth
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } ];
ok($tf->handle_http($t) == 0, 'uppercase access');

$t->{REQUEST}  = ( <<EOF
GET /image.jpg HTTP/1.0
Host: lowercase-auth
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } ];
ok($tf->handle_http($t) == 0, 'lowercase access');


## check that mod_staticfile exclude works
$t->{REQUEST}  = ( <<EOF
GET /image.JPG HTTP/1.0
Host: lowercase-exclude
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
ok($tf->handle_http($t) == 0, 'upper case access to staticfile.exclude-extension');

$t->{REQUEST}  = ( <<EOF
GET /image.jpg HTTP/1.0
Host: lowercase-exclude
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
ok($tf->handle_http($t) == 0, 'lowercase access');


## check that mod_access exclude works
$t->{REQUEST}  = ( <<EOF
GET /image.JPG HTTP/1.0
Host: lowercase-deny
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
ok($tf->handle_http($t) == 0, 'uppercase access to url.access-deny protected location');

$t->{REQUEST}  = ( <<EOF
GET /image.jpg HTTP/1.0
Host: lowercase-deny
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
ok($tf->handle_http($t) == 0, 'lowercase access');


## symlink policy

my $docroot = $tf->{'TESTDIR'}."/tmp/lighttpd/servers/www.example.org/pages";

sub init_testbed {
    return 0 if $tf->{'win32native'}; # win32native lighttpd.exe
    return 0 unless eval { symlink("",""); 1 };
    my $f = "$docroot/index.html";
    my $l = "$docroot/index.xhtml";
    my $rc = undef;
    unless (-l $l) {
        return 0 unless symlink($f,$l);
    };
    $f = "$docroot/subdir";
    $l = "$docroot/symlinked";
    $rc = undef;
    unless (-l $l) {
        return 0 unless symlink($f,$l);
    }
    return 1;
};

SKIP: {
    skip "perl does not support symlinking or setting up the symlinks failed.", 8 unless init_testbed;

# allow case
# simple file
	$t->{REQUEST} = ( <<EOF
GET /index.html HTTP/1.0
Host: symlink.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
	ok($tf->handle_http($t) == 0, 'allow: simple file');

# symlinked file
	$t->{REQUEST} = ( <<EOF
GET /index.xhtml HTTP/1.0
Host: symlink.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
	ok($tf->handle_http($t) == 0, 'allow: symlinked file');

# directly symlinked dir
	$t->{REQUEST} = ( <<EOF
GET /symlinked/ HTTP/1.0
Host: symlink.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
	ok($tf->handle_http($t) == 0, 'allow: directly symlinked dir');

# symlinked dir in path
	$t->{REQUEST} = ( <<EOF
GET /symlinked/any.txt HTTP/1.0
Host: symlink.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
	ok($tf->handle_http($t) == 0, 'allow: symlinked dir in path');

# deny case
# simple file
	$t->{REQUEST} = ( <<EOF
GET /index.html HTTP/1.0
Host: nosymlink.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
	ok($tf->handle_http($t) == 0, 'deny: simple file');

# symlinked file
	$t->{REQUEST} = ( <<EOF
GET /index.xhtml HTTP/1.0
Host: nosymlink.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
	ok($tf->handle_http($t) == 0, 'deny: symlinked file');

# directly symlinked dir
	$t->{REQUEST} = ( <<EOF
GET /symlinked/ HTTP/1.0
Host: nosymlink.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
	ok($tf->handle_http($t) == 0, 'deny: directly symlinked dir');

# symlinked dir in path
	$t->{REQUEST} = ( <<EOF
GET /symlinked/any.txt HTTP/1.0
Host: nosymlink.example.org
EOF
 );
	$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } ];
	ok($tf->handle_http($t) == 0, 'deny: symlinked dir in path');

};


## mod_auth

$t->{REQUEST}  = ( <<EOF
GET /server-status HTTP/1.0
Host: auth-plain.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } ];
ok($tf->handle_http($t) == 0, 'Missing Auth-token');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-plain.example.org
Authorization: Basic \x80mFuOmphb
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Invalid base64 Auth-token');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-plain.example.org
Authorization: Basic bm90Oml0Cg==
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Wrong Auth-token');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-plain.example.org
Authorization: Basic amFuOmphbg==
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Valid Auth-token - plain');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-htpasswd.example.org
Authorization: Basic c2hhOnNoYQ==
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Valid Auth-token - htpasswd (sha)');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-htpasswd.example.org
Authorization: Basic c2hhOnNoYg==
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Valid Auth-token - htpasswd (sha, wrong password)');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-htpasswd.example.org
Authorization: Basic YXByLW1kNTphcHItbWQ1
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Valid Auth-token - htpasswd (apr-md5)');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-htpasswd.example.org
Authorization: Basic YXByLW1kNTphcHItbWQ2
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Valid Auth-token - htpasswd (apr-md5, wrong password)');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-plain.example.org
Authorization: Basic bWQ1Om1kNA==
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Valid Auth-token');

## this should not crash
$t->{REQUEST}  = ( <<EOF
GET /server-status HTTP/1.0
Host: auth-plain.example.org
User-Agent: Wget/1.9.1
Authorization: Digest username="jan", realm="jan", nonce="9a5428ccc05b086a08d918e73b01fc6f",
                uri="/server-status", response="ea5f7d9a30b8b762f9610ccb87dea74f"
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } ];
ok($tf->handle_http($t) == 0, 'Digest-Auth: missing qop, no crash');

# (Note: test case is invalid; mismatch between request line and uri="..."
#  is not what is intended to be tested here, but that is what is invalid)
# https://redmine.lighttpd.net/issues/477
## this should not crash
$t->{REQUEST}  = ( <<EOF
GET /server-status HTTP/1.0
Host: auth-plain.example.org
User-Agent: Wget/1.9.1
Authorization: Digest username="jan", realm="jan",
	nonce="b1d12348b4620437c43dd61c50ae4639",
	uri="/MJ-BONG.xm.mpc", qop=auth, noncecount=00000001",
	cnonce="036FCA5B86F7E7C4965C7F9B8FE714B7",
	response="29B32C2953C763C6D033C8A49983B87E"
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'Digest-Auth: missing nc (noncecount instead), no crash');

$t->{REQUEST}  = ( <<EOF
GET /server-config HTTP/1.0
Host: auth-plain.example.org
Authorization: Basic =
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'Basic-Auth: Invalid Base64');

$t->{REQUEST}  = ( <<EOF
GET /server-status HTTP/1.0
Host: auth-plain.example.org
Authorization: Digest username="jan", realm="download archiv",
	nonce="b3b26457000000003a9b34a3cd56d26e48a52a498ac9765d4b",
	uri="/server-status", qop=auth, nc=00000001,
	algorithm="md5-sess", response="049b000fb00ab51dddea6f093a96aa2e"
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } ];
ok($tf->handle_http($t) == 0, 'Digest-Auth: md5-sess + missing cnonce');

 $t->{REQUEST}  = ( <<EOF
GET /server-status HTTP/1.0
Host: auth-plain.example.org
Authorization: Digest username="jan", realm="download archiv",
	nonce="b3b26457000000003a9b34a3cd56d26e48a52a498ac9765d4b",
	uri="/server-status", qop=auth, nc=00000001, cnonce="65ee1b37",
	algorithm="md5", response="049b000fb00ab51dddea6f093a96aa2e"
EOF
  );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401, 'WWW-Authenticate' => '/, stale=true$/' } ];
ok($tf->handle_http($t) == 0, 'Digest-Auth: stale nonce');

$t->{REQUEST}  = ( <<EOF
GET /server-status HTTP/1.0
Host: auth-plain.example.org
Authorization: Digest username = "jan", realm = "download archiv",
	nonce = "b3b26457000000003a9b34a3cd56d26e48a52a498ac9765d4b",
	uri = "/server-status", qop = auth, nc = 00000001, cnonce = "65ee1b37",
	algorithm = "md5", response = "049b000fb00ab51dddea6f093a96aa2e"     
EOF
 ); # note: trailing whitespace at end of request line above is intentional
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401, 'WWW-Authenticate' => '/, stale=true$/' } ];
ok($tf->handle_http($t) == 0, 'Digest-Auth: BWS, trailing WS, stale nonce');


## mod_cgi

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf->handle_http($t) == 0, 'perl via cgi');

if ($^O ne "cygwin" && $^O ne "msys") {
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

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=ABSENT HTTP/1.1
Host: www.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, 'HTTP-Content' => '[ABSENT not found]' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: ABSENT');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=BLANK_VALUE HTTP/1.1
Host: www.example.org
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, 'HTTP-Content' => '' } ];
ok($tf->handle_http($t) == 0, 'cgi-env: BLANK_VALUE');

# broken header crash
$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?crlfcrash HTTP/1.0
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 302, 'Location' => 'http://www.example.org/' } ];
ok($tf->handle_http($t) == 0, 'broken header via perl cgi');


## mod_deflate

SKIP: {
    my $has_zlib = $tf->has_feature("zlib support");
    skip "skipping tests requiring zlib", 9 unless $has_zlib;

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: deflate.example.org
Accept-Encoding: deflate
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '' } ];
ok($tf->handle_http($t) == 0, 'Vary is set');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: deflate
Host: deflate.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', 'Content-Length' => '1294', '+Content-Encoding' => '' } ];
ok($tf->handle_http($t) == 0, 'deflate - Content-Length and Content-Encoding is set');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: deflate
Host: deflate-cache.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', 'Content-Length' => '1294', '+Content-Encoding' => '' } ];
ok($tf->handle_http($t) == 0, 'deflate - Content-Length and Content-Encoding is set');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: gzip
Host: deflate.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', 'Content-Length' => '1306', '+Content-Encoding' => '' } ];
ok($tf->handle_http($t) == 0, 'gzip - Content-Length and Content-Encoding is set');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: gzip
Host: deflate-cache.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', 'Content-Length' => '1306', '+Content-Encoding' => '' } ];
ok($tf->handle_http($t) == 0, 'gzip - Content-Length and Content-Encoding is set');


$t->{REQUEST}  = ( <<EOF
GET /index.txt HTTP/1.0
Host: deflate.example.org
Accept-Encoding: gzip, deflate
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', '+Content-Encoding' => '' } ];
ok($tf->handle_http($t) == 0, 'gzip, deflate - Content-Length and Content-Encoding is set');

$t->{REQUEST}  = ( <<EOF
GET /index.txt HTTP/1.0
Host: deflate.example.org
Accept-Encoding: gzip, deflate
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', '+Content-Encoding' => '', 'Content-Type' => "text/plain; charset=utf-8" } ];
ok($tf->handle_http($t) == 0, 'Content-Type is from the original file');

$t->{REQUEST}  = ( <<EOF
GET /index.txt HTTP/1.0
Host: deflate.example.org
Accept-encoding:
X-Accept-encoding: x-i2p-gzip;q=1.0, identity;q=0.5, deflate;q=0, gzip;q=0, *;q=0
User-Agent: MYOB/6.66 (AN/ON)
Connection: close
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '-Content-Encoding' => '', 'Content-Type' => "text/plain; charset=utf-8" } ];
ok($tf->handle_http($t) == 0, 'Empty Accept-Encoding');

$t->{REQUEST}  = ( <<EOF
GET /index.txt HTTP/1.0
Accept-Encoding: bzip2, gzip, deflate
Host: deflate-cache.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', 'Content-Encoding' => 'gzip', 'Content-Type' => "text/plain" } ];
ok($tf->handle_http($t) == 0, 'bzip2 requested but disabled');

}


## mod_expire

$t->{REQUEST} = ( <<EOF
GET /subdir/access.txt HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Expires' => '' } ];
ok($tf->handle_http($t) == 0, 'expires HTTP/1.0');

$t->{REQUEST} = ( <<EOF
GET /subdir/access.txt HTTP/1.1
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, '+Cache-Control' => '' } ];
ok($tf->handle_http($t) == 0, 'cache-control HTTP/1.1 by access time');

$t->{REQUEST} = ( <<EOF
GET /subdir/modification.txt HTTP/1.1
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, '+Cache-Control' => '' } ];
ok($tf->handle_http($t) == 0, 'cache-control HTTP/1.1 by modification time');


## mod_extforward

$t->{REQUEST} = ( <<EOF
GET /cgi.pl?env=REMOTE_ADDR HTTP/1.0
Host: www.example.org
X-Forwarded-For: 127.0.10.1
EOF
);
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '127.0.10.1' } ];
ok($tf->handle_http($t) == 0, 'expect 127.0.10.1, from single ip');

$t->{REQUEST} = ( <<EOF
GET /cgi.pl?env=REMOTE_ADDR HTTP/1.0
Host: www.example.org
X-Forwarded-For: 127.0.10.1, 127.0.20.1
EOF
);
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '127.0.20.1' } ];
ok($tf->handle_http($t) == 0, 'expect 127.0.20.1, from two ips');

$t->{REQUEST} = ( <<EOF
GET /cgi.pl?env=REMOTE_ADDR HTTP/1.0
Host: www.example.org
X-Forwarded-For: 127.0.10.1, 127.0.20.1, 127.0.30.1
EOF
);
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '127.0.20.1' } ];
ok($tf->handle_http($t) == 0, 'expect 127.0.20.1, from chained proxies');

$t->{REQUEST} = ( <<EOF
GET /cgi.pl?env=REMOTE_ADDR HTTP/1.0
Host: www.example.org
Forwarded: for=127.0.10.1, for=127.0.20.1;proto=https, for=127.0.30.1;proto=http
EOF
);
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '127.0.20.1' } ];
ok($tf->handle_http($t) == 0, 'expect 127.0.20.1, from chained proxies');


## mod_proxy

do {

my $tf_proxy = LightyTest->new();
$tf_proxy->{CONFIGFILE} = 'proxy.conf';

local $ENV{EPHEMERAL_PORT} = $tf->{PORT};
ok($tf_proxy->start_proc == 0, "Starting lighttpd as proxy") or last;

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } ];
ok($tf_proxy->handle_http($t) == 0, 'valid request');

$t->{REQUEST}  = ( <<EOF
GET /index.html HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Server' => 'lighttpd-1.4.x' } ];
ok($tf_proxy->handle_http($t) == 0, 'drop Server from real server');

$t->{REQUEST}  = ( <<EOF
GET /rewrite/all/some+test%3axxx%20with%20space HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE} = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/some+test%3Axxx%20with%20space' } ];
ok($tf_proxy->handle_http($t) == 0, 'rewrited urls work with encoded path');

ok($tf_proxy->stop_proc == 0, "Stopping lighttpd proxy");

} while (0);


## mod_setenv

$t->{REQUEST} = ( <<EOF
GET /cgi.pl?env=TRAC_ENV HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'tracenv' } ];
ok($tf->handle_http($t) == 0, 'query first setenv');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=SETENV HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'setenv' } ];
ok($tf->handle_http($t) == 0, 'query second setenv');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=NEWENV HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'newenv' } ];
ok($tf->handle_http($t) == 0, 'query set-environment');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=HTTP_FOO HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'foo' } ];
ok($tf->handle_http($t) == 0, 'query add-request-header');

$t->{REQUEST}  = ( <<EOF
GET /cgi.pl?env=HTTP_FOO2 HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'foo2' } ];
ok($tf->handle_http($t) == 0, 'query set-request-header');

$t->{REQUEST} = ( <<EOF
GET /index.html HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'BAR' => 'foo' } ];
ok($tf->handle_http($t) == 0, 'query add-response-header');

$t->{REQUEST} = ( <<EOF
GET /index.html HTTP/1.0
Host: www.example.org
EOF
 );
$t->{RESPONSE}  = [ { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'BAR2' => 'bar2' } ];
ok($tf->handle_http($t) == 0, 'query set-response-header');


ok($tf->stop_proc == 0, "Stopping lighttpd");
