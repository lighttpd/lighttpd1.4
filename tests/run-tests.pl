#! /usr/bin/perl -w

use strict;
use IO::Socket;
use Test::More tests => 126;

my $basedir = (defined $ENV{'top_builddir'} ? $ENV{'top_builddir'} : '.');
my $srcdir = (defined $ENV{'srcdir'} ? $ENV{'srcdir'} : '.');

my $testname;
my @request;
my @response;
my $configfile = $srcdir.'/lighttpd.conf';
my $lighttpd_path = $basedir.'/src/lighttpd';
my $pidfile = '/tmp/lighttpd/lighttpd.pid';
my $pidoffile = '/tmp/lighttpd/pidof.pid';

sub pidof {
	my $prog = $_[0];

	open F, "ps ax  | grep $prog | awk '{ print \$1 }'|" or
	open F, "ps -ef | grep $prog | awk '{ print \$2 }'|" or
	  return -1;

	my $pid = <F>;
	close F;

	return $pid;
}

sub stop_proc {
	open F, $pidfile or return -1;
	my $pid = <F>;
	close F;

	kill('TERM',$pid) or return -1;
	select(undef, undef, undef, 0.01);

	return 0;
}


sub start_proc {
	# kill old proc if necessary
	stop_proc;

	unlink($pidfile);
	system($lighttpd_path." -f ".$configfile);

	if (-e $pidfile) {
		return 0;
	} else {
		return -1;
	}
}

sub handle_http {
	my $EOL = "\015\012";
	my $BLANK = $EOL x 2;
	my $port = 2048;
	my $host = "127.0.0.1";

	my $remote = 
 	  IO::Socket::INET->new(Proto    => "tcp",
				PeerAddr => $host,
				PeerPort => $port)
	  or return -1;

	$remote->autoflush(1);

	foreach(@request) {
		# pipeline requests
		s/\r//g;
		s/\n/$EOL/g;

		print $remote $_.$BLANK;	
	}

	my $lines = "";

	# read everything
	while(<$remote>) {
		$lines .= $_;
	}
	
	close $remote;

	my $href;
	foreach $href (@response) {
		# first line is always response header
		my %resp_hdr;
		my $resp_body;
		my $resp_line;
		my $conditions = $_;

		for (my $ln = 0; defined $lines; $ln++) {
			(my $line, $lines) = split($EOL, $lines, 2);

			# header finished
			last if(length($line) == 0);

			if ($ln == 0) {
				# response header
				$resp_line = $line;
			} else {
				# response vars

				if ($line =~ /^([^:]+):\s*(.+)$/) {
					(my $h = $1) =~ tr/[A-Z]/[a-z]/;

					$resp_hdr{$h} = $2;
				} else {
					return -1;
				}
			}
		}

		# check length
		if (defined $resp_hdr{"content-length"}) {
			($resp_body, $lines) = split("^.".$resp_hdr{"content-length"}, $lines, 2);
		} else {
			$resp_body = $lines;
			undef $lines;
		}

		# check conditions
		if ($resp_line =~ /^(HTTP\/1\.[01]) ([0-9]{3}) .+$/) {
			if ($href->{'HTTP-Protocol'} ne $1) {
				diag(sprintf("proto failed: expected '%s', got '%s'\n", $href->{'HTTP-Protocol'}, $1));
				return -1;
			}
			if ($href->{'HTTP-Status'} ne $2) {
				diag(sprintf("status failed: expected '%s', got '%s'\n", $href->{'HTTP-Status'}, $2));
				return -1;
			}
		} else {
			return -1;
		}

		if (defined $href->{'HTTP-Content'}) {
			if ($href->{'HTTP-Content'} ne $resp_body) {
				diag(sprintf("body failed: expected '%s', got '%s'\n", $href->{'HTTP-Content'}, $resp_body));
				return -1;
			}
		}
		
		if (defined $href->{'-HTTP-Content'}) {
			if (defined $resp_body && $resp_body ne '') {
				diag(sprintf("body failed: expected empty body, got '%s'\n", $resp_body));
				return -1;
			}
		}

		foreach (keys %{ $href }) {
			next if $_ eq 'HTTP-Protocol';
			next if $_ eq 'HTTP-Status';
			next if $_ eq 'HTTP-Content';
			next if $_ eq '-HTTP-Content';

			(my $k = $_) =~ tr/[A-Z]/[a-z]/;

			my $no_val = 0;

			if (substr($k, 0, 1) eq '+') {
				$k = substr($k, 1);
				$no_val = 1;

			}

			if (!defined $resp_hdr{$k}) {
				diag(sprintf("required header '%s' is missing\n", $k));
				return -1;
			}

			if ($no_val == 0 &&
				$href->{$_} ne $resp_hdr{$k}) {
				diag(sprintf("response-header failed: expected '%s', got '%s'\n", $href->{$_}, $resp_hdr{$k}));
				return -1;
			}
		}
	}

	# we should have sucked up everything
	return -1 if (defined $lines); 

	return 0;
}
    
print "\nStart-Up\n";
ok(start_proc == 0, "Starting lighttpd") or die();

print "\nRequest Line\n";

@request  = ( <<EOF
GET / HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'Valid HTTP/1.0 Request') or die();

@request  = ( <<EOF
GET /
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'missing Protocol');

@request  = ( <<EOF
BC /
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'missing protocol + unknown method');

@request  = ( <<EOF
ABC
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'missing protocol + unknown method + missing URI');

@request  = ( <<EOF
ABC / HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 501 } );
ok(handle_http == 0, 'unknown method');

@request  = ( <<EOF
GET / HTTP/1.3
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 505 } );
ok(handle_http == 0, 'unknown protocol');

@request  = ( <<EOF
GET http://www.example.org/ HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'absolute URI');

print "\nLow-Level Request-Header Parsing\n";
@request  = ( <<EOF
GET / HTTP/1.0
ABC : foo
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'whitespace after key');

@request  = ( <<EOF
GET / HTTP/1.0
ABC a: foo
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'whitespace with-in key');

@request  = ( <<EOF
GET / HTTP/1.0
ABC:foo
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'no whitespace');

@request  = ( <<EOF
GET / HTTP/1.0
ABC:foo 
  bc
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'line-folding');

print "\nLow-Level Request-Header Parsing - URI\n";
@request  = ( <<EOF
GET /index%2ehtml HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'URL-encoding');

@request  = ( <<EOF
GET /index.html%00 HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } );
ok(handle_http == 0, 'URL-encoding, %00');



print "\nLow-Level Request-Header Parsing - Host:\n";

@request  = ( <<EOF
GET / HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'hostname');

@request  = ( <<EOF
GET / HTTP/1.0
Host: 127.0.0.1
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'IPv4 address');

@request  = ( <<EOF
GET / HTTP/1.0
Host: [::1]
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'IPv6 address');

@request  = ( <<EOF
GET / HTTP/1.0
Host: www.example.org:80
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'hostname + port');

@request  = ( <<EOF
GET / HTTP/1.0
Host: 127.0.0.1:80
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'IPv4 address + port');

@request  = ( <<EOF
GET / HTTP/1.0
Host: [::1]:80
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'IPv6 address + port');

@request  = ( <<EOF
GET / HTTP/1.0
Host: ../123.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'directory traversal');

@request  = ( <<EOF
GET / HTTP/1.0
Host: .jsdh.sfdg.sdfg.
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'leading and trailing dot');

@request  = ( <<EOF
GET / HTTP/1.0
Host: jsdh.sfdg.sdfg.
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'trailing dot is ok');

@request  = ( <<EOF
GET / HTTP/1.0
Host: .jsdh.sfdg.sdfg
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'leading dot');


@request  = ( <<EOF
GET / HTTP/1.0
Host: jsdh..sfdg.sdfg
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'two dots');

@request  = ( <<EOF
GET / HTTP/1.0
Host: jsdh.sfdg.sdfg:asd
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'broken port-number');

@request  = ( <<EOF
GET / HTTP/1.0
Host: jsdh.sfdg.sdfg:-1
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'negative port-number');


@request  = ( <<EOF
GET / HTTP/1.0
Host: :80
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'port given but host missing');

@request  = ( <<EOF
GET / HTTP/1.0
Host: .jsdh.sfdg.:sdfg.
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'port and host are broken');

@request  = ( <<EOF
GET / HTTP/1.0
Host: a.b-c.d123
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'allowed characters in host-name');

@request  = ( <<EOF
GET / HTTP/1.0
Host: -a.c
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'leading dash');

@request  = ( <<EOF
GET / HTTP/1.0
Host: .
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'dot only');

@request  = ( <<EOF
GET / HTTP/1.0
Host: a192.168.2.10:1234
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'broken IPv4 address - non-digit');

@request  = ( <<EOF
GET / HTTP/1.0
Host: 192.168.2:1234
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'broken IPv4 address - too short');





print "\nLow-Level Request-Header Parsing - Content-Length:\n";
@request  = ( <<EOF
GET /index.html HTTP/1.0
Content-Length: -2
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'negative Content-Length');

@request  = ( <<EOF
POST /12345.txt HTTP/1.0
Host: 123.example.org
Content-Length: 2147483648
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 413 } );
ok(handle_http == 0, 'Content-Length > max-request-size');

@request  = ( <<EOF
POST /12345.txt HTTP/1.0
Host: 123.example.org
Content-Length: 
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 411 } );
ok(handle_http == 0, 'Content-Length is empty');

print "\nLow-Level Request-Header Parsing - HTTP/1.1\n";
@request  = ( <<EOF
GET / HTTP/1.1
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'Host missing');

print "\nLow-Level Response-Header Parsing - HTTP/1.1\n";
@request  = ( <<EOF
GET / HTTP/1.1
Host: www.example.org
Connection: close
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 200, '+Date' => '' } );
ok(handle_http == 0, 'Date header');

@request  = ( <<EOF
GET / HTTP/1.1
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 400, 'Connection' => 'close' } );
ok(handle_http == 0, 'Host missing');








print "\nLow-Level Response-Header Parsing - Content-Length:\n";
@request  = ( <<EOF
GET /12345.html HTTP/1.0
Host: 123.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Length' => '6' } );
ok(handle_http == 0, 'Content-Length for text/html');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'Content-Length' => '6' } );
ok(handle_http == 0, 'Content-Length for text/plain');










print "\nLow-Level Response-Header Parsing - Location:\n";
@request  = ( <<EOF
GET /dummydir HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => 'http://localhost:2048/dummydir/' } );
ok(handle_http == 0, 'internal redirect in directory');

@request  = ( <<EOF
GET /dummydir?foo HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => 'http://localhost:2048/dummydir/?foo' } );
ok(handle_http == 0, 'internal redirect in directory + querystring');












print "\nBasic Request-Handling\n";
@request  = ( <<EOF
GET /foobar HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } );
ok(handle_http == 0, 'file not found');

@request  = ( <<EOF
GET /foobar?foobar HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } );
ok(handle_http == 0, 'file not found + querystring');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/plain' } );
ok(handle_http == 0, 'GET, content == 12345, mimetype text/plain');

@request  = ( <<EOF
GET /12345.html HTTP/1.0
Host: 123.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'text/html' } );
ok(handle_http == 0, 'GET, content == 12345, mimetype text/html');

@request  = ( <<EOF
GET /dummyfile.bla HTTP/1.0
Host: 123.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '12345'."\n", 'Content-Type' => 'application/octet-stream' } );
ok(handle_http == 0, 'GET, content == 12345, mimetype application/octet-stream');

@request  = ( <<EOF
POST / HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 411 } );
ok(handle_http == 0, 'POST request, no Content-Length');


@request  = ( <<EOF
POST / HTTP/1.0
Content-type: application/x-www-form-urlencoded
Content-length: 0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'POST request, empty request-body');

@request  = ( <<EOF
HEAD / HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '-HTTP-Content' => ''} );
ok(handle_http == 0, 'HEAD request, no content');

@request  = ( <<EOF
HEAD /12345.html HTTP/1.0
Host: 123.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '-HTTP-Content' => '', 'Content-Type' => 'text/html', 'Content-Length' => '6'} );
ok(handle_http == 0, 'HEAD request, mimetype text/html, content-length');

@request  = ( <<EOF
HEAD /foobar?foobar HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404, '-HTTP-Content' => '' } );
ok(handle_http == 0, 'HEAD request, file-not-found, query-string');

@request  = ( <<EOF
GET / HTTP/1.1
Connection: close
Expect: 100-continue
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.1', 'HTTP-Status' => 417, '-HTTP-Content' => ''} );
ok(handle_http == 0, 'Continue, Expect');

## ranges

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
Range: bytes=0-3
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 206, 'HTTP-Content' => '1234' } );
ok(handle_http == 0, 'GET, Range 0-3');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
Range: bytes=-3
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 206, 'HTTP-Content' => '45'."\n" } );
ok(handle_http == 0, 'GET, Range -3');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
Range: bytes=3-
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 206, 'HTTP-Content' => '45'."\n" } );
ok(handle_http == 0, 'GET, Range 3-');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
Range: bytes=0-1,3-4
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 206, 'HTTP-Content' => <<EOF
\r
--fkj49sn38dcn3\r
Content-Range: bytes 0-1/6\r
Content-Type: text/plain\r
\r
12\r
--fkj49sn38dcn3\r
Content-Range: bytes 3-4/6\r
Content-Type: text/plain\r
\r
45\r
--fkj49sn38dcn3--\r
EOF
 } );
ok(handle_http == 0, 'GET, Range 0-1,3-4');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
Range: bytes=0--
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'GET, Range 0--');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
Range: bytes=-2-3
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'GET, Range -2-3');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
Range: bytes=-0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 416, 'HTTP-Content' => <<EOF
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>416 - Requested Range Not Satisfiable</title>
 </head>
 <body>
  <h1>416 - Requested Range Not Satisfiable</h1>
 </body>
</html>
EOF
 } );
ok(handle_http == 0, 'GET, Range -0');

@request  = ( <<EOF
GET /12345.txt HTTP/1.0
Host: 123.example.org
Range: bytes=25-
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 416, 'HTTP-Content' => <<EOF
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>416 - Requested Range Not Satisfiable</title>
 </head>
 <body>
  <h1>416 - Requested Range Not Satisfiable</h1>
 </body>
</html>
EOF
 } );

ok(handle_http == 0, 'GET, Range start out of range');


@request  = ( <<EOF
GET / HTTP/1.0
Hsgfsdjf: asdfhdf
hdhd: shdfhfdasd
hfhr: jfghsdfg
jfuuehdmn: sfdgjfdg
jvcbzufdg: sgfdfg
hrnvcnd: jfjdfg
jfusfdngmd: gfjgfdusdfg
nfj: jgfdjdfg
jfue: jfdfdg
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'larger headers');


@request  = ( <<EOF
GET / HTTP/1.0
Host: www.example.org
Host: 123.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'Duplicate Host headers, Bug #25');


@request  = ( <<EOF
GET / HTTP/1.0
Content-Length: 5
Content-Length: 4
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'Duplicate Content-Length headers');

@request  = ( <<EOF
GET / HTTP/1.0
Content-Type: 5
Content-Type: 4
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'Duplicate Content-Type headers');

@request  = ( <<EOF
GET / HTTP/1.0
Range: bytes=5-6
Range: bytes=5-9
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'Duplicate Range headers');

@request  = ( <<EOF
GET / HTTP/1.0
If-None-Match: 5
If-None-Match: 4
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'Duplicate If-None-Match headers');

@request  = ( <<EOF
GET / HTTP/1.0
If-Modified-Since: 5
If-Modified-Since: 4
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 400 } );
ok(handle_http == 0, 'Duplicate If-Modified-Since headers');










print "\nmodules - mod_access\n";

@request  = ( <<EOF
GET /index.html~ HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } );
ok(handle_http == 0, 'forbid access to ...~');


print "\nmodules - mod_auth\n";

@request  = ( <<EOF
GET /server-status HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } );
ok(handle_http == 0, 'Missing Auth-token');

@request  = ( <<EOF
GET /server-status HTTP/1.0
Authorization: Basic amFuOmphb
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 401 } );
ok(handle_http == 0, 'Basic-Auth: Wrong Auth-token');

@request  = ( <<EOF
GET /server-config HTTP/1.0
Authorization: Basic amFuOmphbg==
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'Basic-Auth: Valid Auth-token');

# mod-cgi
#
print "\nmodules - mod_cgi\n";
@request  = ( <<EOF
GET /cgi.pl HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'perl via cgi');

@request  = ( <<EOF
GET /cgi.pl/foo HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/cgi.pl' } );
ok(handle_http == 0, 'perl via cgi + pathinfo');

@request  = ( <<EOF
GET /cgi-pathinfo.pl/foo HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/foo' } );
ok(handle_http == 0, 'perl via cgi + pathinfo');

@request  = ( <<EOF
GET /nph-status.pl HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'NPH + perl, Bug #14');


print "\nmodules - mod_fastcgi\n";

SKIP: {
	skip "no PHP running on port 1026", 13 if pidof("php") == -1; 

	@request  = ( <<EOF
GET /phpinfo.php HTTP/1.0
Host: www.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok(handle_http == 0, 'valid request');

	@request  = ( <<EOF
GET /phpinfofoobar.php HTTP/1.0
Host: www.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } );
	ok(handle_http == 0, 'file not found');

	@request  = ( <<EOF
GET /go/ HTTP/1.0
Host: www.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok(handle_http == 0, 'index-file handling');

	@request  = ( <<EOF
GET /redirect.php HTTP/1.0
Host: www.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 302, 'Location' => 'http://www.example.org:2048/' } );
	ok(handle_http == 0, 'Status + Location via FastCGI');

	@request  = ( <<EOF
GET /phpself.php HTTP/1.0
Host: www.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok(handle_http == 0, '$_SERVER["PHP_SELF"]');

	@request  = ( <<EOF
GET /phpself.php/foo HTTP/1.0
Host: www.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/phpself.php' } );
	ok(handle_http == 0, '$_SERVER["PHP_SELF"]');

	@request  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: www.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
	ok(handle_http == 0, 'SERVER_NAME');

	@request  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: foo.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
	ok(handle_http == 0, 'SERVER_NAME');

	@request  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: vvv.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
	ok(handle_http == 0, 'SERVER_NAME');

	@request  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: zzz.example.org
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'www.example.org' } );
	ok(handle_http == 0, 'SERVER_NAME');

	@request  = ( <<EOF
GET /cgi.php/abc HTTP/1.0
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
	ok(handle_http == 0, 'PATHINFO');

	@request  = ( <<EOF
GET /www/abc/def HTTP/1.0
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } );
	ok(handle_http == 0, 'PATHINFO on a directory');

	@request  = ( <<EOF
GET /indexfile/ HTTP/1.0
EOF
 );
	@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/indexfile/index.php' } );
	ok(handle_http == 0, 'PHP_SELF + Indexfile, Bug #3');


}


print "\nmodules - mod_redirect\n";
@request  = ( <<EOF
GET /redirect/ HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => 'http://localhost:2048/' } );
ok(handle_http == 0, 'external redirect');



print "\nmodules - mod_compress\n";
@request  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: deflate
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '' } );
ok(handle_http == 0, 'Vary is set');

@request  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: deflate
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', 'Content-Length' => '1288', '+Content-Encoding' => '' } );
ok(handle_http == 0, 'deflate - Content-Length and Content-Encoding is set');

@request  = ( <<EOF
GET /index.html HTTP/1.0
Accept-Encoding: gzip
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', '+Content-Encoding' => '' } );
ok(handle_http == 0, 'gzip - Content-Length and Content-Encoding is set');

@request  = ( <<EOF
GET /index.txt HTTP/1.0
Accept-Encoding: gzip, deflate
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Vary' => '', '+Content-Encoding' => '' } );
ok(handle_http == 0, 'gzip, deflate - Content-Length and Content-Encoding is set');


print "\nmodules - mod_expire\n";
@request  = ( <<EOF
GET /expire/access.txt HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Expires' => '' } );
ok(handle_http == 0, 'access');

@request  = ( <<EOF
GET /expire/modification.txt HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, '+Expires' => '' } );
ok(handle_http == 0, 'modification');






print "\nmodules - mod_userdir\n";

# get current user

@request  = ( <<EOF
GET /~jan/ HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404 } );
ok(handle_http == 0, 'valid user');

@request  = ( <<EOF
GET /~jan HTTP/1.0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => 'http://localhost:2048/~jan/' } );
ok(handle_http == 0, 'valid user + redirect');

@request  = ( <<EOF
GET /~jan HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 301, 'Location' => 'http://www.example.org/~jan/' } );
ok(handle_http == 0, 'valid user + redirect');

print "\nclean up\n";

ok(stop_proc == 0, "Stopping lighttpd");

print "\nspecial config\n";

$configfile = $srcdir.'/fastcgi-10.conf';
ok(start_proc == 0, "Starting lighttpd with $configfile") or die();
@request  = ( <<EOF
GET /phphost.php HTTP/1.0
Host: zzz.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'zzz.example.org' } );
ok(handle_http == 0, 'FastCGI + Host');

ok(stop_proc == 0, "Stopping lighttpd");

$configfile = $srcdir.'/fastcgi-auth.conf';
ok(start_proc == 0, "Starting lighttpd with $configfile") or die();
@request  = ( <<EOF
GET /index.html?ok HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'FastCGI - Auth');

@request  = ( <<EOF
GET /index.html?fail HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 403 } );
ok(handle_http == 0, 'FastCGI - Auth');

ok(stop_proc == 0, "Stopping lighttpd");

$configfile = $srcdir.'/fastcgi-13.conf';
ok(start_proc == 0, "Starting lighttpd with $configfile") or die();
@request  = ( <<EOF
GET /indexfile/index.php HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200 } );
ok(handle_http == 0, 'FastCGI + local spawning');

ok(stop_proc == 0, "Stopping lighttpd");

$configfile = $srcdir.'/bug-06.conf';
ok(start_proc == 0, "Starting lighttpd with $configfile") or die();
@request  = ( <<EOF
GET /indexfile/ HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => '/indexfile/index.php' } );
ok(handle_http == 0, 'Bug #6');

ok(stop_proc == 0, "Stopping lighttpd");

$configfile = $srcdir.'/bug-12.conf';
ok(start_proc == 0, "Starting lighttpd with bug-12.conf") or die();
@request  = ( <<EOF
POST /indexfile/abc HTTP/1.0
Host: www.example.org
Content-Length: 0
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 404, 'HTTP-Content' => '/indexfile/return-404.php' } );
ok(handle_http == 0, 'Bug #12');

ok(stop_proc == 0, "Stopping lighttpd");

$configfile = $srcdir.'/fastcgi-responder.conf';
ok(start_proc == 0, "Starting lighttpd with $configfile") or die();
@request  = ( <<EOF
GET /index.fcgi?lf HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
ok(handle_http == 0, 'line-ending \n\n');

@request  = ( <<EOF
GET /index.fcgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
ok(handle_http == 0, 'line-ending \r\n\r\n');

@request  = ( <<EOF
GET /index.fcgi?slow-lf HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
ok(handle_http == 0, 'line-ending \n + \n');

@request  = ( <<EOF
GET /index.fcgi?slow-crlf HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
ok(handle_http == 0, 'line-ending \r\n + \r\n');

@request  = ( <<EOF
GET /index.fcgi?die-at-end HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
ok(handle_http == 0, 'killing fastcgi and wait for restart');

@request  = ( <<EOF
GET /index.fcgi?crlf HTTP/1.0
Host: www.example.org
EOF
 );
@response = ( { 'HTTP-Protocol' => 'HTTP/1.0', 'HTTP-Status' => 200, 'HTTP-Content' => 'test123' } );
ok(handle_http == 0, 'regular response of after restart');



ok(stop_proc == 0, "Stopping lighttpd");

