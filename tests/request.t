#! /usr/bin/perl -w

use strict;
use IO::Socket;
use Test::More tests => 28;

my $basedir = (defined $ENV{'top_builddir'} ? $ENV{'top_builddir'} : '..');
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
    
ok(start_proc == 0, "Starting lighttpd") or die();

## Basic Request-Handling

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



ok(stop_proc == 0, "Stopping lighttpd");

