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

## Low-Level Request-Header Parsing - URI

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



## Low-Level Request-Header Parsing - Host

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



## Low-Level Request-Header Parsing - Content-Length


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

ok(stop_proc == 0, "Stopping lighttpd");

