#! /usr/bin/perl -w

use strict;
use IO::Socket;
use Test::More tests => 15;

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



ok(stop_proc == 0, "Stopping lighttpd");

