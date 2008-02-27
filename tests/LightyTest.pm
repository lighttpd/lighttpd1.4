#! /usr/bin/perl -w

package LightyTest;
use strict;
use IO::Socket;
use Test::More;
use Socket;
use Cwd 'abs_path';

sub mtime {
	my $file = shift;
	my @stat = stat $file;
	return @stat ? $stat[9] : 0;
}
sub new {
	my $class = shift;
	my $self = {};
	my $lpath;

	$self->{CONFIGFILE} = 'lighttpd.conf';

	$lpath = (defined $ENV{'top_builddir'} ? $ENV{'top_builddir'} : '..');
	$self->{BASEDIR} = abs_path($lpath);

	$lpath = (defined $ENV{'top_builddir'} ? $ENV{'top_builddir'}."/tests/" : '.');
	$self->{TESTDIR} = abs_path($lpath);

	$lpath = (defined $ENV{'srcdir'} ? $ENV{'srcdir'} : '.');
	$self->{SRCDIR} = abs_path($lpath);


	if (mtime($self->{BASEDIR}.'/src/lighttpd') > mtime($self->{BASEDIR}.'/build/lighttpd')) {
		$self->{LIGHTTPD_PATH} = $self->{BASEDIR}.'/src/lighttpd';
		$self->{MODULES_PATH} = $self->{BASEDIR}.'/src/.libs';
	} else {
		$self->{LIGHTTPD_PATH} = $self->{BASEDIR}.'/build/lighttpd';
		$self->{MODULES_PATH} = $self->{BASEDIR}.'/build';
	}
	$self->{LIGHTTPD_PIDFILE} = $self->{TESTDIR}.'/tmp/lighttpd/lighttpd.pid';
	$self->{PIDOF_PIDFILE} = $self->{TESTDIR}.'/tmp/lighttpd/pidof.pid';
	$self->{PORT} = 2048;

	my ($name, $aliases, $addrtype, $net) = gethostbyaddr(inet_aton("127.0.0.1"), AF_INET);

	$self->{HOSTNAME} = $name;

	bless($self, $class);

	return $self;
}

sub listening_on {
	my $self = shift;
	my $port = shift;

	my $remote = 
 	  IO::Socket::INET->new(Proto    => "tcp",
				PeerAddr => "127.0.0.1",
				PeerPort => $port) or return 0;

	close $remote;

	return 1;
}

sub stop_proc {
	my $self = shift;

	open F, $self->{LIGHTTPD_PIDFILE} or return -1;
	my $pid = <F>;
	close F;

	if (defined $pid) {
		kill('TERM',$pid) or return -1;
		select(undef, undef, undef, 0.1);
	}

	return 0;
}


sub start_proc {
	my $self = shift;
	# kill old proc if necessary
	$self->stop_proc;

	# pre-process configfile if necessary
	#

	$ENV{'SRCDIR'} = $self->{BASEDIR}.'/tests';

	unlink($self->{LIGHTTPD_PIDFILE});
	if (defined $ENV{"TRACEME"} && $ENV{"TRACEME"} eq 'strace') {
		system("strace -tt -s 512 -o strace ".$self->{LIGHTTPD_PATH}." -D -f ".$self->{SRCDIR}."/".$self->{CONFIGFILE}." -m ".$self->{MODULES_PATH}." &");
	} elsif (defined $ENV{"TRACEME"} && $ENV{"TRACEME"} eq 'valgrind') {
		system("valgrind --tool=memcheck --show-reachable=yes --leak-check=yes --log-file=valgrind ".$self->{LIGHTTPD_PATH}." -D -f ".$self->{SRCDIR}."/".$self->{CONFIGFILE}." -m ".$self->{MODULES_PATH}." &");
	} else {
		system($self->{LIGHTTPD_PATH}." -f ".$self->{SRCDIR}."/".$self->{CONFIGFILE}." -m ".$self->{MODULES_PATH});
	}

	select(undef, undef, undef, 0.1);
	if (not -e $self->{LIGHTTPD_PIDFILE} or 0 == kill 0, `cat $self->{LIGHTTPD_PIDFILE}`) {
		select(undef, undef, undef, 2);	
	}

	unlink($self->{TESTDIR}."/tmp/cfg.file");

	# no pidfile, we failed
	if (not -e $self->{LIGHTTPD_PIDFILE}) {
		diag(sprintf('Could not find pidfile: %s', $self->{LIGHTTPD_PIDFILE}));
		return -1;
	}

	# the process is gone, we failed
	if (0 == kill 0, `cat $self->{LIGHTTPD_PIDFILE}`) {
		diag(sprintf('the process referenced by %s is not up', $self->{LIGHTTPD_PIDFILE}));
		return -1;
	}

	0;
}

sub handle_http {
	my $self = shift;
	my $t = shift;
	my $EOL = "\015\012";
	my $BLANK = $EOL x 2;
	my $host = "127.0.0.1";

	my @request = $t->{REQUEST};
	my @response = $t->{RESPONSE};

	my $remote = 
 	  IO::Socket::INET->new(Proto    => "tcp",
				PeerAddr => $host,
				PeerPort => $self->{PORT});

	if (not defined $remote) {
		diag("connect failed: $!");
	       	return -1;
	}

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

	my $full_response = $lines;

	my $href;
	foreach $href ( @{ $t->{RESPONSE} }) {
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

					if (defined $resp_hdr{$h}) {
						diag(sprintf("header %s is duplicated: %s and %s\n",
						             $h, $resp_hdr{$h}, $2));
					} else {
						$resp_hdr{$h} = $2;
					}
				} else {
					diag(sprintf("unexpected line '$line'\n"));
					return -1;
				}
			}
		}

		$t->{etag} = $resp_hdr{'etag'};
		$t->{date} = $resp_hdr{'date'};

		# check length
		if (defined $resp_hdr{"content-length"}) {
			$resp_body = substr($lines, 0, $resp_hdr{"content-length"});
			if (length($lines) < $resp_hdr{"content-length"}) {
				$lines = "";
			} else {
				$lines = substr($lines, $resp_hdr{"content-length"});
			}
			undef $lines if (length($lines) == 0);
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
			diag(sprintf("unexpected resp_line '$resp_line'\n"));
			return -1;
		}

		if (defined $href->{'HTTP-Content'}) {
			$resp_body = "" unless defined $resp_body;
			if ($href->{'HTTP-Content'} ne $resp_body) {
				diag(sprintf("body failed: expected '%s', got '%s'\n", $href->{'HTTP-Content'}, $resp_body));
				return -1;
			}
		} elsif (defined $href->{'-HTTP-Content'}) {
			if (defined $resp_body && $resp_body ne '') {
				diag(sprintf("body failed: expected empty body, got '%s'\n", $resp_body));
				return -1;
			}
		}

		foreach (keys %{ $href }) {
			## filter special keys
			next if $_ eq 'HTTP-Protocol';
			next if $_ eq 'HTTP-Status';
			next if $_ eq 'HTTP-Content';
			next if $_ eq '-HTTP-Content';

			(my $k = $_) =~ tr/[A-Z]/[a-z]/;

			my $verify_value = 1;
			my $key_inverted = 0;

			if (substr($k, 0, 1) eq '+') {
				## the key has to exist, but the value is ignored
				$k = substr($k, 1);
				$verify_value = 0;
			} elsif (substr($k, 0, 1) eq '-') {
				## the key should NOT exist
				$k = substr($k, 1);
				$key_inverted = 1;
				$verify_value = 0; ## skip the value check
			}

			if ($key_inverted) {
				if (defined $resp_hdr{$k}) {
					diag(sprintf("required header '%s' is missing\n", $k));
					return -1;
				}
			} else {
				if (not defined $resp_hdr{$k}) {
					diag(sprintf("required header '%s' is missing\n", $k));
					return -1;
				}
			}

			if ($verify_value) {
				if ($href->{$_} =~ /^\/(.+)\/$/) {
					if ($resp_hdr{$k} !~ /$1/) {
						diag(sprintf("response-header failed: expected '%s', got '%s', regex: %s\n", 
					             $href->{$_}, $resp_hdr{$k}, $1));
						return -1;
					}
				} elsif ($href->{$_} ne $resp_hdr{$k}) {
					diag(sprintf("response-header failed: expected '%s', got '%s'\n", 
					     $href->{$_}, $resp_hdr{$k}));
					return -1;
				}
			}
		}
	}

	# we should have sucked up everything
	if (defined $lines) {
		diag(sprintf("unexpected lines '$lines'\n"));
		return -1;
	}

	return 0;
}
    
1;

