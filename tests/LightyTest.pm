#! /usr/bin/perl -w

package LightyTest;
use strict;
use IO::Socket;
use Test::More;
use Socket;
use Cwd 'abs_path';
use POSIX ":sys_wait_h";

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
		$self->{BINDIR} = $self->{BASEDIR}.'/src';
		if (mtime($self->{BASEDIR}.'/src/.libs')) {
			$self->{MODULES_PATH} = $self->{BASEDIR}.'/src/.libs';
		} else {
			$self->{MODULES_PATH} = $self->{BASEDIR}.'/src';
		}
	} else {
		$self->{BINDIR} = $self->{BASEDIR}.'/build';
		$self->{MODULES_PATH} = $self->{BASEDIR}.'/build';
	}
	$self->{LIGHTTPD_PATH} = $self->{BINDIR}.'/lighttpd';
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

#	open F, $self->{LIGHTTPD_PIDFILE} or return -1;
#	my $pid = <F>;
#	close F;

#	if (defined $pid) {
#		kill('TERM',$pid) or return -1;
#		select(undef, undef, undef, 0.5);
#	}

	my $pid = $self->{LIGHTTPD_PID};
	if (defined $pid) {
		kill('TERM', $pid) or return -1;
		return -1 if ($pid != waitpid($pid, 0));
	} else {
		diag("Nothing to kill\n");
	}

	return 0;
}

sub wait_for_port_with_proc {
	my $self = shift;
	my $port = shift;
	my $child = shift;

	while (0 == $self->listening_on($port)) {
		select(undef, undef, undef, 0.1);

		# the process is gone, we failed
		if (0 != waitpid($child, WNOHANG)) {
			return -1;
		}
	}

	return 0;
}

sub start_proc {
	my $self = shift;
	# kill old proc if necessary
	#$self->stop_proc;

	# pre-process configfile if necessary
	#

	$ENV{'SRCDIR'} = $self->{BASEDIR}.'/tests';
	$ENV{'PORT'} = $self->{PORT};

	unlink($self->{LIGHTTPD_PIDFILE});
	my $cmdline = $self->{LIGHTTPD_PATH}." -D -f ".$self->{SRCDIR}."/".$self->{CONFIGFILE}." -m ".$self->{MODULES_PATH};
	if (defined $ENV{"TRACEME"} && $ENV{"TRACEME"} eq 'strace') {
		$cmdline = "strace -tt -s 512 -o strace ".$cmdline;
	} elsif (defined $ENV{"TRACEME"} && $ENV{"TRACEME"} eq 'truss') {
		$cmdline = "truss -a -l -w all -v all -o strace ".$cmdline;
	} elsif (defined $ENV{"TRACEME"} && $ENV{"TRACEME"} eq 'gdb') {
		$cmdline = "gdb --batch --ex 'run' --ex 'bt' --args ".$cmdline." > gdb.out";
	} elsif (defined $ENV{"TRACEME"} && $ENV{"TRACEME"} eq 'valgrind') {
		$cmdline = "valgrind --tool=memcheck --show-reachable=yes --leak-check=yes --log-file=valgrind ".$cmdline;
	}
	# diag("starting lighttpd at :".$self->{PORT}.", cmdline: ".$cmdline );
	my $child = fork();
	if (not defined $child) {
		diag("Fork failed");
		return -1;
	}
	if ($child == 0) {
		exec $cmdline or die($?);
	}
#	system($cmdline) == 0 or die($?);

	unlink($self->{TESTDIR}."/tmp/cfg.file");

	if (0 != $self->wait_for_port_with_proc($self->{PORT}, $child)) {
		diag(sprintf('The process %i is not up', $child));
		return -1;
	}

	$self->{LIGHTTPD_PID} = $child;

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
	my $is_debug = $ENV{"TRACE_HTTP"};

	my $remote = 
 	  IO::Socket::INET->new(Proto    => "tcp",
				PeerAddr => $host,
				PeerPort => $self->{PORT});

	if (not defined $remote) {
		diag("connect failed: $!");
	       	return -1;
	}

	$remote->autoflush(1);

	diag("sending request header to ".$host.":".$self->{PORT}) if $is_debug;
	foreach(@request) {
		# pipeline requests
		s/\r//g;
		s/\n/$EOL/g;

		print $remote $_.$BLANK;
		diag("<< ".$_) if $is_debug;
	}
	shutdown($remote, 1); # I've stopped writing data
	diag("... done") if $is_debug;

	my $lines = "";

	diag("receiving response") if $is_debug;
	# read everything
	while(<$remote>) {
		$lines .= $_;
		diag(">> ".$_) if $is_debug;
	}
	diag("... done") if $is_debug;
	
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
						diag(sprintf("header '%s' is duplicated: '%s' and '%s'\n",
						             $h, $resp_hdr{$h}, $2));
					} else {
						$resp_hdr{$h} = $2;
					}
				} else {
					diag(sprintf("unexpected line '%s'\n", $line));
					return -1;
				}
			}
		}

		if (not defined($resp_line)) {
			diag(sprintf("empty response\n"));
			return -1;
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
			diag(sprintf("unexpected resp_line '%s'\n", $resp_line));
			return -1;
		}

		if (defined $href->{'HTTP-Content'}) {
			$resp_body = "" unless defined $resp_body;
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

			my $verify_value = 1;
			my $key_inverted = 0;

			if (substr($k, 0, 1) eq '+') {
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
					diag(sprintf("header '%s' MUST not be set\n", $k));
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
		diag(sprintf("unexpected lines '%s'\n", $lines));
		return -1;
	}

	return 0;
}

sub spawnfcgi {
	my ($self, $binary, $port) = @_;
	my $child = fork();
	if (not defined $child) {
		diag("Couldn't fork\n");
		return -1;
	}
	if ($child == 0) {
		my $cmd = $self->{BINDIR}.'/spawn-fcgi -n -p '.$port.' -f "'.$binary.'"';
		exec $cmd or die($?);
	} else {
		if (0 != $self->wait_for_port_with_proc($port, $child)) {
			diag(sprintf('The process %i is not up (port %i, %s)', $child, $port, $binary));
			return -1;
		}
		return $child;
	}
}

sub endspawnfcgi {
	my ($self, $pid) = @_;
	return -1 if (-1 == $pid);
	kill(2, $pid);
	waitpid($pid, 0);
	return 0;
}

1;
