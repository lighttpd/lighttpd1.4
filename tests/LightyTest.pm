package LightyTest;

use strict;
use IO::Socket ();
use Test::More; # diag()
use Socket;
use Cwd 'abs_path';
use Config;

$ENV{PERL} = $Config{perlpath} . $Config{_exe};

sub mtime {
	my $file = shift;
	my @stat = stat $file;
	return @stat ? $stat[9] : 0;
}

sub new {
	my $class = shift;
	my $self = {};
	my $lpath;
	my $exe = $^O eq "cygwin" ? ".exe" : "";

	$self->{CONFIGFILE} = 'lighttpd.conf';

	$lpath = (defined $ENV{'top_builddir'} ? $ENV{'top_builddir'} : '..');
	$self->{BASEDIR} = abs_path($lpath);

	$lpath = (defined $ENV{'top_builddir'} ? $ENV{'top_builddir'}."/tests" : '.');
	$self->{TESTDIR} = abs_path($lpath);

	if (mtime($self->{BASEDIR}."/src/lighttpd$exe") > mtime($self->{BASEDIR}."/build/lighttpd$exe")) {
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
	$self->{LIGHTTPD_PATH} = $self->{BINDIR}."/lighttpd$exe";
	if (exists $ENV{LIGHTTPD_EXE_PATH}) {
		$self->{LIGHTTPD_PATH} = $ENV{LIGHTTPD_EXE_PATH};
	}

	# test for cygwin w/ _WIN32 native lighttpd.exe (not linked w/ cygwin1.dll)
	#   ($^O eq "MSWin32") is untested; not supported
	$self->{"win32native"} = $^O eq "cygwin"
	                      && 0 != system("ldd '$$self{LIGHTTPD_PATH}' | grep -q cygwin");

	my ($name, $aliases, $addrtype, $net) = gethostbyaddr(inet_aton("127.0.0.1"), AF_INET);

	$self->{HOSTNAME} = $name;

	bless($self, $class);

	return $self;
}

sub listening_on {
	my $self = shift;
	my $port = shift;

	local $@;
	local $SIG{ALRM} = sub { };
    eval {
	local $SIG{ALRM} = sub { die 'alarm()'; };
	alarm(1);
	my $remote = IO::Socket::INET->new(
		Timeout  => 1,
		Proto    => "tcp",
		PeerAddr => "127.0.0.1",
		PeerPort => $port) || do { alarm(0); die 'socket()'; };

	close $remote;
	alarm(0);
    };
	alarm(0);
	return (defined($@) && $@ eq "");
}

sub stop_proc {
	my $self = shift;

	my $pid = $self->{LIGHTTPD_PID};
	if (defined $pid && $pid != -1) {
		if ($self->{"win32native"}) {
			# kill process tree; not a graceful shutdown of lighttpd or backends
			#
			# https://cygwin.com/cygwin-ug-net/kill.html
			# aside: /bin/kill is not the same as shell builtin kill
			# Still, lighttpd currently does not appear able to catch
			# signals from Perl kill() or from /bin/kill, and so the
			# process tree including backends is not cleaned up; only
			# lighttpd is killed.
			# system('/bin/kill', '-s', 'INT', '-f', '-W', $winpid) == 0 or return -1;
			#
			# powershell kill -Force -Id $winpid          (same as Stop-Process)
			# powershell Stop-Process -Force -Id $winpid  (same as kill)
			# powershell Stop-Process -Force -Name lighttpd.exe
			#
			# sysinternal tools
			# https://docs.microsoft.com/en-us/sysinternals/downloads/pskill
			#   pskill -nobanner -t $winpid
			#   pskill -nobanner -t lighttpd.exe
			#
			my $winpid = 0;
			if (open(my $WH, "<", "/proc/$pid/winpid")) {
				$winpid = <$WH>;
				chomp($winpid);
				close($WH);
			}
			if ($winpid) {
				system('/cygdrive/c/windows/system32/taskkill.exe', '/F', '/T', '/PID', $winpid);
			}
			else {
				system('/cygdrive/c/windows/system32/taskkill.exe', '/F', '/T', '/IM', 'lighttpd.exe');
			}
		}
		else {
			kill('USR1', $pid) if (($ENV{"TRACEME"}||'') eq 'strace');
			kill('TERM', $pid) or return -1;
		}
		return -1 if ($pid != waitpid($pid, 0));
	} else {
		diag("\nProcess not started, nothing to stop");
		return -1;
	}

	return 0;
}

sub wait_for_port_with_proc {
	my $self = shift;
	my $port = shift;
	my $child = shift;
	my $timeout = 10*100; # 10 secs (valgrind might take a while), select waits 0.01 s

	while (0 == $self->listening_on($port)) {
		select(undef, undef, undef, 0.01);
		$timeout--;

		# the process is gone, we failed
		require POSIX;
		if (0 != waitpid($child, POSIX::WNOHANG())) {
			return -1;
		}
		if (0 >= $timeout) {
			diag("\nTimeout while trying to connect; killing child");
			kill('TERM', $child);
			return -1;
		}
	}

	return 0;
}

sub bind_ephemeral_tcp_socket {
	my $SOCK;
	socket($SOCK, PF_INET, SOCK_STREAM, 0) || die "socket: $!";
	setsockopt($SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) || die "setsockopt: $!";
	bind($SOCK, sockaddr_in(0, INADDR_LOOPBACK)) || die "bind: $!";
	my($port) = sockaddr_in(getsockname($SOCK));
	return ($SOCK, $port);
}

sub get_ephemeral_tcp_port {
	# bind to an ephemeral port, close() it, and return port that was used
	# (While there is a race condition before caller may reuse the port,
	#  the port is likely to remain available for the serialized tests)
	my $port;
	(undef, $port) = bind_ephemeral_tcp_socket();
	return $port;
}

sub cygpath_alm {
    my $FH;
    open($FH, '-|', "cygpath", "-alm", $_[0]) || return $_[0];
    my $result = <$FH>;
    close $FH;
    chomp $result;
    $result =~ s/^[A-Z]://i unless $_[1]; # remove volume (C:)
    return $result;
}

sub start_proc {
	my $self = shift;
	# kill old proc if necessary
	#$self->stop_proc;

	# listen on localhost and kernel-assigned ephemeral port
	my $SOCK;
	($SOCK, $self->{PORT}) = bind_ephemeral_tcp_socket();

	my $child = fork();
	if (not defined $child) {
		diag("\nFork failed");
		close($SOCK);
		return -1;
	}
	if ($child == 0) {

		my $testdir      = $self->{TESTDIR};
		my $conf         = $self->{TESTDIR}.'/'.$self->{CONFIGFILE};
		my $modules_path = $self->{MODULES_PATH};

		if ($self->{"win32native"}) {
			$ENV{SHELL}         = "/bin/sh";
			$ENV{PERL}          = cygpath_alm($ENV{PERL});
			$testdir            = cygpath_alm($testdir);
			$conf               = cygpath_alm($conf);
			$modules_path       = cygpath_alm($modules_path);

			$ENV{CYGROOT}       = cygpath_alm("/", 1);
			$ENV{CYGVOL}        = $ENV{CYGROOT} =~ m%^([a-z]):%i
			                      ? "/cygdrive/$1"
			                      : "/cygdrive/c";

			# On platforms where systemd socket activation is not supported
			# or inconvenient for testing (i.e. cygwin <-> native Windows exe),
			# there is a race condition with close() before server start,
			# but port specific port is unlikely to be reused so quickly,
			# and the point is to avoid a port which is already in use.
			close($SOCK);
			my $CONF;
			open($CONF,'>',$self->{TESTDIR}."/tmp/bind.conf") || die "open: $!";
			print $CONF <<BIND_OVERRIDE;
server.systemd-socket-activation := "disable"
server.bind = "127.0.0.1"
server.port = $$self{'PORT'}
server.modules += ("mod_setenv")
setenv.set-environment += ("CYGROOT" => "$ENV{CYGROOT}")
BIND_OVERRIDE
		}
		else {
			# set up systemd socket activation env vars
			$ENV{LISTEN_FDS} = "1";
			$ENV{LISTEN_PID} = $$;
			if (defined($ENV{"TRACEME"}) && $ENV{"TRACEME"} ne "valgrind") {
				$ENV{LISTEN_PID} = "parent:$$"; # lighttpd extension
			}
			listen($SOCK, 1024) || die "listen: $!";
			if (fileno($SOCK) != 3) { # SD_LISTEN_FDS_START 3
				require POSIX;
				POSIX::dup2(fileno($SOCK), 3) || die "dup2: $!";
				close($SOCK);
			}
			else {
				require Fcntl;
				fcntl($SOCK, Fcntl::F_SETFD(), 0); # clr FD_CLOEXEC
			}
		}

		$ENV{'SRCDIR'} = $testdir;

		my @cmdline = ($self->{LIGHTTPD_PATH}, "-D", "-f", $conf, "-m", $modules_path);
		splice(@cmdline, -2) if exists $ENV{LIGHTTPD_EXE_PATH};
		if (!defined $ENV{"TRACEME"}) {
		} elsif ($ENV{"TRACEME"} eq 'strace') {
			@cmdline = (qw(strace -tt -s 4096 -o strace -f -v), @cmdline);
		} elsif ($ENV{"TRACEME"} eq 'truss') {
			@cmdline = (qw(truss -a -l -w all -v all -o strace), @cmdline);
		} elsif ($ENV{"TRACEME"} eq 'gdb') {
			@cmdline = ('gdb', '--batch', '--ex', 'run', '--ex', 'bt full', '--args', @cmdline);
		} elsif ($ENV{"TRACEME"} eq 'valgrind') {
			@cmdline = (qw(valgrind --tool=memcheck --track-origins=yes --show-reachable=yes --leak-check=yes --log-file=valgrind.%p), @cmdline);
		}
		#diag("\nstarting lighttpd at :$$self{PORT}, cmdline: @cmdline");
		#diag(sprintf('\ncmd: %s', "@cmdline"));
		exec @cmdline or die($?);
	}
	close($SOCK);

	if (0 != $self->wait_for_port_with_proc($self->{PORT}, $child)) {
		diag(sprintf('\nThe process %i is not up', $child));
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
	my $slow = defined $t->{SLOWREQUEST};
	my $is_debug = $ENV{"TRACE_HTTP"};

	my $remote =
		IO::Socket::INET->new(
			Proto    => "tcp",
			PeerAddr => $host,
			PeerPort => $self->{PORT});

	if (not defined $remote) {
		diag("\nconnect failed: $!");
		return -1;
	}

	$remote->autoflush(1);
	my $ipproto_tcp = defined &Socket::IPPROTO_TCP ? Socket::IPPROTO_TCP : 6;
	my $tcp_nodelay = defined &Socket::TCP_NODELAY ? Socket::TCP_NODELAY : 1;
	$remote->setsockopt($ipproto_tcp, $tcp_nodelay, 1); # (ignore rc)

	diag("\nsending request header to ".$host.":".$self->{PORT}) if $is_debug;
	foreach(@request) {
		# pipeline requests
		chomp;
		s/\r//g;
		s/\n/$EOL/g;

		diag("<< ".$_."\n") if $is_debug;
		if (!$slow) {
			print $remote $_,$BLANK;
		}
		else {
			print $remote $_;
			print $remote "\015";
			print $remote "\012";
			print $remote "\015";
			print $remote "\012";
		}
	}
	if ($^O ne "openbsd" && $^O ne "dragonfly" && !$self->{"win32native"}) {
		# (avoid on OS where TCP half-close may be reported as POLLHUP)
		shutdown($remote, 1); # I've stopped writing data
	}
	diag("\n... done") if $is_debug;

	my $lines = "";

	diag("\nreceiving response") if $is_debug;
	# read everything
	while(<$remote>) {
		$lines .= $_;
		diag(">> ".$_) if $is_debug;
	}
	diag("\n... done") if $is_debug;

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
			last if(!defined $line or length($line) == 0);

			if ($ln == 0) {
				# response header
				$resp_line = $line;
			} else {
				# response vars

				if ($line =~ /^([^:]+):\s*(.+)$/) {
					(my $h = $1) =~ tr/[A-Z]/[a-z]/;

					if (defined $resp_hdr{$h}) {
#						diag(sprintf("\nheader '%s' is duplicated: '%s' and '%s'\n",
#						             $h, $resp_hdr{$h}, $2));
						$resp_hdr{$h} .= ', '.$2;
					} else {
						$resp_hdr{$h} = $2;
					}
				} else {
					diag(sprintf("\nunexpected line '%s'", $line));
					return -1;
				}
			}
		}

		if (not defined($resp_line)) {
			diag(sprintf("\nempty response"));
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
				diag(sprintf("\nproto failed: expected '%s', got '%s'", $href->{'HTTP-Protocol'}, $1));
				return -1;
			}
			if ($href->{'HTTP-Status'} ne $2) {
				diag(sprintf("\nstatus failed: expected '%s', got '%s'", $href->{'HTTP-Status'}, $2));
				return -1;
			}
		} else {
			diag(sprintf("\nunexpected resp_line '%s'", $resp_line));
			return -1;
		}

		if (defined $href->{'HTTP-Content'}) {
			$resp_body = "" unless defined $resp_body;
			if ($href->{'HTTP-Content'} ne $resp_body) {
				diag(sprintf("\nbody failed: expected '%s', got '%s'", $href->{'HTTP-Content'}, $resp_body));
				return -1;
			}
		}

		if (defined $href->{'-HTTP-Content'}) {
			if (defined $resp_body && $resp_body ne '') {
				diag(sprintf("\nbody failed: expected empty body, got '%s'", $resp_body));
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
					diag(sprintf("\nheader '%s' MUST not be set", $k));
					return -1;
				}
			} else {
				if (not defined $resp_hdr{$k}) {
					diag(sprintf("\nrequired header '%s' is missing", $k));
					return -1;
				}
			}

			if ($verify_value) {
				if ($href->{$_} =~ /^\/(.+)\/$/) {
					if ($resp_hdr{$k} !~ /$1/) {
						diag(sprintf(
							"\nresponse-header failed: expected '%s', got '%s', regex: %s",
							$href->{$_}, $resp_hdr{$k}, $1));
						return -1;
					}
				} elsif ($href->{$_} ne $resp_hdr{$k}) {
					diag(sprintf(
						"\nresponse-header failed: expected '%s', got '%s'",
						$href->{$_}, $resp_hdr{$k}));
					return -1;
				}
			}
		}
	}

	# we should have sucked up everything
	if (defined $lines) {
		diag(sprintf("\nunexpected lines '%s'", $lines));
		return -1;
	}

	return 0;
}

sub spawnfcgi {
	my ($self, $binary, $port) = @_;
	my $child = fork();
	if (not defined $child) {
		diag("\nCouldn't fork");
		return -1;
	}
	if ($child == 0) {
		my $iaddr   = inet_aton('localhost') || die "no host: localhost";
		my $proto   = getprotobyname('tcp');
		socket(SOCK, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
		setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) || die "setsockopt: $!";
		bind(SOCK, sockaddr_in($port, $iaddr)) || die "bind: $!";
		listen(SOCK, 1024) || die "listen: $!";
		require POSIX;
		POSIX::dup2(fileno(SOCK), 0) || die "dup2: $!";
		exec { $binary } ($binary) or die($?);
	} else {
		if (0 != $self->wait_for_port_with_proc($port, $child)) {
			diag(sprintf("\nThe process %i is not up (port %i, %s)", $child, $port, $binary));
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

sub has_feature {
	# quick-n-dirty crude parse of "lighttpd -V"
	# (XXX: should be run on demand and only once per instance, then cached)
	my ($self, $feature) = @_;
	my $FH;
	open($FH, "-|",$self->{LIGHTTPD_PATH}, "-V") || return 0;
	while (<$FH>) {
		return ($1 eq '+') if (/([-+]) \Q$feature\E/);
	}
	close $FH;
	return 0;
}

sub has_crypto {
	# quick-n-dirty crude parse of "lighttpd -V"
	# (XXX: should be run on demand and only once per instance, then cached)
	my ($self) = @_;
	my $FH;
	open($FH, "-|",$self->{LIGHTTPD_PATH}, "-V") || return 0;
	while (<$FH>) {
		#return 1 if (/[+] (?i:OpenSSL|mbedTLS|GnuTLS|WolfSSL|Nettle|NSS crypto) support/);
		return 1 if (/[+] (?i:OpenSSL|mbedTLS|GnuTLS|WolfSSL|Nettle) support/);
	}
	close $FH;
	return 0;
}

1;
