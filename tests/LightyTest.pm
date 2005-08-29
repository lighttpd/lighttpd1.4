#! /usr/bin/perl -w

package LightyTest;
use strict;
use IO::Socket;
use Test::More;

sub new {
	my $class = shift;
	my $self = {};
	my $lpath;

	$self->{CONFIGFILE} = 'lighttpd.conf';

	$lpath = (defined $ENV{'top_builddir'} ? $ENV{'top_builddir'} : '..');
	$lpath = `readlink -f '$lpath'`;
	chomp $lpath;
	$self->{BASEDIR} = $lpath;

	$lpath = (defined $ENV{'top_builddir'} ? $ENV{'top_builddir'}."/tests/" : '.');
	$lpath = `readlink -f '$lpath'`;
	chomp $lpath;
	$self->{TESTDIR} = $lpath;

	$lpath = (defined $ENV{'srcdir'} ? $ENV{'srcdir'} : '.');
	$lpath = `readlink -f '$lpath'`;
	chomp $lpath;
	$self->{SRCDIR} = $lpath;


	$self->{LIGHTTPD_PATH} = $self->{BASEDIR}.'/src/lighttpd';
	$self->{LIGHTTPD_PIDFILE} = $self->{TESTDIR}.'/tmp/lighttpd/lighttpd.pid';
	$self->{PIDOF_PIDFILE} = $self->{TESTDIR}.'/tmp/lighttpd/pidof.pid';
	$self->{PORT} = 2048;
	
	bless($self, $class);

	return $self;
}

sub pidof {
	my $self = shift;
	my $prog = shift;

	open F, "ps ax  | grep $prog | grep -v grep | awk '{ print \$1 }'|" or
	open F, "ps -ef | grep $prog | grep -v grep | awk '{ print \$2 }'|" or
	  return -1;

	my $pid = <F>;
	close F;

	if (defined $pid) { return $pid; }

	return -1;
}

sub stop_proc {
	my $self = shift;

	open F, $self->{LIGHTTPD_PIDFILE} or return -1;
	my $pid = <F>;
	close F;

	if (defined $pid) {
		kill('TERM',$pid) or return -1;
		select(undef, undef, undef, 0.01);
	}

	return 0;
}


sub start_proc {
	my $self = shift;
	# kill old proc if necessary
	$self->stop_proc;

	# pre-process configfile if necessary
	#

	unlink($self->{TESTDIR}."/tmp/cfg.file");
	system("cat ".$self->{SRCDIR}."/".$self->{CONFIGFILE}.' | perl -pe "s#\@SRCDIR\@#'.$self->{BASEDIR}.'/tests/#" > '.$self->{TESTDIR}.'/tmp/cfg.file');

	unlink($self->{LIGHTTPD_PIDFILE});
	if (1) {
		system($self->{LIGHTTPD_PATH}." -f ".$self->{TESTDIR}."/tmp/cfg.file -m ".$self->{BASEDIR}."/src/.libs");
		select(undef, undef, undef, 0.1);
	} else {
		system("valgrind --tool=memcheck --show-reachable=yes --leak-check=yes --logfile=foo ".$self->{LIGHTTPD_PATH}." -D -f ".$self->{TESTDIR}."/tmp/cfg.file -m ".$self->{BASEDIR}."/src/.libs &");
		select(undef, undef, undef, 2);
	}
	

	# sleep(1);

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

#					if (defined $resp_hdr{$h}) {
#						diag(sprintf("header %s is duplicated: %s and %s\n",
#						             $h, $resp_hdr{$h}, $2));
#						return -1;	
#					}

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

			my $no_val = 0;

			if (substr($k, 0, 1) eq '+') {
				$k = substr($k, 1);
				$no_val = 1;

			}

			if (!defined $resp_hdr{$k}) {
				diag(sprintf("required header '%s' is missing\n", $k));
				return -1;
			}

			if ($no_val == 0) {
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
	return -1 if (defined $lines); 

	return 0;
}
    
1;

