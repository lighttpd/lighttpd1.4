#! /usr/bin/perl -w

use strict;
use IO::Socket;

my $EOL = "\015\012";
my $BLANK = $EOL x 2;


my @f = <STDIN>;

# drop first line
my $headline = shift @f;
chomp $headline;
printf STDERR "%-40s", $headline." ";


my $remote = 
  IO::Socket::INET->new(Proto    => "tcp",
			PeerAddr => "127.0.0.1",
			PeerPort => $#ARGV == 0 ? "1025" : "2048")
  or die "cannot connect to remote host";

$remote->autoflush(1);

my %y;
my $m = 0;
my $line = 0;
my $method;
foreach(@f) {
    if (/^$/) {
	$m = 1;
	next;
    }
    
    chomp;
    if ($m == 0) {
	    # header line
	    #
	    if ($line++ == 0) {
		    ($method = $_ ) =~ s/ .*//;
	    }
	print $remote $_.$EOL;
    } else {
	my ($key, $value) = split /: /, $_;
	
	$y{$key} = $value;
    }
}
print $remote $EOL;

my $ln = 0;
my $error = 0;
my $con_len = -1;
my $body = "";
$m = 0;

my %header;
while(<$remote>) {
    $ln++;
    
#    print STDERR $_;
    
    if ($ln == 1) {
	if (/^HTTP/) {
	    my ($proto, $status, $text) = split / /, $_, 3;
	    if (defined $y{"Status"}) {
		if ($status ne $y{"Status"}) {
		    $error = 1;
		    print STDERR "E: wrong Status code - ";
		}
	    } 
	} elsif ($y{"Protocol"} eq "HTTP/0.9") {
	    # we expected HTTP/0.9 or Bad Protocol
	    $m = 1;
	} else {
	    $error = 1;
	    print STDERR "E: broken something - ";
	}
    } elsif ($m == 0) {
	# response header 
	my ($key, $value) = split /: /, $_;
	
	if (not /^\r$/) {
	    ($header{$key} = $value) =~ s/\r\n$//;
	}
    }
    
    # grep for content-length
    if (/^Content-Length: ([0-9]+)\r$/) {
	$con_len = $1;
    }
    
    if ($m == 1) {
	$body .= $_;
    }
    
    if (/^\r$/) {
	$m = 1;
    }
    
    print $_;
    
    if ($m == 1 && (length($body) == $con_len)) {
#	print STDERR length($body)." - ".$con_len."\n";
	last;
    }
}

close $remote;

if ($con_len != -1 && $method ne "HEAD" && $m == 1 && (length($body) != $con_len)) {
    $error = 1;
    print STDERR "E: wrong content-length - ";
}

# check the MUST header

if (defined $y{"MUST"}) {
    foreach (split / /, $y{"MUST"}) {
	if (not defined $header{$_}) {
	    $error = 1;
	    print STDERR "E: MUST missing - ";
	}
    }
}
my $might = 0;
if (defined $y{"MIGHT"}) {
    foreach (split / /, $y{"MIGHT"}) {
	if (not defined $header{$_}) {
	    $might = 1;
	}
    }
}

if (defined $y{"Content"}) {
	if ($body ne $y{"Content"}) {
	    $error = 1;
	    print STDERR "E: Content doesn't match - ";
	}
}

foreach (keys %y) {
    next if /^MIGHT$/;
    next if /^MUST$/;
    next if /^Status$/;
    next if /^Protocol$/;
    next if /^Content$/;
    
    if ((not defined $header{$_}) || 
	($header{$_} ne $y{$_})) {
	    $error = 1;
	    print STDERR "E: headerline missing - ";
    }
}

if ($error) {
    exit 1;
} elsif ($might) {
    exit 77;
} else {
    exit 0;
}

