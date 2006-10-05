#! /usr/bin/env perl

use strict;

use Test::Harness qw(&runtests $verbose);
$verbose=0;

my $srcdir = (defined $ENV{'srcdir'} ? $ENV{'srcdir'} : '.');

opendir DIR, $srcdir;
my (@fs, $f);
while ($f = readdir(DIR)) {
	if ($f =~ /\.t$/) {
		push @fs, $srcdir.'/'.$f;
	}
}
closedir DIR;
runtests @fs;

