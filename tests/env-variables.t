#!/usr/bin/perl

BEGIN {
    # add current source dir to the include-path
    # we need this for make distcheck
   (my $srcdir = $0) =~ s#/[^/]+$#/#;
   unshift @INC, $srcdir;
}

use strict;
use IO::Socket;
use Test::More tests => 2;
use LightyTest;

my $tf = LightyTest->new();
$tf->{CONFIGFILE} = 'env-variables.conf';

TODO: {
    local $TODO = 'we still crash on undefined environment variables';
    ok($tf->start_proc == 0, "Starting lighttpd");
    ok($tf->stop_proc  == 0, "Stopping lighttpd");
};
