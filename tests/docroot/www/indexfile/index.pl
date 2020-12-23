#!/usr/bin/perl

if ($ENV{REDIRECT_STATUS}) {
    print "Status: $ENV{REDIRECT_STATUS}\r\n\r\n$ENV{SCRIPT_NAME}";
    exit 0;
}

print "Status: 200\r\n\r\n";
