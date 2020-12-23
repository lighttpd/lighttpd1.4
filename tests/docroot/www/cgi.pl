#!/usr/bin/env perl

if ($ENV{"QUERY_STRING"} eq "internal-redir") {
    print "Location: /cgi-pathinfo.pl/foo\r\n\r\n";
    exit 0;
}

if ($ENV{"QUERY_STRING"} eq "external-redir") {
    print "Location: http://www.example.org:2048/\r\n\r\n";
    exit 0;
}

# X-Sendfile
if ($ENV{"QUERY_STRING"} eq "xsendfile") {
    # urlencode path for CGI header
    # (including urlencode ',' if in path, for X-Sendfile2 w/ FastCGI (not CGI))
    # (This implementation is not minimal encoding;
    #  encode everything that is not alphanumeric, '.' '_', '-', '/')
    require Cwd;
    my $path = Cwd::getcwd() . "/index.txt";
    $path =~ s#([^\w./-])#"%".unpack("H2",$1)#eg;

    print "Status: 200\r\n";
    print "X-Sendfile: $path\r\n\r\n";
    exit 0;
}

# env
if ($ENV{"QUERY_STRING"} =~ /^env=(\w+)/) {
    print "Status: 200\r\n\r\n$ENV{$1}";
    exit 0;
}

# default
print "Content-Type: text/html\r\n\r\n";

print $ENV{"SCRIPT_NAME"};

0;
