#!/usr/bin/env perl

# env
if ($ENV{"QUERY_STRING"} =~ /^env=(\w+)/) {
    print "Status: 200\r\n\r\n$ENV{$1}";
    exit 0;
}

# redirection
if ($ENV{"QUERY_STRING"} eq "internal-redir") {
    # (not actually 404 error, but use separate script from cgi.pl for testing)
    print "Location: /404.pl/internal-redir\r\n\r\n";
    exit 0;
}

# redirection
if ($ENV{"QUERY_STRING"} eq "external-redir") {
    print "Location: http://www.example.org:2048/\r\n\r\n";
    exit 0;
}

# 404
if ($ENV{"QUERY_STRING"} eq "send404") {
    print "Status: 404\n\nsend404\n";
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

# NPH
if ($ENV{"QUERY_STRING"} =~ /^nph=(\w+)/) {
    print "Status: $1 FooBar\r\n\r\n";
    exit 0;
}

# crlfcrash
if ($ENV{"QUERY_STRING"} eq "crlfcrash") {
    print "Location: http://www.example.org/\r\n\n\n";
    exit 0;
}

# POST length
if ($ENV{"QUERY_STRING"} eq "post-len") {
    $cl = $ENV{CONTENT_LENGTH} || 0;
    my $len = 0;
    if ($ENV{"REQUEST_METHOD"} eq "POST") {
        while (<>) { # expect test data to end in newline
            $len += length($_);
            last if $len >= $cl;
        }
    }
    print "Status: 200\r\n\r\n$len";
    exit 0;
}

# default
print "Content-Type: text/plain\r\n\r\n";
print $ENV{"QUERY_STRING"};

0;
