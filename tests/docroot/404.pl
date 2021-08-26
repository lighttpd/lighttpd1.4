#!/usr/bin/env perl

my $request_uri = $ENV{'REQUEST_URI'};

if ($request_uri =~ m/^\/dynamic\/200\// ) {
  print "Status: 200\n",
        "Content-Type: text/plain\n",
        "\n",
        "found here\n";
}
elsif ($request_uri =~ m|^/dynamic/302/| ) {
  print "Status: 302\n",
        "Location: http://www.example.org/\n",
        "\n";
}
elsif ($request_uri =~ m/^\/dynamic\/404\// ) {
  print "Status: 404\n",
        "Content-Type: text/plain\n",
        "\n",
        "Not found here\n";
}
elsif ($request_uri =~ m/^\/send404\.pl/ ) {
  print "Status: 404\n",
        "Content-Type: text/plain\n",
        "\n",
        "Not found here (send404)\n";
}
elsif ($request_uri =~ m/^\/dynamic\/nostatus\// ) {
  print ("found here\n");
}
elsif ($request_uri =~ m/^\/dynamic\/redirect_status\// ) {
  print "Status: $ENV{'REDIRECT_STATUS'}\n",
        "Content-Type: text/plain\n",
        "\n",
        "REDIRECT_STATUS\n";
}
elsif ($ENV{PATH_INFO} eq "/internal-redir" ) {
  # (not actually 404 error, but use separate script from cgi.pl for testing)
  print "Status: 200\r\n\r\n";
}
else {
  print "Status: 500\n",
        "Content-Type: text/plain\n",
        "\n",
        "huh\n";
};
