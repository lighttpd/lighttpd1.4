#!/usr/bin/env perl

use CGI qw/:standard/;

my $cgi = new CGI;
my $request_uri = $ENV{'REQUEST_URI'};  # server.error-handler-404
my $redirect_uri= $ENV{'REDIRECT_URI'}; # server.error-handler
print (STDERR "REQUEST_URI:  $request_uri\n");
print (STDERR "REDIRECT_URI: $redirect_uri\n");

if ($request_uri =~ m/^\/dynamic\/200\// ) {
  print header ( -status => 200,
                 -type   => 'text/plain' );
  print ("found here\n");
}
elsif ($request_uri =~ m|^/dynamic/302/| ) {
  print header( -status=>302,
                -location => 'http://www.example.org/');
}
elsif ($request_uri =~ m/^\/dynamic\/404\// ) {
  print header ( -status => 404
                 -type   => 'text/plain' );
  print ("Not found here\n");
}
elsif ($request_uri =~ m/^\/send404\.pl/ ) {
  print header ( -status => 404
                 -type   => 'text/plain' );
  print ("Not found here (send404)\n");
}
elsif ($request_uri =~ m/^\/dynamic\/nostatus\// ) {
  print ("found here\n");
}
elsif ($redirect_uri =~ m/^\/dynamic\/redirect_status\// ) {
  print header ( -status => $ENV{'REDIRECT_STATUS'},
                 -type   => 'text/plain');
  print ("REDIRECT_STATUS\n");
}
else {
  print header ( -status => 500,
                 -type   => 'text/plain');
  print ("huh\n");
};
