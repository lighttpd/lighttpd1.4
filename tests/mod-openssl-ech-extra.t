#!/usr/bin/env perl
BEGIN {
	# add current source dir to the include-path
	# we need this for make distcheck
	(my $srcdir = $0) =~ s,/[^/]+$,/,;
	unshift @INC, $srcdir;
}

use strict;
use File::Path qw(make_path);
use MIME::Base64 qw(encode_base64);
use Test::More tests => 30;
use LightyTest;

my $tf = LightyTest->new();
my $openssl = $ENV{OPENSSL} || find_tool('openssl');
my $curl = $ENV{CURL} || find_tool('curl');
my $bssl = $ENV{BSSL} || find_tool('bssl');
my $timeout_cmd = $ENV{TIMEOUT} || find_tool('timeout');
my $ldd = find_tool('ldd');
my $nm = find_tool('nm');
my $module = $tf->{MODULES_PATH} . '/mod_openssl.so';
my $tmpdir = $tf->{TESTDIR} . '/tmp/lighttpd';
my $tlsdir = $tmpdir . '/tls';
my $echbase = $tmpdir . '/ech-extra';
my $echvalid = $echbase . '/valid';
my $echinvalid = $echbase . '/invalid';
my $public_root = $tmpdir . '/servers/ech-public/pages';
my $hidden_root = $tmpdir . '/servers/ech-hidden/pages';
my $errorlog = $tmpdir . '/logs/lighttpd-ssl-ech-extra.error.log';
my $stderrlog = $tmpdir . '/logs/lighttpd-ssl-ech-extra.stderr.log';
my $public_host = 'example.com';
my $hidden_host = 'hidden.example.com';
my $public_body = "public ECH fallback vhost\n";
my $hidden_body = "hidden ECH-only vhost\n";

SKIP: {
	my @missing;
	push @missing, 'crypto support' unless $tf->has_crypto();
	push @missing, 'openssl' unless $openssl;
	push @missing, 'curl' unless $curl;
	push @missing, 'bssl' unless $bssl;
	push @missing, 'timeout' unless $timeout_cmd;
	push @missing, 'mod_openssl.so' unless -f $module;
	push @missing, 'ECH-capable libssl' unless linked_libssl_has_ech($module, $ldd, $nm);
	push @missing, 'bssl generate-ech' unless bssl_supports_generate_ech($bssl);
	skip 'missing ECH extra test prerequisites: ' . join(', ', @missing), 30 if @missing;

	make_path($tlsdir, $echvalid, $echinvalid, $public_root, $hidden_root);
	$ENV{LIGHTTPD_STDERR_FILE} = $stderrlog;

	my $tls_cert = $tlsdir . '/server.crt';
	my $tls_key = $tlsdir . '/server.key';
	my $valid_cfg = $echvalid . '/ech_config.bin';
	my $valid_cfg_list = $echvalid . '/ech_config_list.bin';
	my $valid_priv = $echvalid . '/ech_private_key.bin';
	my $valid_pem = $echvalid . '/example.com.ech';
	my $invalid_cfg_list = $echinvalid . '/ech_config_list.bin';

	my ($rc, $out) = run_cmd(15, undef,
		$openssl, 'req',
		'-x509', '-newkey', 'rsa:2048', '-nodes',
		'-keyout', $tls_key,
		'-out', $tls_cert,
		'-days', '1',
		'-subj', '/CN=example.com',
		'-addext', 'subjectAltName=DNS:example.com,DNS:hidden.example.com,IP:127.0.0.1');
	ok($rc == 0 && -s $tls_cert && -s $tls_key, 'generated TLS certificate fixture')
	  or diag($out);

	($rc, $out) = run_cmd(10, undef,
		$bssl, 'generate-ech',
		'-public-name', $public_host,
		'-config-id', '11',
		'-out-ech-config-list', $valid_cfg_list,
		'-out-ech-config', $valid_cfg,
		'-out-private-key', $valid_priv);
	ok($rc == 0
	   && -s $valid_cfg_list
	   && write_ech_pem($valid_pem, $valid_priv, $valid_cfg),
	   'generated server ECH fixture')
	  or diag($out);

	my $valid_cfg_raw = slurp_file($valid_cfg_list);
	my $invalid_cfg_raw =
	  defined($valid_cfg_raw) && length($valid_cfg_raw) > 1
	  ? substr($valid_cfg_raw, 0, length($valid_cfg_raw) - 1)
	  : undef;
	ok(defined($invalid_cfg_raw)
	   && write_file($invalid_cfg_list, $invalid_cfg_raw)
	   && -s $invalid_cfg_list,
	   'generated malformed client ECH config fixture');

	ok(write_file($public_root . '/index.txt', $public_body)
	   && write_file($hidden_root . '/index.txt', $hidden_body),
	   'wrote distinct public and hidden vhost content fixtures');

	$ENV{ECH_KEYDIR} = $echvalid;
	clear_error_log($errorlog);
	clear_error_log($stderrlog);
	$tf->{CONFIGFILE} = 'mod-openssl-ech-extra.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();

	# Validate the public vhost baseline so fallback comparisons have a known target.
	assert_curl_https_body($tf, $public_host, $public_body,
		'public vhost baseline served expected content without ECH');

	# Validate that a non-ECH client falls back to the public/default vhost.
	($rc, $out) = bssl_http_get($tf, $hidden_host, undef, $bssl, 'HTTP/1.0');
	my $fallback_resp = parse_http_response($out);
	my $fallback_state = extract_ech_state($out);
	ok($rc == 0, 'ECH fallback: non-ECH client completed TLS handshake') or diag($out);
	is($fallback_state, 'no', 'ECH fallback: non-ECH handshake stayed on standard TLS') or diag($out);
	ok($fallback_resp && $fallback_resp->{status} == 200,
	   'ECH fallback: non-ECH request returned HTTP 200') or diag($out);
	is($fallback_resp ? $fallback_resp->{body} : undef, $public_body,
	   'ECH fallback: hidden host without ECH served public vhost content') or diag($out);
	isnt($fallback_resp ? $fallback_resp->{body} : undef, $hidden_body,
	     'ECH-only host: non-ECH request did not expose hidden content') or diag($out);

	# Validate that the hidden vhost is only reached when ECH is accepted.
	($rc, $out) = bssl_http_get($tf, $hidden_host, $valid_cfg_list, $bssl, 'HTTP/1.0');
	my $ech_resp = parse_http_response($out);
	my $ech_state = extract_ech_state($out);
	ok($rc == 0, 'ECH-only host: ECH client completed TLS handshake') or diag($out);
	is($ech_state, 'yes', 'ECH-only host: ECH was accepted') or diag($out);
	ok($ech_resp && $ech_resp->{status} == 200,
	   'ECH-only host: ECH request returned HTTP 200') or diag($out);
	is($ech_resp ? $ech_resp->{body} : undef, $hidden_body,
	   'ECH-only host: ECH request served hidden vhost content') or diag($out);

	# Validate that a malformed client ECH config is detected as a failed ECH attempt.
	($rc, $out) = bssl_http_get($tf, $hidden_host, $invalid_cfg_list, $bssl, 'HTTP/1.0');
	my $invalid_resp = parse_http_response($out);
	ok($rc != 0 && $rc != 124,
	   'invalid ECH config was rejected without hanging') or diag($out);
	ok(!$invalid_resp || $invalid_resp->{status} != 200,
	   'invalid ECH config did not complete HTTP 200') or diag($out);
	like($out, qr/\b(ECH|alert|error|fail|reject)\b/i,
	     'invalid ECH config produced a failure trace') or diag($out);
	assert_curl_https_body($tf, $public_host, $public_body,
		'server stayed healthy after invalid ECH input');

	# Validate that the recorded handshake states differ between plain TLS and ECH.
	ok(defined($fallback_state)
	   && defined($ech_state)
	   && $fallback_state ne $ech_state,
	   'TLS vs ECH comparison: handshake traces differ as expected');

	# Validate that repeated ECH handshakes stay consistent across sequential connections.
	for my $i (1 .. 5) {
		($rc, $out) = bssl_http_get($tf, $hidden_host, $valid_cfg_list, $bssl, 'HTTP/1.0');
		my $resp = parse_http_response($out);
		my $state = extract_ech_state($out);
		ok($rc == 0
		   && defined($state) && $state eq 'yes'
		   && $resp && $resp->{status} == 200
		   && $resp->{body} eq $hidden_body,
		   "sequential ECH connection #$i stayed consistent") or diag($out);
	}

	# Validate explicit HTTP/1.1 operation over an ECH-accepted TLS connection.
	($rc, $out) = bssl_http_get($tf, $hidden_host, $valid_cfg_list, $bssl, 'HTTP/1.1');
	my $http11_resp = parse_http_response($out);
	my $http11_state = extract_ech_state($out);
	ok($rc == 0, 'HTTP/1.1 ECH request completed TLS handshake') or diag($out);
	is($http11_state, 'yes', 'HTTP/1.1 ECH request kept ECH enabled') or diag($out);
	ok($http11_resp
	   && $http11_resp->{protocol} eq 'HTTP/1.1'
	   && $http11_resp->{status} == 200,
	   'HTTP/1.1 ECH request returned HTTP 200') or diag($out);
	is($http11_resp ? $http11_resp->{body} : undef, $hidden_body,
	   'HTTP/1.1 ECH request served hidden vhost content') or diag($out);

	ok($tf->stop_proc == 0, 'Stopping lighttpd');
}

sub assert_curl_https_body {
	my ($tf, $host, $expect_body, $label) = @_;
	my ($rc, $status, $body) = curl_https($tf, $host);
	ok($rc == 0 && defined $status && $status == 200 && $body eq $expect_body, $label)
	  or diag($body);
}

sub curl_https {
	my ($tf, $host) = @_;
	my ($rc, $out) = run_cmd(10, undef,
		$curl,
		'-k',
		'--silent',
		'--show-error',
		'--http1.1',
		'--connect-timeout', '2',
		'--max-time', '5',
		'--resolve', $host . ':' . $tf->{PORT} . ':127.0.0.1',
		'--write-out', "\n__STATUS__:%{http_code}\n",
		'https://' . $host . ':' . $tf->{PORT} . '/');
	my $status;
	if ($out =~ s/\n__STATUS__:(\d+)\n\z//s) {
		$status = $1;
	}
	return ($rc, $status, $out);
}

sub bssl_http_get {
	my ($tf, $host, $ech_cfg_list, $bssl, $http_version) = @_;
	$http_version ||= 'HTTP/1.0';
	my $request = "GET / $http_version\r\nHost: $host\r\n";
	$request .= "Connection: close\r\n" if $http_version eq 'HTTP/1.1';
	$request .= "\r\n";
	my @cmd = (
		$bssl,
		'client',
		'-connect', '127.0.0.1:' . $tf->{PORT},
		'-server-name', $host,
		'-debug',
	);
	push @cmd, ('-ech-config-list', $ech_cfg_list) if defined $ech_cfg_list;
	return run_cmd(5, $request, @cmd);
}

sub parse_http_response {
	my ($out) = @_;
	return undef unless defined $out;
	(my $norm = $out) =~ s/\r\n/\n/g;
	my $start = index($norm, 'HTTP/');
	return undef if $start < 0;
	my $resp = substr($norm, $start);
	my ($head, $rest) = split(/\n\n/, $resp, 2);
	return undef unless defined $head && defined $rest;
	my @lines = split(/\n/, $head);
	my $status_line = shift @lines;
	return undef unless defined $status_line;
	my ($protocol, $status) = $status_line =~ m{^(HTTP/\d\.\d) (\d{3})\b};
	return undef unless defined $protocol;
	my %headers;
	for my $line (@lines) {
		next if $line eq '';
		my ($k, $v) = split(/:\s*/, $line, 2);
		next unless defined $k && defined $v;
		$headers{lc $k} = $v;
	}
	my $body = $rest;
	if (defined $headers{'content-length'} && $headers{'content-length'} =~ /^\d+\z/) {
		$body = substr($body, 0, $headers{'content-length'});
	}
	return {
		protocol => $protocol,
		status => 0 + $status,
		body => $body,
		headers => \%headers,
	};
}

sub extract_ech_state {
	my ($out) = @_;
	return undef unless defined $out;
	return lc($1) if $out =~ /Encrypted ClientHello:\s+([A-Za-z]+)/;
	return undef;
}

sub bssl_supports_generate_ech {
	my ($bssl) = @_;
	my $quoted = shell_quote($bssl) . ' 2>&1';
	my $out = `$quoted`;
	return $out =~ /\bgenerate-ech\b/;
}

sub linked_libssl_has_ech {
	my ($module, $ldd, $nm) = @_;
	return 0 unless $ldd && $nm && -f $module;
	my $ldd_cmd = join(' ', map { shell_quote($_) } ($ldd, $module)) . ' 2>/dev/null';
	my $ldd_out = `$ldd_cmd`;
	my ($libssl) = $ldd_out =~ /^\s*libssl(?:\.\S+)?\s*=>\s*(\S+)/m;
	return 0 unless $libssl && -f $libssl;
	my $nm_cmd = join(' ', map { shell_quote($_) } ($nm, '-D', $libssl)) . ' 2>/dev/null';
	my $nm_out = `$nm_cmd`;
	return $nm_out =~ /\bSSL_CTX_set1_ech_keys\b/
	    && $nm_out =~ /\bSSL_ech_accepted\b/;
}

sub find_tool {
	for my $name (@_) {
		next unless defined $name && $name ne '';
		return $name if $name =~ m{/} && -x $name;
		my $cmd = 'command -v ' . shell_quote($name) . ' 2>/dev/null';
		my $path = `$cmd`;
		chomp $path;
		return $path if $path ne '' && -x $path;
	}
	return undef;
}

sub run_cmd {
	my ($timeout_secs, $stdin, @cmd) = @_;
	my $cmd = join(' ', map { shell_quote($_) } ($timeout_cmd, $timeout_secs . 's', @cmd));
	my $stdin_file = $tmpdir . '/cmd.stdin';
	if (defined $stdin) {
		write_file($stdin_file, $stdin) or return (255, '');
		$cmd .= ' < ' . shell_quote($stdin_file);
	}
	$cmd .= ' 2>&1';
	my $out = `$cmd`;
	my $rc = $? >> 8;
	unlink $stdin_file if -f $stdin_file;
	return ($rc, $out);
}

sub write_ech_pem {
	my ($pem, $priv, $cfg) = @_;
	my $priv_raw = slurp_file($priv);
	my $cfg_raw = slurp_file($cfg);
	return 0 unless defined $priv_raw && defined $cfg_raw;

	my $pem_txt =
	  "-----BEGIN PRIVATE KEY-----\n"
	. wrap_base64($priv_raw)
	. "-----END PRIVATE KEY-----\n"
	. "-----BEGIN ECHCONFIG-----\n"
	. wrap_base64($cfg_raw)
	. "-----END ECHCONFIG-----\n";

	return write_file($pem, $pem_txt);
}

sub wrap_base64 {
	my ($raw) = @_;
	my $b64 = encode_base64($raw, '');
	$b64 =~ s/(.{1,64})/$1\n/g;
	return $b64;
}

sub clear_error_log {
	my ($path) = @_;
	unlink $path if -f $path;
}

sub slurp_file {
	my ($path) = @_;
	open my $fh, '<', $path or return undef;
	binmode $fh;
	local $/;
	my $data = <$fh>;
	close $fh;
	return $data;
}

sub write_file {
	my ($path, $data) = @_;
	open my $fh, '>', $path or return 0;
	binmode $fh;
	print {$fh} $data or return 0;
	close $fh;
	return 1;
}

sub shell_quote {
	my ($s) = @_;
	return "''" unless defined $s && length $s;
	$s =~ s/'/'\"'\"'/g;
	return "'$s'";
}
