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
use Test::More tests => 34;
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
my $echbase = $tmpdir . '/ech';
my $echvalid = $echbase . '/valid';
my $echother = $echbase . '/other';
my $echmalformed = $echbase . '/malformed';
my $echmissing = $echbase . '/missing';
my $errorlog = $tmpdir . '/logs/lighttpd-ssl-ech.error.log';
my $stderrlog = $tmpdir . '/logs/lighttpd-ssl-ech.stderr.log';
my $hidden_host = 'hidden.example.com';

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
	skip 'missing ECH test prerequisites: ' . join(', ', @missing), 34 if @missing;

	make_path($tlsdir, $echvalid, $echother, $echmalformed);
	$ENV{LIGHTTPD_STDERR_FILE} = $stderrlog;

	my $tls_cert = $tlsdir . '/server.crt';
	my $tls_key = $tlsdir . '/server.key';
	my $valid_cfg = $echvalid . '/ech_config.bin';
	my $valid_cfg_list = $echvalid . '/ech_config_list.bin';
	my $valid_priv = $echvalid . '/ech_private_key.bin';
	my $valid_pem = $echvalid . '/example.com.ech';
	my $other_cfg = $echother . '/ech_config.bin';
	my $other_cfg_list = $echother . '/ech_config_list.bin';
	my $other_priv = $echother . '/ech_private_key.bin';
	my $bad_pem = $echmalformed . '/bad.ech';

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
		'-public-name', 'example.com',
		'-config-id', '1',
		'-out-ech-config-list', $valid_cfg_list,
		'-out-ech-config', $valid_cfg,
		'-out-private-key', $valid_priv);
	ok($rc == 0
	   && -s $valid_cfg_list
	   && write_ech_pem($valid_pem, $valid_priv, $valid_cfg),
	   'generated server ECH fixture')
	  or diag($out);

	($rc, $out) = run_cmd(10, undef,
		$bssl, 'generate-ech',
		'-public-name', 'other.example.com',
		'-config-id', '9',
		'-out-ech-config-list', $other_cfg_list,
		'-out-ech-config', $other_cfg,
		'-out-private-key', $other_priv);
	ok($rc == 0 && -s $other_cfg_list, 'generated mismatched client ECH fixture')
	  or diag($out);

	ok(write_file($bad_pem, "not a pem\n") && -s $bad_pem, 'generated malformed ECH fixture');

	$ENV{ECH_KEYDIR} = $echvalid;
	clear_error_log($errorlog);
	$tf->{CONFIGFILE} = 'mod-openssl-ech.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();

	assert_curl_https_ok($tf, $hidden_host, 'ECH-enabled server serves HTTPS');

	($rc, $out) = bssl_http_get($tf, $hidden_host, undef, $bssl);
	ok($rc == 0, 'non-ECH client completed TLS handshake') or diag($out);
	like($out, qr/Encrypted ClientHello: no\b/, 'non-ECH client stayed on standard TLS') or diag($out);
	like($out, qr/HTTP\/1\.0 200 OK\r?$/m, 'non-ECH client received HTTP 200') or diag($out);

	($rc, $out) = bssl_http_get($tf, $hidden_host, $valid_cfg_list, $bssl);
	ok($rc == 0, 'ECH client completed TLS handshake') or diag($out);
	like($out, qr/Encrypted ClientHello: yes\b/, 'valid ECH was accepted') or diag($out);
	like($out, qr/HTTP\/1\.0 200 OK\r?$/m, 'ECH client received HTTP 200') or diag($out);

	($rc, $out) = bssl_http_get($tf, $hidden_host, $other_cfg_list, $bssl);
	ok($rc != 0 && $rc != 124, 'mismatched ECH input was rejected without hanging') or diag($out);
	like($out, qr/\bECH_REJECTED\b/, 'mismatched ECH input produced ECH rejection') or diag($out);
	assert_curl_https_ok($tf, $hidden_host, 'server stayed healthy after mismatched ECH input');

	ok($tf->stop_proc == 0, 'Stopping lighttpd');

	clear_error_log($errorlog);
	$tf->{CONFIGFILE} = 'mod-openssl-tls.conf';
	ok($tf->start_proc == 0, "Starting lighttpd with $tf->{CONFIGFILE}") or die();

	assert_curl_https_ok($tf, $hidden_host, 'non-ECH server serves HTTPS');

	($rc, $out) = bssl_http_get($tf, $hidden_host, $valid_cfg_list, $bssl);
	ok($rc != 0 && $rc != 124, 'ECH-capable client was rejected when ECH was disabled') or diag($out);
	like($out, qr/\bECH_REJECTED\b/, 'ECH-disabled server returned ECH rejection') or diag($out);
	assert_curl_https_ok($tf, $hidden_host, 'non-ECH server stayed healthy after ECH attempt');

	ok($tf->stop_proc == 0, 'Stopping lighttpd');

	$ENV{ECH_KEYDIR} = $echmissing;
	clear_error_log($errorlog);
	clear_error_log($stderrlog);
	$tf->{CONFIGFILE} = 'mod-openssl-ech.conf';
	ok($tf->start_proc == 0, 'starting lighttpd with missing ECH keydir succeeds') or die();

	($rc, $out) = bssl_http_get($tf, $hidden_host, $valid_cfg_list, $bssl);
	ok($rc != 0 && $rc != 124, 'missing ECH keydir rejected client without hanging') or diag($out);
	like($out, qr/\bECH_REJECTED\b/, 'missing ECH keydir produced ECH rejection') or diag($out);
	like(slurp_file($stderrlog), qr/No such file or directory/, 'missing ECH keydir was logged');
	assert_curl_https_ok($tf, $hidden_host, 'server stayed healthy with missing ECH keydir');

	ok($tf->stop_proc == 0, 'Stopping lighttpd');

	$ENV{ECH_KEYDIR} = $echmalformed;
	clear_error_log($errorlog);
	clear_error_log($stderrlog);
	$tf->{CONFIGFILE} = 'mod-openssl-ech.conf';
	ok($tf->start_proc == 0, 'starting lighttpd with malformed ECH key file succeeds') or die();

	($rc, $out) = bssl_http_get($tf, $hidden_host, $valid_cfg_list, $bssl);
	ok($rc != 0 && $rc != 124, 'malformed ECH key file rejected client without hanging') or diag($out);
	like($out, qr/\bECH_REJECTED\b/, 'malformed ECH key file produced ECH rejection') or diag($out);
	like(slurp_file($stderrlog), qr/\bNO_START_LINE\b/, 'malformed ECH key file was logged');
	assert_curl_https_ok($tf, $hidden_host, 'server stayed healthy with malformed ECH key file');

	ok($tf->stop_proc == 0, 'Stopping lighttpd');
}

sub assert_curl_https_ok {
	my ($tf, $host, $label) = @_;
	my ($rc, $status, $body) = curl_https($tf, $host);
	ok($rc == 0 && defined $status && $status == 200, $label) or diag($body);
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
	my ($tf, $host, $ech_cfg_list, $bssl) = @_;
	my @cmd = (
		$bssl,
		'client',
		'-connect', '127.0.0.1:' . $tf->{PORT},
		'-server-name', $host,
		'-debug',
	);
	push @cmd, ('-ech-config-list', $ech_cfg_list) if defined $ech_cfg_list;
	return run_cmd(5, "GET / HTTP/1.0\r\nHost: $host\r\n\r\n", @cmd);
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
