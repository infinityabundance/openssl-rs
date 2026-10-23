use strict;
use warnings;
use Net::SSLeay;
use IO::Socket::INET;

my ($ca, $other, $port, $body) = @ARGV;
Net::SSLeay::initialize();

sub open_tls {
    my ($cafile, $session) = @_;
    my $ctx = Net::SSLeay::CTX_new();
    return () unless $ctx;
    Net::SSLeay::CTX_set_options($ctx, 0x20000000); # SSL_OP_NO_TLSv1_3
    Net::SSLeay::CTX_set_cipher_list($ctx, "ECDHE-RSA-AES128-GCM-SHA256");
    Net::SSLeay::CTX_load_verify_locations($ctx, $cafile, "") == 1 or return ();
    Net::SSLeay::CTX_set_verify($ctx, 1, undef);
    my $ssl = Net::SSLeay::new($ctx);
    my $sock = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $port,
                                     Proto => "tcp", Timeout => 10);
    return () unless $sock;
    Net::SSLeay::set_fd($ssl, fileno($sock));
    Net::SSLeay::set_cipher_list($ssl, "ECDHE-RSA-AES128-GCM-SHA256");
    Net::SSLeay::set_tlsext_host_name($ssl, "127.0.0.1");
    Net::SSLeay::set_session($ssl, $session) if defined $session;
    my $rc = Net::SSLeay::connect($ssl);
    if (!defined($rc) || $rc <= 0) {
        print STDERR "connect rc=" . (defined($rc) ? $rc : "undef") . " " .
            Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error()) . "\n";
        close $sock;
        Net::SSLeay::free($ssl);
        Net::SSLeay::CTX_free($ctx);
        return ();
    }
    return ($ctx, $ssl, $sock);
}

my ($ctx, $ssl, $sock) = open_tls($ca, undef);
if (!$ssl) {
    print "tls_connect=bad\n";
    exit 0;
}
print "tls_connect=ok\n";
my $req = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
Net::SSLeay::write($ssl, $req);
my $data = Net::SSLeay::read($ssl);
print "tls_payload=" . (defined($data) && index($data, $body) >= 0 ? "ok" : "bad") . "\n";
my $session = Net::SSLeay::get_session($ssl);
Net::SSLeay::shutdown($ssl);
Net::SSLeay::free($ssl);
Net::SSLeay::CTX_free($ctx);
close $sock;

my ($ctx2, $ssl2, $sock2) = open_tls($ca, $session);
if ($ssl2) {
    print "tls_session=" . (Net::SSLeay::session_reused($ssl2) ? "ok" : "bad") . "\n";
    Net::SSLeay::shutdown($ssl2);
    Net::SSLeay::free($ssl2);
    Net::SSLeay::CTX_free($ctx2);
    close $sock2;
} else {
    print "tls_session=bad\n";
}

my ($ctx3, $ssl3, $sock3) = open_tls($other, undef);
print "tls_unrelated_ca=" . (($ssl3) ? "bad" : "rejected") . "\n";
if ($ssl3) {
    Net::SSLeay::shutdown($ssl3);
    Net::SSLeay::free($ssl3);
    Net::SSLeay::CTX_free($ctx3);
    close $sock3;
}
