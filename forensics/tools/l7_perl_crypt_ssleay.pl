use strict;
use warnings;

# Crypt::SSLeay 0.73.06 L7 workload.  argv: CA OTHER PORT BODY.
#
# The module's CTX/Conn XS surface is the low-level libssl API
# (SSL_CTX_new / SSL_new / SSL_set_fd / SSL_connect / SSL_write / SSL_read).
# Verification follows the module's own contract: HTTPS_CA_FILE is loaded by
# Crypt::SSLeay::CTX::set_verify before the handshake.

use IO::Socket::INET;
use Crypt::SSLeay;

my ( $ca, $other, $port, $body ) = @ARGV;

sub connect_tls {
    my ($cafile) = @_;

    local $ENV{HTTPS_CA_FILE} = $cafile;
    delete $ENV{HTTPS_CA_DIR};

    my $ctx = Crypt::SSLeay::CTX->new(0);
    return () unless $ctx;
    $ctx->set_verify();

    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1",
        PeerPort => $port,
        Proto    => "tcp",
        Timeout  => 10
    );
    return () unless $sock;

    my $ssl = Crypt::SSLeay::Conn->new( $ctx, 0 );
    return () unless $ssl;
    $ssl->set_fd( fileno($sock) );
    $ssl->set_tlsext_host_name("127.0.0.1");

    my $rc = $ssl->connect();
    if ( !$rc || !$ssl->get_verify_result() ) {
        close $sock;
        return ();
    }
    return ( $ctx, $ssl, $sock );
}

my ( $ctx, $ssl, $sock ) = connect_tls($ca);
if ( !$ssl ) {
    print "ssleay_connect=bad\n";
} else {
    print "ssleay_connect=ok\n";
    $ssl->write("GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    my $buf = "";
    my $n   = $ssl->read( $buf, 4096 );
    my $ok  = ( defined($n) && $n > 0 && index( $buf, $body ) >= 0 ) ? "ok" : "bad";
    print "ssleay_payload=$ok\n";
    $ssl->free();
    $ctx->free();
    close $sock;
}

my ( $ctx2, $ssl2, $sock2 ) = connect_tls($other);
print "ssleay_wrong_ca=" . ( $ssl2 ? "bad" : "rejected" ) . "\n";
if ($ssl2) {
    $ssl2->free();
    $ctx2->free();
    close $sock2;
}
