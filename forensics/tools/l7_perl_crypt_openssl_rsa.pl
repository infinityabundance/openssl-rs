use strict;
use warnings;
use Crypt::OpenSSL::RSA;

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
my $pub = Crypt::OpenSSL::RSA->new_public_key($rsa->get_public_key_string());
my $msg = "s33-rsa-workload";
my $sig = $rsa->sign($msg);
print "rsa_sign=ok\n" if length($sig) > 0;
print "rsa_verify=" . ($pub->verify($msg, $sig) ? "ok" : "bad") . "\n";
print "rsa_tamper_rejected=" . ($pub->verify($msg . "x", $sig) ? "bad" : "ok") . "\n";
my $ct = $pub->encrypt("s33");
print "rsa_encrypt=ok\n" if length($ct) > 0;
print "rsa_decrypt=" . ($rsa->decrypt($ct) eq "s33" ? "ok" : "bad") . "\n";
