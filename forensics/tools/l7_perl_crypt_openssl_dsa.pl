use strict;
use warnings;
use Crypt::OpenSSL::DSA;

my $dsa = Crypt::OpenSSL::DSA->generate_parameters(1024);
$dsa->generate_key();
my $msg = "s33-dsa-workload";
my $sig = $dsa->sign($msg);
print "dsa_sign=ok\n" if defined($sig) && length($sig) > 0;
print "dsa_verify=" . ($dsa->verify($msg, $sig) ? "ok" : "bad") . "\n";
print "dsa_tamper_rejected=" . ($dsa->verify($msg . "x", $sig) ? "bad" : "ok") . "\n";
my $pub = $dsa->get_pub_key();
my $priv = $dsa->get_priv_key();
my $tmp = "/tmp/s33-dsa-" . $$;
$dsa->write_pub_key("$tmp.pub");
$dsa->write_priv_key("$tmp.priv");
my $pub2 = Crypt::OpenSSL::DSA->read_pub_key("$tmp.pub");
my $priv2 = Crypt::OpenSSL::DSA->read_priv_key("$tmp.priv");
print "dsa_pem_roundtrip=" . ($pub2->verify($msg, $sig) ? "ok" : "bad") . "\n";
