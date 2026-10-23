use strict;
use warnings;
use Crypt::OpenSSL::PKCS10;
use Crypt::OpenSSL::PKCS10 qw(:const);

my $req = Crypt::OpenSSL::PKCS10->new(2048);
$req->set_subject("/C=RO/O=S33/CN=127.0.0.1");
$req->add_ext(Crypt::OpenSSL::PKCS10::NID_key_usage, "critical,digitalSignature,keyEncipherment");
$req->add_ext(Crypt::OpenSSL::PKCS10::NID_subject_alt_name, "IP:127.0.0.1");
$req->add_ext_final();
$req->sign();
my $pem = $req->get_pem_req();
print "pkcs10_sign=ok\n" if $pem =~ /BEGIN CERTIFICATE REQUEST/;
my $pub = $req->get_pem_pubkey();
print "pkcs10_pubkey=ok\n" if $pub =~ /BEGIN PUBLIC KEY/;
print "pkcs10_pubkey_type=" . ($req->pubkey_type() =~ /RSA/i ? "ok" : "bad") . "\n";
