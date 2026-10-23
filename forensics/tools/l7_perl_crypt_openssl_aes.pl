use strict;
use warnings;
use Crypt::OpenSSL::AES;

my $key = pack("C*", 0 .. 31);
my $cipher = Crypt::OpenSSL::AES->new($key);
my $plain = "s33-aes-plain!xx";
my $ct = $cipher->encrypt($plain);
print "aes_encrypt=ok\n" if length($ct) > 0;
print "aes_roundtrip=" . ($cipher->decrypt($ct) eq $plain ? "ok" : "bad") . "\n";
my $iv = pack("C*", 32 .. 47);
my $cbc = Crypt::OpenSSL::AES->new($key, { cipher => 'AES-256-CBC', iv => $iv, padding => 1 });
my $ct2 = $cbc->encrypt("s33-cbc-plaintext");
print "aes_cbc_encrypt=ok\n" if length($ct2) > 0;
print "aes_cbc_roundtrip=" . ($cbc->decrypt($ct2) eq "s33-cbc-plaintext" ? "ok" : "bad") . "\n";
