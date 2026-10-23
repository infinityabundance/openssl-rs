use strict;
use warnings;
use Crypt::OpenSSL::Random;

my $a = Crypt::OpenSSL::Random::random_bytes(32);
my $b = Crypt::OpenSSL::Random::random_bytes(32);
print "rand_bytes=" . (defined($a) && length($a) == 32 ? "ok" : "bad") . "\n";
print "rand_differs=" . ($a ne $b ? "ok" : "bad") . "\n";
my $status = Crypt::OpenSSL::Random::random_status();
print "rand_status=" . ($status ? "ok" : "bad") . "\n";
