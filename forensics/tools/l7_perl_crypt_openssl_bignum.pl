use strict;
use warnings;
use Crypt::OpenSSL::Bignum;

my $a = Crypt::OpenSSL::Bignum->new_from_decimal("123456789012345678901234567890");
my $b = Crypt::OpenSSL::Bignum->new_from_decimal("987654321098765432109876543210");
my $ctx = Crypt::OpenSSL::Bignum::CTX->new();
my $sum = $a->add($b);
print "bn_add=" . ($sum->to_decimal() eq "1111111110111111111011111111100" ? "ok" : "bad") . "\n";
my $prod = $a->mul($b, $ctx);
print "bn_mul=ok\n" if $prod->to_decimal() =~ /^121932631137021795226185032733622923332237463801111263526900$/;
my $base = Crypt::OpenSSL::Bignum->new_from_word(7);
my $exp = Crypt::OpenSSL::Bignum->new_from_word(13);
my $mod = Crypt::OpenSSL::Bignum->new_from_word(1000);
my $pow = $base->mod_exp($exp, $mod, $ctx);
print "bn_modexp=" . ($pow->to_decimal() eq "407" ? "ok" : "bad") . "\n";
my $inv = Crypt::OpenSSL::Bignum->new_from_word(3)->mod_inverse(Crypt::OpenSSL::Bignum->new_from_word(11), $ctx);
print "bn_inverse=" . ($inv->to_decimal() eq "4" ? "ok" : "bad") . "\n";
