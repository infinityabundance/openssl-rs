use strict;
use warnings;
use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum;

my $group = eval { Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name(415) };
if (!$group) {
    print "ec_group=bad\n";
    exit 0;
}
my $degree = Crypt::OpenSSL::EC::EC_GROUP::get_degree($group);
print "ec_group=" . ($degree == 256 ? "ok" : "bad") . "\n";
my $point = Crypt::OpenSSL::EC::EC_POINT::new($group);
print "ec_point_new=ok\n" if $point;
Crypt::OpenSSL::EC::EC_POINT::set_to_infinity($group, $point);
print "ec_point_infinity=" .
    (Crypt::OpenSSL::EC::EC_POINT::is_at_infinity($group, $point) ? "ok" : "bad") . "\n";
