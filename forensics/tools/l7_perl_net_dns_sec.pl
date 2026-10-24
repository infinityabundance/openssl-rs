use strict;
use warnings;

# Net::DNS::SEC 1.20 DNSSEC workload: RSA/SHA-256 sign and verify with a fixed test key,
# then two negative controls (corrupted payload, unrelated public key).  The key material
# is the RSA/SHA-256 vector from the module's own t/23-RSA-SHA256.t, so the workload needs
# no network access and no fixture files.

use File::Temp qw(tempdir);
use Net::DNS;
use Net::DNS::SEC;
use Net::DNS::SEC::Private;

my $dir = tempdir(CLEANUP => 1);

my $key = Net::DNS::RR->new(<<'END');
RSASHA256.example.	IN	DNSKEY	256 3 8 (
	AwEAAZRSF/5NLnExp5n4M6ynF2Yok3N2aG9AWu8/vKQrZGFQcbL+WPGYbWUtMpiNXmvzTr2j86kN
	QU4wBawm589mjzXgVQRfXYDMMFhHMtagzEKOiNy2ojhhFyS7r2O2vUbo4hGbnM54ynSM1al+ygKU
	Gy1TNzHuYMiwh+gsQCsC5hfJ ; Key ID = 35418
	)
END

my $keyfile = "$dir/" . $key->privatekeyname;
open(my $handle, '>', $keyfile) or die "open $keyfile: $!";
print $handle <<'END';
Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: lFIX/k0ucTGnmfgzrKcXZiiTc3Zob0Ba7z+8pCtkYVBxsv5Y8ZhtZS0ymI1ea/NOvaPzqQ1BTjAFrCbnz2aPNeBVBF9dgMwwWEcy1qDMQo6I3LaiOGEXJLuvY7a9RujiEZucznjKdIzVqX7KApQbLVM3Me5gyLCH6CxAKwLmF8k=
PublicExponent: AQAB
PrivateExponent: c74UZyhHo6GCDs73VDYYNmpXlnTCTn7D94ufY+VQsfgaofmF4xJ128yHfTBkjI0T1z1H+ZYUbjVfV9YMc3avLcXAb4YOEuNw0CSZrtTFc/oTvAyM9tKoa7hB9MSlYtmYvaWiEatHzKL0wYvo71jtfoTyDLQTISzrBWsA+K1a3hk=
Prime1: wvw2lVu+kepiu0fasCrA3BlemVJ3XvWdd/y0sB5+egVGIJCn1bgkaSL/IP+683K28tN7hQYzMGiDBPymu3FeAw==
Prime2: wruzE41ctH5D2SLhW4pi/pz+WSyeBUSvsmUe5kr4c9mlIqYUK1k72kmsjjZtD4eJsjq3xb/VGi+pcMuK2t1/Qw==
Exponent1: lgk3AxTWfjcqA8wVpesv/ezzku0W95Xtto9YhhDg54m5XYOR8e1A7znDsaO2OnAyAIXlDQYpS32QG71Bmwhv+w==
Exponent2: KyNVekFYhgtqkFFvxs2TPIAewDZoExayLTzFaZK2E0PllxVfZnLwFV04wpA//K6zzC3BxCbI2HIygPA2JGHo7Q==
Coefficient: R3pSnerhKwfAHrH3iyojUzKzhM+AQ+97CWavx36eyKT3Yr/SIDANeeXGlT9U7RdxbkZzyeWbFNCnT+b89UX1RQ==
END
close($handle);

my $private = Net::DNS::SEC::Private->new($keyfile);
if ( !$private ) {
    print "dnssec_key=bad\n";
    exit 0;
}

my $class   = 'Net::DNS::SEC::RSA';
my $sigdata = 'arbitrary data';
my $corrupt = 'corrupted data';

my $signature = eval { $class->sign( $sigdata, $private ) };
print "dnssec_rsa_sign=" . ( $signature ? "ok" : "bad" ) . "\n";

my $verified = eval { $class->verify( $sigdata, $key, $signature ) };
print "dnssec_rsa_verify=" . ( $verified ? "ok" : "bad" ) . "\n";

my $tampered = eval { $class->verify( $corrupt, $key, $signature ) };
print "dnssec_corrupt_rejected=" . ( $tampered ? "bad" : "rejected" ) . "\n";

my $wrongkey = Net::DNS::RR->new(<<'END');
ECDSAP256SHA256.example.	IN	DNSKEY	( 257 3 13
	IYHbvpnqrhxM4i0SuOyAq9hk19tNXpjja7jCQnfAjZBFBfcLorJPnq4FWMVDg6QT2C4JeW0yCxK4
	iEhb4w9KWQ== ) ; Key ID = 27566
END

my $wrong = eval { $class->verify( $sigdata, $wrongkey, $signature ) };
print "dnssec_wrong_key_rejected=" . ( $wrong ? "bad" : "rejected" ) . "\n";
