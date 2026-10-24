#!/usr/bin/perl
# Phase-25 L7 workload for Net::DNS::SEC.
#
# The XS module signs and verifies arbitrary data with an RSA/SHA-256 DNSKEY
# through the subject libcrypto. The key material is the module's own test
# fixture, so the workload is deterministic. Arguments are the harness fixture
# paths and are not used.
use strict;
use warnings;

use Net::DNS;
use Net::DNS::SEC;
use Net::DNS::SEC::Private;

my $key = Net::DNS::RR->new( <<'END' );
RSASHA256.example.	IN	DNSKEY	256 3 8 (
	AwEAAZRSF/5NLnExp5n4M6ynF2Yok3N2aG9AWu8/vKQrZGFQcbL+WPGYbWUtMpiNXmvzTr2j86kN
	QU4wBawm589mjzXgVQRfXYDMMFhHMtagzEKOiNy2ojhhFyS7r2O2vUbo4hGbnM54ynSM1al+ygKU
	Gy1TNzHuYMiwh+gsQCsC5hfJ ; Key ID = 35418
	)
END
print "dnssec_key=ok\n" if $key;

my $keyfile = "/tmp/s46-netdnssec.key";
open( my $fh, '>', $keyfile ) or die "open: $!";
print $fh <<'END';
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
close($fh);

my $private = Net::DNS::SEC::Private->new($keyfile);
print "dnssec_key=ok\n" if $private;

my $data = 'phase25-l7-netdnssec-payload';
my $corrupt = 'phase25-l7-netdnssec-payloaX';
my $sig = eval { Net::DNS::SEC::RSA->sign( $data, $private ) };
if ($sig) { print "dnssec_sign=ok\n" } else { print "dnssec_sign=fail: $@\n" }

my $ok = eval { Net::DNS::SEC::RSA->verify( $data, $key, $sig ) };
if ($ok) { print "dnssec_verify=ok\n" } else { print "dnssec_verify=fail: $@\n" }
my $bad = eval { Net::DNS::SEC::RSA->verify( $corrupt, $key, $sig ) };
print "dnssec_tamper=rejected\n" if !$bad;

unlink($keyfile);
