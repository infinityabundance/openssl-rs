use strict;
use warnings;
use Crypt::SMIME qw(NO_CHECK_CERTIFICATE);

my ($cert, $key, $ca) = @ARGV;
sub slurp { my ($p) = @_; open my $fh, '<', $p or die "open $p: $!"; local $/; <$fh> }
my ($crt, $priv, $cacrt) = (slurp($cert), slurp($key), slurp($ca));

my $plain = "From: s33\@example.org\nTo: s33\@example.net\nSubject: s33 smime\n\nbody\n";
my $m = Crypt::SMIME->new();
$m->setPrivateKey($priv, $crt);
$m->setPublicKey($crt);
my $signed = $m->sign($plain);
print "smime_sign=ok\n" if length($signed) > 10;

my $v = Crypt::SMIME->new();
$v->setPublicKey($cacrt);
my $checked = eval { $v->check($signed, NO_CHECK_CERTIFICATE); };
print "smime_check=" . (defined($checked) ? "ok" : "bad") . "\n";

my $enc = $m->encrypt($plain);
print "smime_encrypt=ok\n" if length($enc) > 10;
my $d = Crypt::SMIME->new();
$d->setPrivateKey($priv, $crt);
my $dec = eval { $d->decrypt($enc) };
print "smime_roundtrip=" . (defined($dec) && $dec =~ /s33 smime/ ? "ok" : "bad") . "\n";
