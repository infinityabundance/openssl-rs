use strict;
use warnings;
use Crypt::OpenSSL::X509;

my ($cert, $key, $ca, $other) = @ARGV;
my $x = Crypt::OpenSSL::X509->new_from_file($cert);
print "x509_parse=ok\n" if $x->version() >= 0;
print "x509_subject=" . ($x->subject() =~ /127\.0\.0\.1/ ? "ok" : "bad") . "\n";
print "x509_fingerprint=" . (length($x->fingerprint_sha256()) >= 32 ? "ok" : "bad") . "\n";
print "x509_pubkey=" . (length($x->pubkey()) > 100 ? "ok" : "bad") . "\n";
print "x509_checkend=" . ($x->checkend(3600) ? "bad" : "ok") . "\n";
my $exts = $x->extensions_by_name();
print "x509_extensions=" . (keys(%$exts) > 0 ? "ok" : "bad") . "\n";
my $ca_x = Crypt::OpenSSL::X509->new_from_file($ca);
my $other_x = Crypt::OpenSSL::X509->new_from_file($other);
print "x509_issuer_matches_ca=" . ($x->issuer_hash() eq $ca_x->subject_hash() ? "ok" : "bad") . "\n";
print "x509_unrelated_differs=" . ($ca_x->subject_hash() ne $other_x->subject_hash() ? "ok" : "bad") . "\n";
