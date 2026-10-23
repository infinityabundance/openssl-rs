<?php
// S33: PHP 8.2's openssl extension over PKCS#12, CMS/PKCS#7 and X.509 verification.
$cert = $argv[1]; $key = $argv[2]; $ca = $argv[3];
$dir = sys_get_temp_dir();
$p12 = "$dir/s33-php.p12";
$plain = "$dir/s33-php.txt";
$sig = "$dir/s33-php.sig";
$enc = "$dir/s33-php.enc";
$out = "$dir/s33-php.out";
file_put_contents($plain, "s33 php openssl workload\n");

$c = openssl_x509_read(file_get_contents($cert));
$k = openssl_pkey_get_private(file_get_contents($key));
if (!$c || !$k) { echo "php_key=bad\n"; exit(0); }

$ok = openssl_pkcs12_export_to_file($c, $p12, $k, "s33pass");
echo "php_pkcs12_export=" . ($ok && file_exists($p12) ? "ok" : "bad") . "\n";
$certs = [];
$ok = openssl_pkcs12_read(file_get_contents($p12), $certs, "s33pass");
echo "php_pkcs12_read=" . ($ok && isset($certs["cert"]) && isset($certs["pkey"]) ? "ok" : "bad") . "\n";

$ok = openssl_cms_sign($plain, $sig, $c, $k, null, 0, OPENSSL_ENCODING_SMIME);
echo "php_cms_sign=" . ($ok ? "ok" : "bad") . "\n";
$ok = openssl_cms_verify($sig, OPENSSL_CMS_NOVERIFY, null, [], null, $out, null, null, OPENSSL_ENCODING_SMIME);
if (!$ok) { $errs = []; while ($e = openssl_error_string()) { $errs[] = $e; } echo "php_cms_verify_err=" . implode("|", array_slice($errs, 0, 3)) . "\n"; }
echo "php_cms_verify=" . ($ok && strpos(file_get_contents($out), "s33 php openssl workload") !== false ? "ok" : "bad") . "\n";

$ok = openssl_cms_encrypt($plain, $enc, $c, null, 0, OPENSSL_ENCODING_SMIME);
echo "php_cms_encrypt=" . ($ok ? "ok" : "bad") . "\n";
$ok = openssl_cms_decrypt($enc, $out, $c, $k, OPENSSL_ENCODING_SMIME);
echo "php_cms_decrypt=" . ($ok && strpos(file_get_contents($out), "s33 php openssl workload") !== false ? "ok" : "bad") . "\n";

$purpose = openssl_x509_checkpurpose($c, X509_PURPOSE_SSL_SERVER, [$ca]);
echo "php_x509_checkpurpose=" . ($purpose === true ? "ok" : "bad") . "\n";
$other = openssl_x509_read(file_get_contents($argv[4]));
$purpose2 = openssl_x509_checkpurpose($c, X509_PURPOSE_SSL_SERVER, [$argv[4]]);
echo "php_unrelated_ca=" . ($purpose2 === true ? "bad" : "rejected") . "\n";
?>
