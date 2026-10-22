# Phase-25 L7 workload for the `jimtcl` family: the TLS server half.
#
# The runner forks this script as the child. It listens on l7_port, upgrades
# the accepted stream with `$conn ssl -server cert key` (jim-aio.c's OpenSSL
# path: SSL_use_certificate_file/SSL_use_PrivateKey_file/SSL_accept/SSL_read/
# SSL_write), reads one request line and answers with one response line. With
# the mismatched key the SSL_accept fails, so no response is written.
#
# SPDX-License-Identifier: Apache-2.0

set cert $l7_cert
set key  $l7_key
set port $l7_port

set srv [socket stream.server 127.0.0.1:$port]
set conn [$srv accept]
if {[catch {$conn ssl -server $cert $key} err]} {
    puts stderr "jimtcl server ssl: $err"
    $conn close
    $srv close
    exit 2
}
set line [$conn gets]
if {$line eq "jimtcl-l7-request"} {
    $conn puts "jimtcl-l7-response"
    flush $conn
}
$conn close
$srv close
exit 0
