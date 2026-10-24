# Phase-25 L7 workload for TclTLS: a verified TLS client channel and an
# unrelated-CA reject. Arguments: ROOT PORT NEG_PORT CA.
set root     [lindex $::argv 0]
set port     [lindex $::argv 1]
set neg_port [lindex $::argv 2]
set ca       [lindex $::argv 3]

set mods [glob -nocomplain $root/libtls*.so $root/tcltls*.so]
if {[llength $mods] == 0} {
    puts "tcltls_payload=fail"
    puts "tcltls_unrelated_ca=fail"
    exit 1
}
load [lindex $mods 0] Tls

proc fetch {port cafile} {
    set s [tls::socket -cafile $cafile -require 1 127.0.0.1 $port]
    fconfigure $s -translation binary
    puts -nonewline $s "GET / HTTP/1.0\r\nConnection: close\r\n\r\n"
    flush $s
    set data [read $s]
    close $s
    return $data
}

if {[catch {fetch $port $ca} data]} {
    puts "tcltls_payload=fail"
    exit 1
}
if {[string length $data] > 0} {
    puts "tcltls_payload=ok"
} else {
    puts "tcltls_payload=fail"
}

if {[catch {fetch $neg_port $ca} ignored]} {
    puts "tcltls_unrelated_ca=rejected"
} else {
    puts "tcltls_unrelated_ca=fail"
}
exit 0
