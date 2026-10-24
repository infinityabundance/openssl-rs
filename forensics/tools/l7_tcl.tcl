#
# TclTLS 1.7.22 L7 workload.  Globals tcltls_so, tcltls_ca, tcltls_other and tcltls_port
# are set by the embedding harness (l7_tcl.c).
#
# A verified TLS client session against the loopback peer prints tcl_tls_connect=ok and
# tcl_tls_payload=tcl-payload; the same peer presented through an unrelated CA must be
# refused by the handshake and prints tcl_tls_wrong_ca=rejected.
#

if {[catch {load $tcltls_so Tls} err]} {
    puts "tcl_tls_load=bad $err"
    return
}
if {[catch {package require tls} err]} {
    puts "tcl_tls_load=bad $err"
    return
}

proc tcltls_session {cafile port} {
    set chan [::tls::socket -cafile $cafile -servername 127.0.0.1 127.0.0.1 $port]
    return $chan
}

if {[catch {tcltls_session $tcltls_ca $tcltls_port} chan]} {
    puts "tcl_tls_connect=bad"
} else {
    puts "tcl_tls_connect=ok"
    fconfigure $chan -translation lf
    if {[catch {gets $chan line} err]} {
        set line ""
    }
    if {$line eq "tcl-payload"} {
        puts "tcl_tls_payload=tcl-payload"
    } else {
        puts "tcl_tls_payload=bad"
    }
    catch {close $chan}
}

if {[catch {tcltls_session $tcltls_other $tcltls_port} chan]} {
    puts "tcl_tls_wrong_ca=rejected"
} else {
    puts "tcl_tls_wrong_ca=bad"
    catch {close $chan}
}
