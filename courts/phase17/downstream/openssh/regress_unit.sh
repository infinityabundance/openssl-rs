#!/bin/sh
#
# openssl-rs — Phase 17 downstream: run OpenSSH's own regress unit-test binaries
# one by one so a failure in one does not hide the rest. The binaries are the
# ones `make unit` builds from the unmodified tree; only the driver is ours.
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/openssh/regress_unit.sh
#
set -u

SRC=${SRC:-/court/openssh/openssh-10.5p1}
U=$SRC/regress/unittests
TMO=${TMO:-180}

# Ordered roughly so that the crypto-relevant ones are visible first; mirrors the
# upstream `make unit` order otherwise.
NAMES="sshbuf sshkey kex hostkeys crypto sshsig authopt bitmap conversion match misc servconf utf8"

pass=0; fail=0
for n in $NAMES; do
    bin=$U/$n/test_$n
    if [ ! -x "$bin" ]; then
        echo "### $n: binary missing ($bin)"
        fail=$((fail+1))
        continue
    fi
    set -- 
    case $n in
        sshkey|sshsig|authopt|hostkeys|crypto) set -- -d "$U/$n/testdata" ;;
    esac
    log=/court/openssh/regress-unit.$n.log
    timeout "$TMO" "$bin" "$@" >"$log" 2>&1
    rc=$?
    if [ "$rc" = 0 ]; then
        echo "### $n: PASS"
        pass=$((pass+1))
    else
        echo "### $n: FAIL (rc=$rc)"
        tail -4 "$log" | sed 's/^/      /'
        fail=$((fail+1))
    fi
done

echo "=== regress unit summary: $pass pass, $fail fail (timeout ${TMO}s each) ==="
