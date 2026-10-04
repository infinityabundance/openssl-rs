#!/bin/sh
#
# openssl-rs — Phase 17 downstream: localise the OpenSSH user/host key round-trip
# defect. Reads each private key with both the candidate-linked and the
# authority-linked ssh-keygen so the failure can be attributed to the candidate.
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/openssh/keyformat_probe.sh
#
set -u

CAND_KG=${CAND_KG:-/court/openssh/openssh-10.5p1/ssh-keygen}
AUTH_KG=${AUTH_KG:-/court/openssh-auth/openssh-10.5p1/ssh-keygen}
UPSTREAM=${UPSTREAM:-/court/openssh/openssh-10.5p1/regress}
WORK=${WORK:-/court/openssh/keyfmt}

rm -rf "$WORK"; mkdir -p "$WORK"

say() { printf '%s\n' "$*"; }

read_by() {
    # read_by <label> <keygen> <privfile>
    label=$1; kg=$2; f=$3
    if out=$("$kg" -y -f "$f" 2>&1); then
        say "  [OK]   $label  -> $(printf '%s' "$out" | cut -c1-60)"
    else
        say "  [FAIL] $label  -> $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-90)"
    fi
}

say "=== A. candidate ssh-keygen writes, both readers read ==="
for t in rsa ecdsa ed25519; do
    "$CAND_KG" -q -t "$t" -N '' -f "$WORK/cand_$t" 2>/dev/null
    say "-- cand_$t (native openssh-key-v1) --"
    read_by "candidate keygen reads" "$CAND_KG" "$WORK/cand_$t"
    read_by "authority keygen reads" "$AUTH_KG" "$WORK/cand_$t"
done

say ""
say "=== B. authority ssh-keygen writes, both readers read ==="
for t in rsa ecdsa ed25519; do
    "$AUTH_KG" -q -t "$t" -N '' -f "$WORK/auth_$t" 2>/dev/null
    say "-- auth_$t (native openssh-key-v1) --"
    read_by "candidate keygen reads" "$CAND_KG" "$WORK/auth_$t"
    read_by "authority keygen reads" "$AUTH_KG" "$WORK/auth_$t"
done

say ""
say "=== C. upstream regress test keys (shipped by OpenSSH itself) ==="
for k in ecdsa256_openssh rsa_openssh ed25519_openssh; do
    [ -f "$UPSTREAM/$k.prv" ] || { say "  (missing $k.prv)"; continue; }
    say "-- $k.prv --"
    read_by "candidate keygen reads" "$CAND_KG" "$UPSTREAM/$k.prv"
    read_by "authority keygen reads" "$AUTH_KG" "$UPSTREAM/$k.prv"
done

say ""
say "=== D. legacy PEM ('-m PEM') written by candidate, read back ==="
for t in rsa ecdsa; do
    "$CAND_KG" -q -t "$t" -N '' -m PEM -f "$WORK/pem_$t" 2>/dev/null
    say "-- pem_$t ($(head -1 "$WORK/pem_$t")) --"
    read_by "candidate keygen reads" "$CAND_KG" "$WORK/pem_$t"
done

say ""
say "=== E. public-part-only operations on the candidate-native keys ==="
for t in rsa ecdsa ed25519; do
    say "-- cand_$t --"
    fp=$("$CAND_KG" -lf "$WORK/cand_$t" 2>&1 | cut -c1-70)
    # does the .pub fingerprint match the private key's own public part?
    fppub=$("$CAND_KG" -lf "$WORK/cand_$t.pub" 2>&1 | cut -c1-70)
    say "  -lf private: $fp"
    say "  -lf public:  $fppub"
done
