#!/usr/bin/env bash
#
# run_pfp4_differential.sh — PFP-4 DSO-bound ECDSA differential court.
#
# One process per subject. Each process dlopens exactly one libcrypto.so.3 and
# prints the file it mapped (LOADED realpath/dev/ino/size and LIB via dladdr);
# the runner compares those with stat(2) on the expected on-disk DSO.
#
# Two modes are run against both DSOs and compared byte for byte:
#
#   sign-ex    4,096 supplied-nonce signatures (`ECDSA_do_sign_ex`), each with
#              the defining equation `s*k = m + r*d (mod n)` checked and the
#              DER checked against `ECDSA_sign_ex`.
#   sign-rand  4,096 signatures through the shipped `ECDSA_do_sign` path with a
#              deterministic RAND_METHOD, so the library's own nonce draw is
#              identical on both sides. This exercises `ecdsa_sign_setup`'s
#              order inverse end to end.
#
# Cross-verification runs both directions for both modes. A single SIG-line or
# signature-file mismatch, a rejected cross-signature, a population shortfall or
# an identity mismatch is a STOP.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec \
#       bash evidence/performance-frontier/campaigns/PFP-4/differential/run_pfp4_differential.sh

set -euo pipefail

ROOT=/work
# shellcheck source=/dev/null
. "$ROOT/forensics/tools/require_court.sh"

HARNESS_SRC="$ROOT/evidence/performance-frontier/campaigns/PFP-4/differential/pfp4_dso_sign.c"
OUT="${PFP4_DIFF_OUT:-$ROOT/evidence/performance-frontier/campaigns/PFP-4/differential}"
RAW="$OUT/raw"
BUILD="$OUT/build"
CAND="${PFP4_DIFF_CAND:-$ROOT/court/tmp/pfp4-a/distribution/libcrypto.so.3}"
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"

EXPECT_AUTH=611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
EXPECT_CAND="${PFP4_DIFF_CAND_SHA:-4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77}"
SEED=0x5046503450485034
COUNT=4096

fail() {
    printf 'PFP4-DIFF STOP: %s\n' "$*" >&2
    exit 1
}

[ -f "$CAND" ] || fail "candidate DSO missing: $CAND"
[ -f "$AUTH" ] || fail "authority DSO missing: $AUTH"
[ -f "$HARNESS_SRC" ] || fail "harness source missing"

CSHA="$(sha256sum "$CAND" | awk '{print $1}')"
ASHA="$(sha256sum "$AUTH" | awk '{print $1}')"
[ "$CSHA" = "$EXPECT_CAND" ] || fail "candidate DSO sha256 $CSHA != $EXPECT_CAND"
[ "$ASHA" = "$EXPECT_AUTH" ] || fail "authority DSO sha256 $ASHA != $EXPECT_AUTH"

mkdir -p "$RAW" "$BUILD"
rm -f "$RAW"/*.out "$RAW"/*.err "$RAW"/*.bin "$RAW"/*.siglines \
      "$RAW"/comparison.tsv "$RAW"/cross-verification.tsv \
      "$RAW"/identity-check.tsv "$RAW"/run-meta.env

echo "=== compile the DSO harness (links no libcrypto) ==="
cc -O2 -g -Wall -Wextra -Wno-deprecated-declarations -I "$INC" \
   "$HARNESS_SRC" -ldl -o "$BUILD/pfp4_dso_sign"

SRC_SHA="$(sha256sum "$HARNESS_SRC" | awk '{print $1}')"
BIN_SHA="$(sha256sum "$BUILD/pfp4_dso_sign" | awk '{print $1}')"
printf '%s  %s\n%s  %s\n' "$SRC_SHA" "$HARNESS_SRC" "$BIN_SHA" \
       "$BUILD/pfp4_dso_sign" >"$RAW/harness.sha256"

printf 'label\tsubject\tdso_sha256\texpected_realpath\treported_realpath\texpected_dev\treported_dev\texpected_ino\treported_ino\texpected_size\treported_size\tmaps_entries\tstatus\n' \
    >"$RAW/identity-check.tsv"
printf 'mode\tcompared_lines\tmismatches\tsigfile_bytes\tsigfile_sha256\teq_lines\n' \
    >"$RAW/comparison.tsv"
printf 'mode\tdirection\tsigner\tverifier\tsigned\tverified\tpublic_key\n' \
    >"$RAW/cross-verification.tsv"

verify_loaded() { # file label subject dso
    local file=$1 label=$2 subject=$3 dso=$4
    local rp dev ino size entries erp edev eino esize lib libres

    read -r rp dev ino size entries < <(
        awk '/^LOADED / {
                 for (i = 2; i <= NF; i++) {
                     split($i, a, "=");
                     if (a[1] == "realpath") r = a[2];
                     else if (a[1] == "dev") d = a[2];
                     else if (a[1] == "ino") n = a[2];
                     else if (a[1] == "size") s = a[2];
                 }
             }
             /^MAPS / {
                 for (i = 2; i <= NF; i++) {
                     split($i, a, "=");
                     if (a[1] == "entries") e = a[2];
                 }
             }
             END { print r, d, n, s, e }' "$file"
    )
    [ -n "${rp:-}" ] || fail "$label/$subject: no LOADED line"
    erp="$(realpath "$dso")"
    read -r edev eino esize < <(stat -c '%d %i %s' "$erp")
    [ "$rp" = "$erp" ] || fail "$label/$subject: mapped $rp, expected $erp"
    [ "$dev" = "$edev" ] || fail "$label/$subject: device $dev != on-disk $edev"
    [ "$ino" = "$eino" ] || fail "$label/$subject: inode $ino != on-disk $eino"
    [ "$size" = "$esize" ] || fail "$label/$subject: size $size != on-disk $esize"
    [ "${entries:-0}" -ge 1 ] || fail "$label/$subject: no /proc/self/maps entry"
    lib="$(awk '/^LIB / { sub(/^LIB /, ""); print; exit }' "$file")"
    libres="$(realpath "$lib")"
    [ "$libres" = "$erp" ] || fail "$label/$subject: LIB $libres != $erp"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$label" "$subject" \
        "$([ "$subject" = candidate ] && echo "$CSHA" || echo "$ASHA")" \
        "$erp" "$rp" "$edev" "$dev" "$eino" "$ino" "$esize" "$size" \
        "$entries" ok >>"$RAW/identity-check.tsv"
}

run() { # mode subject dso outfile sigfile
    local mode=$1 subject=$2 dso=$3 out=$4 sig=$5
    "$BUILD/pfp4_dso_sign" --lib "$dso" --mode "$mode" --seed "$SEED" \
        --count "$COUNT" --sigfile "$sig" >"$out" 2>"$out.err" \
        || fail "$mode/$subject: harness exited nonzero"
    verify_loaded "$out" "$mode" "$subject" "$dso"
    awk '/^SIG / || /^VERIFY /' "$out" >"$out.siglines"
}

check_count() { # file prefix n
    local got
    got="$(grep -c "^$2 " "$1" || true)"
    [ "$got" -eq "$3" ] || fail "$1: $got $2 lines, expected $3"
}

for mode in sign-ex sign-rand; do
    cand_bytes=""; cand_sha=""; cand_eq=""
    auth_bytes=""; auth_sha=""; auth_eq=""
    for subject in candidate authority; do
        if [ "$subject" = candidate ]; then dso="$CAND"; else dso="$AUTH"; fi
        run "$mode" "$subject" "$dso" "$RAW/$mode-$subject.out" \
            "$RAW/$mode-$subject.bin"
        check_count "$RAW/$mode-$subject.out" SIG "$COUNT"
        awk -v n="$COUNT" '/^SIG / {
                if ($3 != "ok=1" || $4 != "self=1") exit 1; c++ }
            END { if (c != n) exit 1 }' "$RAW/$mode-$subject.out" \
            || fail "$mode/$subject: SIG lines are not $COUNT self-verified successes"
        if [ "$mode" = sign-ex ]; then
            eqc="$(grep -c ' eq=1 ' "$RAW/$mode-$subject.out" || true)"
            [ "$eqc" -eq "$COUNT" ] \
                || fail "$mode/$subject: $eqc defining-equation checks, expected $COUNT"
        else
            eqc="-"
        fi
        bytes="$(stat -c %s "$RAW/$mode-$subject.bin")"
        sha="$(sha256sum "$RAW/$mode-$subject.bin" | awk '{print $1}')"
        if [ "$subject" = candidate ]; then
            cand_bytes=$bytes; cand_sha=$sha; cand_eq=$eqc
        else
            auth_bytes=$bytes; auth_sha=$sha; auth_eq=$eqc
        fi
    done

    # Byte-identity of the SIG lines and of the DER records.
    if ! cmp -s "$RAW/$mode-candidate.out.siglines" \
                "$RAW/$mode-authority.out.siglines"; then
        diff -u "$RAW/$mode-authority.out.siglines" \
                "$RAW/$mode-candidate.out.siglines" | sed -n '1,10p' >&2 || true
        fail "$mode: SIG lines differ; a single mismatch is a STOP"
    fi
    cmp -s "$RAW/$mode-candidate.bin" "$RAW/$mode-authority.bin" \
        || fail "$mode: signature files differ; a single mismatch is a STOP"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$mode-candidate" "$COUNT" 0 \
        "$cand_bytes" "$cand_sha" "$cand_eq" >>"$RAW/comparison.tsv"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$mode-authority" "$COUNT" 0 \
        "$auth_bytes" "$auth_sha" "$auth_eq" >>"$RAW/comparison.tsv"

    # Public key must agree across all four processes.
    pubs="$(cat "$RAW/$mode-candidate.out" "$RAW/$mode-authority.out" \
            | grep -o '^PUB [0-9a-f]*' | sort -u | wc -l)"
    [ "$pubs" -eq 1 ] || fail "$mode: processes derived $pubs distinct public keys"
    PUB="$(awk '/^PUB / { print $2; exit }' "$RAW/$mode-candidate.out")"

    # Cross-verification, both directions.
    for pair in "authority candidate" "candidate authority"; do
        set -- $pair
        signer=$1
        verifier=$2
        if [ "$verifier" = candidate ]; then vdso="$CAND"; else vdso="$AUTH"; fi
        run verify "$verifier" "$vdso" \
            "$RAW/$mode-verify-by-$verifier.out" \
            "$RAW/$mode-$signer.bin"
        check_count "$RAW/$mode-verify-by-$verifier.out" VERIFY "$COUNT"
        awk -v n="$COUNT" '/^VERIFY / { if ($3 != "ok=1") exit 1; c++ }
            END { if (c != n) exit 1 }' "$RAW/$mode-verify-by-$verifier.out" \
            || fail "$mode: $verifier rejected a $signer signature"
        printf '%s\t%s\t%s\t%s\t%d\t%d\t%s\n' "$mode" \
            "$signer->$verifier" "$signer" "$verifier" "$COUNT" "$COUNT" "$PUB" \
            >>"$RAW/cross-verification.tsv"
    done
done

# Cross-verification rows are written inside the mode loop above.

# Identity re-check after execution.
CSHA2="$(sha256sum "$CAND" | awk '{print $1}')"
ASHA2="$(sha256sum "$AUTH" | awk '{print $1}')"
[ "$CSHA2" = "$EXPECT_CAND" ] || fail "candidate DSO changed during the run"
[ "$ASHA2" = "$EXPECT_AUTH" ] || fail "authority DSO changed during the run"

{
    echo "candidate_path=$CAND"
    echo "candidate_sha256=$CSHA"
    echo "authority_path=$AUTH"
    echo "authority_sha256=$ASHA"
    echo "seed=$SEED"
    echo "count=$COUNT"
    echo "instrument_source=$HARNESS_SRC"
    echo "instrument_source_sha256=$SRC_SHA"
    echo "instrument_binary_sha256=$BIN_SHA"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
} >"$RAW/run-meta.env"

echo "PASS: PFP-4 DSO differential (candidate $CSHA, authority $ASHA)"
