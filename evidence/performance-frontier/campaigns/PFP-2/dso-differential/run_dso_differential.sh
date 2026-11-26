#!/usr/bin/env bash
#
# run_dso_differential.sh — PFP-2 differential court bound to the shipped DSO.
#
# One process per subject.  Each process dlopens exactly one libcrypto.so.3 and
# prints the file it actually mapped (`LOADED` realpath/dev/ino/size and `LIB`
# from dladdr); this runner compares those fields with stat(2) on the expected
# on-disk DSO and refuses a mismatch.  That is what makes the court DSO-bound
# rather than source-bound.
#
# The candidate and authority DSO digests are checked before any case runs and
# again after.  A single serialised-point mismatch, a rejected cross-signature,
# a population shortfall or an identity mismatch is a STOP (exit 1); nothing is
# aggregated into a statistic.
#
# Runs inside the court:
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec \
#       bash evidence/performance-frontier/campaigns/PFP-2/dso-differential/run_dso_differential.sh
#
# Nothing is rebuilt: the candidate is the frozen distribution DSO at
# 83f67826, built by the campaign from staging 790685a0aa's src.

set -euo pipefail

ROOT=/work
# shellcheck source=/dev/null
. "$ROOT/forensics/tools/require_court.sh"

CAND="${PFP2_DIFF_CAND:-$ROOT/court/tmp/pfp2-fix/distribution/libcrypto.so.3}"
AUTH="${PFP2_DIFF_AUTH:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3}"
AUTH_PREFIX="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
AUTH_INC="$AUTH_PREFIX/include"
OUT="${PFP2_DIFF_OUT:-$ROOT/evidence/performance-frontier/campaigns/PFP-2/dso-differential}"
RAW="$OUT/raw"
BUILD="$OUT/build"

EXPECT_CAND=83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f
EXPECT_AUTH=611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
SEED=0x5046503250485032
COUNT=4096
SIG_COUNT=256

fail() {
    printf 'PFP2-DSO-DIFF STOP: %s\n' "$*" >&2
    exit 1
}

[ -f "$CAND" ] || fail "candidate DSO missing: $CAND"
[ -f "$AUTH" ] || fail "authority DSO missing: $AUTH"
[ -f "$OUT/pfp2_dso_differential.c" ] || fail "harness source missing"

CSHA="$(sha256sum "$CAND" | awk '{print $1}')"
ASHA="$(sha256sum "$AUTH" | awk '{print $1}')"
[ "$CSHA" = "$EXPECT_CAND" ] || fail "candidate DSO sha256 $CSHA != $EXPECT_CAND"
[ "$ASHA" = "$EXPECT_AUTH" ] || fail "authority DSO sha256 $ASHA != $EXPECT_AUTH"

mkdir -p "$RAW" "$BUILD"
rm -f "$RAW"/*.out "$RAW"/*.out.err "$RAW"/*.points "$RAW"/comparison.tsv \
      "$RAW"/cross-verification.tsv "$RAW"/identity-check.tsv "$RAW"/run-meta.env \
      "$RAW"/signatures-*.bin "$OUT"/differential-dso-bound.json

echo "=== compile the DSO harness (links no libcrypto) ==="
cc -O2 -g -Wall -Wextra -Wno-deprecated-declarations -I "$AUTH_INC" \
   "$OUT/pfp2_dso_differential.c" -ldl -o "$BUILD/pfp2_dso_differential"

SRC_SHA="$(sha256sum "$OUT/pfp2_dso_differential.c" | awk '{print $1}')"
BIN_SHA="$(sha256sum "$BUILD/pfp2_dso_differential" | awk '{print $1}')"
printf '%s  %s\n%s  %s\n' "$SRC_SHA" "$OUT/pfp2_dso_differential.c" \
       "$BIN_SHA" "$BUILD/pfp2_dso_differential" >"$RAW/harness.sha256"

printf 'label\tsubject\tdso_sha256\texpected_realpath\treported_realpath\texpected_dev\treported_dev\texpected_ino\treported_ino\texpected_size\treported_size\tmaps_entries\tstatus\n' \
    >"$RAW/identity-check.tsv"
printf 'mode\tcompared_lines\tmismatches\tcandidate_output_sha256\tauthority_output_sha256\n' \
    >"$RAW/comparison.tsv"
printf 'direction\tsigner\tverifier\tsigned\tverified\tpublic_key\n' \
    >"$RAW/cross-verification.tsv"

CURRENT_LABEL=""

verify_loaded() { # file subject dso
    local file=$1 subject=$2 dso=$3 rp dev ino size entries
    local erp edev eino esize lib libres

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
    [ -n "${rp:-}" ] || fail "$CURRENT_LABEL/$subject: no LOADED line"
    erp="$(realpath "$dso")"
    read -r edev eino esize < <(stat -c '%d %i %s' "$erp")
    [ "$rp" = "$erp" ] || fail "$CURRENT_LABEL/$subject: mapped $rp, expected $erp"
    [ "$dev" = "$edev" ] || fail "$CURRENT_LABEL/$subject: device $dev != on-disk $edev"
    [ "$ino" = "$eino" ] || fail "$CURRENT_LABEL/$subject: inode $ino != on-disk $eino"
    [ "$size" = "$esize" ] || fail "$CURRENT_LABEL/$subject: size $size != on-disk $esize"
    [ "${entries:-0}" -ge 1 ] || fail "$CURRENT_LABEL/$subject: no /proc/self/maps entry"
    lib="$(awk '/^LIB / { sub(/^LIB /, ""); print; exit }' "$file")"
    libres="$(realpath "$lib")"
    [ "$libres" = "$erp" ] || fail "$CURRENT_LABEL/$subject: LIB $libres != $erp"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$CURRENT_LABEL" "$subject" \
        "$([ "$subject" = candidate ] && echo "$CSHA" || echo "$ASHA")" \
        "$erp" "$rp" "$edev" "$dev" "$eino" "$ino" "$esize" "$size" \
        "$entries" ok >>"$RAW/identity-check.tsv"
}

run() { # subject dso outfile args...
    local subject=$1 dso=$2 out=$3
    shift 3
    "$BUILD/pfp2_dso_differential" --lib "$dso" --seed "$SEED" "$@" \
        >"$out" 2>"$out.err" || fail "$CURRENT_LABEL/$subject: harness exited nonzero"
    verify_loaded "$out" "$subject" "$dso"
}

check_point_population() { # file n
    local file=$1 n=$2 got
    got="$(awk '$1 == "POINT" { c++ } END { print c + 0 }' "$file")"
    [ "$got" -eq "$n" ] || fail "$CURRENT_LABEL: $got POINT lines, expected $n"
    awk -v n="$n" 'BEGIN { expect = 0 }
        $1 == "POINT" { split($2, a, "="); if (a[2] + 0 != expect) exit 1; expect++ }
        END { if (expect != n) exit 1 }' "$file" \
        || fail "$CURRENT_LABEL: POINT indices are not 0..$((n - 1)) in order"
}

compare_points() { # mode
    local mode=$1 cf="$RAW/$1-candidate.points" af="$RAW/$1-authority.points"
    grep '^POINT ' "$RAW/$mode-candidate.out" >"$cf"
    grep '^POINT ' "$RAW/$mode-authority.out" >"$af"
    cmp -s "$cf" "$af" || {
        echo "--- first differing cases (authority then candidate) ---" >&2
        diff -u "$af" "$cf" | sed -n '1,20p' >&2
        fail "$mode: serialised point mismatch; a single mismatch is a STOP"
    }
    local sc sa
    sc="$(sha256sum "$cf" | awk '{print $1}')"
    sa="$(sha256sum "$af" | awk '{print $1}')"
    printf '%s\t%d\t0\t%s\t%s\n' "$mode" "$COUNT" "$sc" "$sa" \
        >>"$RAW/comparison.tsv"
}

check_sign_lines() { # file n
    awk -v n="$2" '$1 == "SIGN" {
            if ($3 != "ok=1" || $4 != "self=1") exit 1; c++ }
        END { if (c != n) exit 1 }' "$1" \
        || fail "$CURRENT_LABEL: SIGN lines are not $2 self-verified successes"
}

check_verify_lines() { # file n
    awk -v n="$2" '$1 == "VERIFY" {
            if ($3 != "ok=1") exit 1; c++ }
        END { if (c != n) exit 1 }' "$1" \
        || fail "$CURRENT_LABEL: VERIFY lines are not $2 accepted signatures"
}

# --- multiplication courts -------------------------------------------------

for mode in mul-g mul-p; do
    for subject in candidate authority; do
        if [ "$subject" = candidate ]; then dso="$CAND"; else dso="$AUTH"; fi
        CURRENT_LABEL="mul"
        run "$subject" "$dso" "$RAW/$mode-$subject.out" --mode "$mode" --count "$COUNT"
        check_point_population "$RAW/$mode-$subject.out" "$COUNT"
    done
    cmp -s <(sed -n 's/^MODE .*/&/p' "$RAW/$mode-candidate.out") \
           <(sed -n 's/^MODE .*/&/p' "$RAW/$mode-authority.out") \
        || fail "$mode: MODE line differs"
    compare_points "$mode"
done

# --- ECDSA sign / cross-verify, both directions ----------------------------

CURRENT_LABEL="ecdsa-candidate-signs"
run candidate "$CAND" "$RAW/sign-candidate.out" --mode sign \
    --count "$SIG_COUNT" --sigfile "$RAW/signatures-candidate.bin"
check_sign_lines "$RAW/sign-candidate.out" "$SIG_COUNT"

CURRENT_LABEL="ecdsa-authority-verifies"
run authority "$AUTH" "$RAW/verify-authority.out" --mode verify \
    --count "$SIG_COUNT" --sigfile "$RAW/signatures-candidate.bin"
check_verify_lines "$RAW/verify-authority.out" "$SIG_COUNT"

CURRENT_LABEL="ecdsa-authority-signs"
run authority "$AUTH" "$RAW/sign-authority.out" --mode sign \
    --count "$SIG_COUNT" --sigfile "$RAW/signatures-authority.bin"
check_sign_lines "$RAW/sign-authority.out" "$SIG_COUNT"

CURRENT_LABEL="ecdsa-candidate-verifies"
run candidate "$CAND" "$RAW/verify-candidate.out" --mode verify \
    --count "$SIG_COUNT" --sigfile "$RAW/signatures-authority.bin"
check_verify_lines "$RAW/verify-candidate.out" "$SIG_COUNT"

# The derived public key and the message sequence must agree on both sides.
pubs="$(cat "$RAW/sign-candidate.out" "$RAW/verify-authority.out" \
             "$RAW/sign-authority.out" "$RAW/verify-candidate.out" \
        | grep -o 'pub=[0-9a-f]*' | sed 's/^pub=//' | sort -u | wc -l)"
[ "$pubs" -eq 1 ] || fail "ECDSA: the four processes derived ${pubs} distinct public keys"
PUB="$(awk -F'pub=' '/^SIGN / { print $2; exit }' "$RAW/sign-candidate.out")"
[ -n "$PUB" ] || fail "ECDSA: no public key in the candidate sign output"

for f in verify-authority sign-authority verify-candidate; do
    grep -o 'msg=[0-9a-f]*' "$RAW/$f.out" | sed 's/^msg=//' >"$RAW/$f.msgs"
done
grep -o 'msg=[0-9a-f]*' "$RAW/sign-candidate.out" | sed 's/^msg=//' \
    >"$RAW/sign-candidate.msgs"
for f in verify-authority sign-authority verify-candidate; do
    cmp -s "$RAW/sign-candidate.msgs" "$RAW/$f.msgs" \
        || fail "ECDSA: message sequence differs between candidate-sign and $f"
done

printf 'candidate->authority\tcandidate\tauthority\t%d\t%d\t%s\n' \
    "$SIG_COUNT" "$SIG_COUNT" "$PUB" >>"$RAW/cross-verification.tsv"
printf 'authority->candidate\tauthority\tcandidate\t%d\t%d\t%s\n' \
    "$SIG_COUNT" "$SIG_COUNT" "$PUB" >>"$RAW/cross-verification.tsv"

# --- identity re-check after execution -------------------------------------

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
    echo "sig_count=$SIG_COUNT"
    echo "instrument_source=$OUT/pfp2_dso_differential.c"
    echo "instrument_source_sha256=$SRC_SHA"
    echo "instrument_binary_sha256=$BIN_SHA"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
} >"$RAW/run-meta.env"

{
    echo "$BUILD/pfp2_dso_differential --lib <dso> --seed $SEED --mode mul-g --count $COUNT"
    echo "$BUILD/pfp2_dso_differential --lib <dso> --seed $SEED --mode mul-p --count $COUNT"
    echo "$BUILD/pfp2_dso_differential --lib <dso> --seed $SEED --mode sign --count $SIG_COUNT --sigfile <file>"
    echo "$BUILD/pfp2_dso_differential --lib <dso> --seed $SEED --mode verify --count $SIG_COUNT --sigfile <file>"
} >"$RAW/commands.txt"

python3 "$OUT/dso_differential_record.py" --dir "$OUT" \
    --out "$OUT/differential-dso-bound.json"

echo "PASS: DSO-bound differential completed (candidate $CSHA, authority $ASHA)"
