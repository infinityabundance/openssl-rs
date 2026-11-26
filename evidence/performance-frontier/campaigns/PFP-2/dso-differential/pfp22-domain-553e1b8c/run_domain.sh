#!/usr/bin/env bash
#
# run_domain.sh — PFP-22 differential domain completion, bound to the shipped
# DSOs at candidate 553e1b8c and authority 611e511d.
#
# The instrument is the dlopen loader and identity proof of the PFP-2 court
# (pfp2_dso_differential.c, same source sha256): one process per subject loads
# exactly one libcrypto.so.3, prints LOADED realpath/dev/ino/size and LIB from
# dladdr, and every case is compared byte-for-byte on its serialised point.
# Nothing is rebuilt; the candidate is the frozen distribution DSO.
#
# Classes (each with its own seed and case count):
#   base-mul-g      4096   the original seed-driven population, kept comparable
#   base-mul-p      4096   the original seed-driven population, kept comparable
#   upper-g         4096   uniform in [2^255, q-1], k*G
#   upper-p         4096   uniform in [2^255, q-1], k*P
#   boundary-g         8   1, 2, q-2, q-1, q, q+1, 2q-1, 2^256-1 as k*G
#   boundary-p         8   the same boundaries as k*P
#   exceptional       10   infinity, zero operands, generator/non-generator,
#                          decode acceptance/rejection, all-zero/all-0xff limbs
#   limb-g            12   one non-zero limb per position + top-limb-zero, k*G
#   limb-p            12   the same scalars, k*P
#
# A single serialised-point difference, an identity mismatch, a population
# shortfall or a changed DSO digest is a STOP (exit 1).  Nothing is aggregated.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec bash \
#       evidence/performance-frontier/campaigns/PFP-2/dso-differential/pfp22-domain-553e1b8c/run_domain.sh

set -euo pipefail

ROOT=/work
# shellcheck source=/dev/null
. "$ROOT/forensics/tools/require_court.sh"

CAND="${PFP22_DOMAIN_CAND:-$ROOT/court/tmp/pfp21/a/distribution/libcrypto.so.3}"
AUTH="${PFP22_DOMAIN_AUTH:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3}"
AUTH_PREFIX="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
AUTH_INC="$AUTH_PREFIX/include"
OUT="$ROOT/evidence/performance-frontier/campaigns/PFP-2/dso-differential/pfp22-domain-553e1b8c"
RAW="$OUT/raw"
BUILD="$OUT/build"

EXPECT_CAND=553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4
EXPECT_AUTH=611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2

# Historical digests of the original 4096+4096 population at these two DSOs,
# from dso-differential-pfp20/raw.  Reproducing them proves the comparable
# population did not change when the new classes were added.
HIST_MUL_G=a9e1068d9c28846fd8beec36d372845723e9f253f3c09602fe93bfb7a23361fd
HIST_MUL_P=bcb22a91415f5a8593262b56935218f0a21712b2bbedddb2d8824d485af9e23b

BASE_SEED=0x5046503250485032
UPPER_G_SEED=0x5050463232555047
UPPER_P_SEED=0x5050463232555050
BOUNDARY_G_SEED=0x5050463232424f47
BOUNDARY_P_SEED=0x5050463232424f50
EXCEPTIONAL_SEED=0x5050463232455845
LIMB_G_SEED=0x50504632324c4d47
LIMB_P_SEED=0x50504632324c4d50

fail() {
    printf 'PFP22-DOMAIN STOP: %s\n' "$*" >&2
    exit 1
}

[ -f "$CAND" ] || fail "candidate DSO missing: $CAND"
[ -f "$AUTH" ] || fail "authority DSO missing: $AUTH"
[ -f "$OUT/pfp22_domain_differential.c" ] || fail "harness source missing"

CSHA="$(sha256sum "$CAND" | awk '{print $1}')"
ASHA="$(sha256sum "$AUTH" | awk '{print $1}')"
[ "$CSHA" = "$EXPECT_CAND" ] || fail "candidate DSO sha256 $CSHA != $EXPECT_CAND"
[ "$ASHA" = "$EXPECT_AUTH" ] || fail "authority DSO sha256 $ASHA != $EXPECT_AUTH"

mkdir -p "$RAW" "$BUILD"
rm -f "$RAW"/*.out "$RAW"/*.out.err "$RAW"/*.points "$RAW"/comparison.tsv \
      "$RAW"/identity-check.tsv "$RAW"/run-meta.env

echo "=== compile the DSO harness (links no libcrypto) ==="
cc -O2 -g -Wall -Wextra -Wno-deprecated-declarations -I "$AUTH_INC" \
   "$OUT/pfp22_domain_differential.c" -ldl -o "$BUILD/pfp22_domain_differential"

SRC_SHA="$(sha256sum "$OUT/pfp22_domain_differential.c" | awk '{print $1}')"
BIN_SHA="$(sha256sum "$BUILD/pfp22_domain_differential" | awk '{print $1}')"
printf '%s  %s\n%s  %s\n' "$SRC_SHA" "$OUT/pfp22_domain_differential.c" \
       "$BIN_SHA" "$BUILD/pfp22_domain_differential" >"$RAW/harness.sha256"

printf 'class\tmode\tseed\texpected_cases\tcompared_lines\tmismatches\tcandidate_output_sha256\tauthority_output_sha256\n' \
    >"$RAW/comparison.tsv"
printf 'label\tsubject\tdso_sha256\texpected_realpath\treported_realpath\texpected_dev\treported_dev\texpected_ino\treported_ino\texpected_size\treported_size\tmaps_entries\tstatus\n' \
    >"$RAW/identity-check.tsv"

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

run_one() { # class mode seed count subject dso outfile
    local cls=$1 mode=$2 seed=$3 count=$4 subject=$5 dso=$6 out=$7
    CURRENT_LABEL="$cls"
    "$BUILD/pfp22_domain_differential" --lib "$dso" --mode "$mode" --seed "$seed" \
        --count "$count" >"$out" 2>"$out.err" \
        || fail "$cls/$subject: harness exited nonzero"
    verify_loaded "$out" "$subject" "$dso"
}

check_population() { # file n label
    local file=$1 n=$2 label=$3 got
    got="$(awk '$1 == "POINT" { c++ } END { print c + 0 }' "$file")"
    [ "$got" -eq "$n" ] || fail "$label: $got POINT lines, expected $n"
    awk -v n="$n" 'BEGIN { expect = 0 }
        $1 == "POINT" {
            idx = -1;
            for (k = 2; k <= NF; k++) {
                split($k, a, "=");
                if (a[1] == "i") idx = a[2] + 0;
            }
            if (idx != expect) exit 1;
            expect++;
        }
        END { if (expect != n) exit 1 }' "$file" \
        || fail "$label: POINT indices are not 0..$((n - 1)) in order"
}

point_of() { # file case-pattern
    awk -v pat="$2" '$0 ~ pat {
            for (i = 1; i <= NF; i++)
                if ($i ~ /^point=/) { sub(/^point=/, "", $i); print $i; exit }
        }' "$1"
}

run_class() { # class mode seed count
    local cls=$1 mode=$2 seed=$3 count=$4 subject dso
    local cf="$RAW/$cls-candidate.out" af="$RAW/$cls-authority.out"

    for subject in candidate authority; do
        if [ "$subject" = candidate ]; then dso="$CAND"; else dso="$AUTH"; fi
        run_one "$cls" "$mode" "$seed" "$count" "$subject" "$dso" "$RAW/$cls-$subject.out"
        check_population "$RAW/$cls-$subject.out" "$count" "$cls/$subject"
    done

    grep '^POINT ' "$cf" >"$RAW/$cls-candidate.points"
    grep '^POINT ' "$af" >"$RAW/$cls-authority.points"
    cmp -s "$RAW/$cls-candidate.points" "$RAW/$cls-authority.points" || {
        echo "--- first differing cases (authority then candidate) ---" >&2
        diff -u "$RAW/$cls-authority.points" "$RAW/$cls-candidate.points" | sed -n '1,40p' >&2
        fail "$cls: serialised point mismatch; a single mismatch is a STOP"
    }

    local sc sa
    sc="$(sha256sum "$RAW/$cls-candidate.points" | awk '{print $1}')"
    sa="$(sha256sum "$RAW/$cls-authority.points" | awk '{print $1}')"
    printf '%s\t%s\t%s\t%s\t%s\t0\t%s\t%s\n' \
        "$cls" "$mode" "$seed" "$count" "$count" "$sc" "$sa" >>"$RAW/comparison.tsv"
}

# --- the original population, reported separately --------------------------
run_class base-mul-g mul-g "$BASE_SEED" 4096
run_class base-mul-p mul-p "$BASE_SEED" 4096

base_g="$(sha256sum "$RAW/base-mul-g-candidate.points" | awk '{print $1}')"
base_p="$(sha256sum "$RAW/base-mul-p-candidate.points" | awk '{print $1}')"
[ "$base_g" = "$HIST_MUL_G" ] \
    || fail "base-mul-g does not reproduce the historical digest: $base_g != $HIST_MUL_G"
[ "$base_p" = "$HIST_MUL_P" ] \
    || fail "base-mul-p does not reproduce the historical digest: $base_p != $HIST_MUL_P"

# --- class 1: upper half ---------------------------------------------------
run_class upper-g upper-g "$UPPER_G_SEED" 4096
run_class upper-p upper-p "$UPPER_P_SEED" 4096
for f in upper-g upper-p; do
    rej="$(grep -c 'status=rej' "$RAW/$f-authority.points" || true)"
    [ "${rej:-0}" -eq 0 ] || fail "$f: authority rejected ${rej} upper-half scalars"
done

# --- class 2: order boundaries --------------------------------------------
run_class boundary-g boundary-g "$BOUNDARY_G_SEED" 8
run_class boundary-p boundary-p "$BOUNDARY_P_SEED" 8

# Mathematical sanity on the trusted authority, so the comparison is not a
# comparison of two identically broken outputs.
bq="$(point_of "$RAW/boundary-g-authority.points" 'case=q ')"
bq1="$(point_of "$RAW/boundary-g-authority.points" 'case=q\+1 ')"
bone="$(point_of "$RAW/boundary-g-authority.points" 'case=one ')"
[ "$bq" = "00" ] || fail "boundary-g: q*G is not the point at infinity (got $bq)"
[ "$bq1" = "$bone" ] || fail "boundary-g: (q+1)*G differs from 1*G"
[ "${#bone}" -eq 130 ] || fail "boundary-g: 1*G is not a 65-byte uncompressed point"

# --- class 3: exceptional and structural ----------------------------------
run_class exceptional exceptional "$EXCEPTIONAL_SEED" 10
[ "$(point_of "$RAW/exceptional-authority.points" 'case=zero_alllimbs_g ')" = "00" ] \
    || fail "exceptional: 0*G is not the point at infinity"
[ "$(point_of "$RAW/exceptional-authority.points" 'case=infinity_base_5 ')" = "00" ] \
    || fail "exceptional: 5*infinity is not the point at infinity"
g7="$(point_of "$RAW/exceptional-authority.points" 'case=generator_base_7 ')"
[ "${#g7}" -eq 130 ] || fail "exceptional: 7*G is not a 65-byte uncompressed point"
grep -q 'case=reject_offcurve .* status=rej' "$RAW/exceptional-authority.points" \
    || fail "exceptional: authority accepted an off-curve point"

# --- class 4: limb occupancy ----------------------------------------------
run_class limb-g limb-g "$LIMB_G_SEED" 12
run_class limb-p limb-p "$LIMB_P_SEED" 12
for f in limb-g limb-p; do
    rej="$(grep -c 'status=rej' "$RAW/$f-authority.points" || true)"
    [ "${rej:-0}" -eq 0 ] || fail "$f: authority rejected ${rej} limb cases"
done

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
    echo "instrument_source=$OUT/pfp22_domain_differential.c"
    echo "instrument_source_sha256=$SRC_SHA"
    echo "instrument_binary_sha256=$BIN_SHA"
    echo "historical_mul_g_sha256=$HIST_MUL_G"
    echo "historical_mul_p_sha256=$HIST_MUL_P"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
    echo "cc=$(cc --version | head -1)"
} >"$RAW/run-meta.env"

python3 "$OUT/domain_record.py" --dir "$OUT" --out "$OUT/domain-differential-553e1b8c.json"

echo "PASS: PFP-22 domain differential completed (candidate $CSHA, authority $ASHA)"
