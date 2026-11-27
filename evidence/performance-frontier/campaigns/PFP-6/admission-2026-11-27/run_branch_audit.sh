#!/bin/sh
# run_branch_audit.sh — PFP-6 admission: enumerate every conditional transfer,
# setcc and cmovcc in the CIOS carrier of the admitted DSO, plus the SOS
# reference and the ladder driver for context.
#
# The classification is produced by classify_cios.py from THIS listing; no
# address or count is inherited from PFP-27's earlier digest.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27/run_branch_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27
OUT=/work/court/tmp/pfp6-admission
SITES="$EV/disasm_sites.py"
mkdir -p "$EV/raw/disasm"

sym() { # dso-path symbol
    nm -S --defined-only "$1" | awk -v s="$2" '$NF ~ ("arith[0-9]+" s "$") {print $1, $2}'
}

dump() { # dso-path tag symbol
    p=$1; d=$2; s=$3
    got=$(sym "$p" "$s")
    [ -n "$got" ] || { echo "FATAL: $s not found in $d" >&2; exit 1; }
    addr=$(echo "$got" | awk '{print $1}')
    size=$(echo "$got" | awk '{print $2}')
    end=$(printf '%x' $((0x$addr + 0x$size)))
    echo "=== $d $s at 0x$addr size 0x$size ==="
    objdump -d --no-show-raw-insn --start-address="0x$addr" --stop-address="0x$end" \
        "$p" >"$EV/raw/disasm/$d-$s.dis"
    python3 "$SITES" "$EV/raw/disasm/$d-$s.dis" "$s" \
        >"$EV/raw/disasm/$d-$s.sites.tsv"
    printf '%s\t%s\t%s\t%s\n' "$d" "$s" "$addr" "$size" \
        >>"$EV/raw/disasm/carriers.tsv"
    awk -F'\t' '{c[$7]++} END {for (k in c) printf "%s=%d ", k, c[k]; print ""}' \
        "$EV/raw/disasm/$d-$s.sites.tsv"
}

: >"$EV/raw/disasm/carriers.tsv"

# The CIOS carrier (the kernel whose overflowing_add carry handling is audited).
dump "$OUT/cand/distribution/libcrypto.so.3" cand mont_mul_ladder_into
# Context: the SOS reference kernel (present in the reference twin).
dump "$OUT/ref/distribution/libcrypto.so.3" ref mont_mul_sos_into
# Context: the window driver (public-exponent selection and loop geometry).
dump "$OUT/cand/distribution/libcrypto.so.3" cand run_mont_ladder

echo "=== dedicated squaring kernel presence ==="
: >"$EV/raw/disasm/absent-squaring.txt"
for d in cand ref; do
    p="$OUT/$d/distribution/libcrypto.so.3"
    if nm -a "$p" | grep -q 'mont_sqr_into'; then
        echo "$d PRESENT" >>"$EV/raw/disasm/absent-squaring.txt"
    else
        echo "$d absent (LADDER_DEDICATED_SQUARING = false; no symbol, no body)" \
            >>"$EV/raw/disasm/absent-squaring.txt"
    fi
done
cat "$EV/raw/disasm/absent-squaring.txt"

{
    for d in cand ref; do
        p="$OUT/$d/distribution/libcrypto.so.3"
        printf '%s dso_sha256=%s\n' "$d" "$(sha256sum "$p" | awk '{print $1}')"
        printf '%s producer=%s\n' "$d" "$(readelf -p .comment "$p" | sed -n 's/.*\]  //p' | tr '\n' ' ')"
    done
} | tee "$EV/raw/disasm/carrier-identity.txt"

python3 "$EV/classify_cios.py"
echo "branch audit: done"
