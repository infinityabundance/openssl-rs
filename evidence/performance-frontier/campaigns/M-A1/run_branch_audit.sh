#!/bin/sh
# run_branch_audit.sh — M-A1: enumerate every conditional transfer, setcc and
# cmovcc in the CIOS carrier of the candidate DSO.
#
# The eight compile-time-width kernels and the generic fallback are inlined into
# `mont_mul_ladder_into`, so that one symbol is the specialised carrier. The
# generic previous build (`prev`) is dumped for context only. The classification
# is produced from THIS listing by classify_widths.py; no address or count is
# inherited from another digest.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/M-A1/run_branch_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/M-A1
OUT=/work/court/tmp/ma1
SITES="$EV/disasm_sites.py"
mkdir -p "$EV/raw/disasm"

sym() { # dso-path symbol
    nm -S --defined-only "$1" | awk -v s="$2" '$NF ~ (s "$") {print $1, $2}'
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

# The specialised carrier: all eight fixed-width kernels are inlined here.
dump "$OUT/cand/distribution/libcrypto.so.3" cand mont_mul_ladder_into
# Context: the previous (generic slice-kernel) carrier at the previous digest.
dump "$OUT/prev/distribution/libcrypto.so.3" prev mont_mul_ladder_into

# Separate-symbol check: if the compiler chose not to inline a width, its symbol
# would appear here and would need its own audit. Record the observed state.
: >"$EV/raw/disasm/fixed-symbols.txt"
nm --defined-only "$OUT/cand/distribution/libcrypto.so.3" | grep -i 'cios_fixed' \
    >>"$EV/raw/disasm/fixed-symbols.txt" || true
if [ -s "$EV/raw/disasm/fixed-symbols.txt" ]; then
    echo "NOTE: out-of-line fixed-width symbols present (audited separately)" \
        >>"$EV/raw/disasm/fixed-symbols.txt"
else
    echo "no out-of-line mont_mul_cios_fixed symbol: all widths are inlined into mont_mul_ladder_into" \
        >>"$EV/raw/disasm/fixed-symbols.txt"
fi
cat "$EV/raw/disasm/fixed-symbols.txt"

{
    for d in cand prev; do
        p="$OUT/$d/distribution/libcrypto.so.3"
        printf '%s dso_sha256=%s\n' "$d" "$(sha256sum "$p" | awk '{print $1}')"
        printf '%s producer=%s\n' "$d" "$(readelf -p .comment "$p" | sed -n 's/.*\]  //p' | tr '\n' ' ')"
    done
} | tee "$EV/raw/disasm/carrier-identity.txt"

python3 "$EV/classify_widths.py"
echo "branch audit: done"
