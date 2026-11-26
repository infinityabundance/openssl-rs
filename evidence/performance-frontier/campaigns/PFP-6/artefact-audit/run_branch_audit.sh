#!/bin/sh
# run_branch_audit.sh — PFP-27: extract every conditional transfer, setcc and
# cmovcc from the kernel carriers in the release DSOs, and prove the dedicated
# squaring kernel is absent from both artefacts.
#
# Carriers audited (symbol extents taken from the artefact's own symbol table):
#   b mont_mul_ladder_into  — the CIOS kernel, inlined (DSO B)
#   a mont_mul_sos_into     — the production multiply and the ladder's squaring
#   b mont_mul_sos_into     — the same function in the CIOS artefact
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/artefact-audit/run_branch_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp27
EV=/work/evidence/performance-frontier/campaigns/PFP-6/artefact-audit
SITES="$EV/disasm_sites.py"
mkdir -p "$EV/raw/disasm"

sym() { # dso symbol
    nm -S --defined-only "$1" | awk -v s="$2" '$4==s {print $1, $2}'
}

for spec in "a mont_mul_sos_into" "b mont_mul_ladder_into" "b mont_mul_sos_into"; do
    set -- $spec
    d=$1; s=$2
    p="$OUT/$d/distribution/libcrypto.so.3"
    got=$(sym "$p" "_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith${#s}_$s")
    # Rust legacy mangling length prefix is the symbol's own length; use a
    # prefix match instead of reconstructing it.
    got=$(nm -S --defined-only "$p" | awk -v s="$s" '$NF ~ ("arith[0-9]+" s "$") {print $1, $2}')
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
done

echo "=== dedicated squaring kernel presence ==="
: >"$EV/raw/disasm/absent-squaring.txt"
for d in a b; do
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
    for d in a b; do
        p="$OUT/$d/distribution/libcrypto.so.3"
        printf '%s dso_sha256=%s\n' "$d" "$(sha256sum "$p" | awk '{print $1}')"
        printf '%s producer=%s\n' "$d" "$(readelf -p .comment "$p" | sed -n 's/.*\]  //p' | tr '\n' ' ')"
    done
} | tee "$EV/raw/disasm/carrier-identity.txt"

echo "branch audit: done"
