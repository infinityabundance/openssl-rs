#!/bin/sh
# run_branch_audit.sh — PFP-8: enumerate and classify every conditional
# transfer, setcc and cmovcc in the two carriers the DH profile reaches at the
# frozen digest: the CIOS kernel `mont_mul_ladder_into` (specialised widths are
# inlined) and the window loop `run_mont_ladder` (the masked scan is inlined).
#
# No Rust source changed in this batch, so this is the same DSO as M-A1
# (`88c0c7e0`); the classification is regenerated from THIS digest's listing,
# not inherited.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     courts/performance-frontier/pfp8/run_branch_audit.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8/audit
OUT=/work/court/tmp/pfp8-build
DSO="$OUT/cand/distribution/libcrypto.so.3"
SITES="$EV/disasm_sites.py"
mkdir -p "$EV/raw/disasm"

sym() {
    nm -S --defined-only "$1" | awk -v s="$2" '$NF ~ (s "$") {print $1, $2}'
}

dump() { # tag symbol
    d=cand
    s=$1
    got=$(sym "$DSO" "$s")
    [ -n "$got" ] || { echo "FATAL: $s not found" >&2; exit 1; }
    addr=$(echo "$got" | awk '{print $1}')
    size=$(echo "$got" | awk '{print $2}')
    end=$(printf '%x' $((0x$addr + 0x$size)))
    echo "=== $d $s at 0x$addr size 0x$size ==="
    objdump -d --no-show-raw-insn --start-address="0x$addr" --stop-address="0x$end" \
        "$DSO" >"$EV/raw/disasm/$d-$s.dis"
    python3 "$SITES" "$EV/raw/disasm/$d-$s.dis" "$s" \
        >"$EV/raw/disasm/$d-$s.sites.tsv"
    printf '%s\t%s\t%s\t%s\n' "$d" "$s" "$addr" "$size" \
        >>"$EV/raw/disasm/carriers.tsv"
    awk -F'\t' '{c[$7]++} END {for (k in c) printf "%s=%d ", k, c[k]; print ""}' \
        "$EV/raw/disasm/$d-$s.sites.tsv"
}

: >"$EV/raw/disasm/carriers.tsv"
dump mont_mul_ladder_into
dump run_mont_ladder

printf 'cand dso_sha256=%s\n' "$(sha256sum "$DSO" | awk '{print $1}')" \
    >"$EV/raw/disasm/carrier-identity.txt"
cat "$EV/raw/disasm/carrier-identity.txt"

# Kernel: the M-A1 const-generic CIOS classification, regenerated here.
python3 "$EV/classify_widths.py"
mv "$EV/raw/disasm/classification.tsv" "$EV/raw/disasm/kernel-classification.tsv"
mv "$EV/raw/disasm/classification.md" "$EV/raw/disasm/kernel-classification.md"

# Ladder: the same structural rules, SYMBOL=run_mont_ladder.
python3 "$EV/classify_ladder.py"

echo "branch audit: done"
