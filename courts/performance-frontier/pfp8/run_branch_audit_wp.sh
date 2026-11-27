#!/bin/sh
# run_branch_audit_wp.sh — PFP8-WIDTH-POLICY: enumerate and classify every
# conditional transfer, setcc and cmovcc in the carriers this change reaches at
# the new digest:
#
#   mont_mul_ladder_into          the CIOS kernel (unchanged body, new digest)
#   run_mont_ladder               the window loop + masked scan (new digest)
#   bn_mod_exp_mont_impl          the dispatch that now consults the policy width
#   dh_bn_mod_exp                 the DH method entry that reads the public bound
#
#   bash docker/openssl-rs-court.sh exec bash \
#     courts/performance-frontier/pfp8/run_branch_audit_wp.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8/width-policy/audit
OUT=/work/court/tmp/pfp8-wp-build
DSO="$OUT/cand/distribution/libcrypto.so.3"
SITES=/work/evidence/performance-frontier/campaigns/PFP-8/audit/disasm_sites.py
CLASSIFY=/work/courts/performance-frontier/pfp8/classify_wp.py
mkdir -p "$EV/raw/disasm"
rm -f "$EV/raw/disasm"/*

sym() { # pattern -> "addr size"
    nm -S --defined-only "$DSO" | awk -v s="$1" '$NF ~ s {print $1, $2; exit}'
}

dump() { # label  nm-pattern
    label=$1
    pattern=$2
    got=$(sym "$pattern")
    [ -n "$got" ] || { echo "FATAL: $label ($pattern) not found" >&2; exit 1; }
    addr=$(echo "$got" | awk '{print $1}')
    size=$(echo "$got" | awk '{print $2}')
    end=$(printf '%x' $((0x$addr + 0x$size)))
    echo "=== $label at 0x$addr size 0x$size ==="
    objdump -d --no-show-raw-insn --start-address="0x$addr" --stop-address="0x$end" \
        "$DSO" >"$EV/raw/disasm/$label.dis"
    python3 "$SITES" "$EV/raw/disasm/$label.dis" "$label" \
        >"$EV/raw/disasm/$label.sites.tsv"
    printf '%s\t%s\t%s\t%s\n' "$label" "$label" "$addr" "$size" \
        >>"$EV/raw/disasm/carriers.tsv"
    awk -F'\t' '{c[$7]++} END {for (k in c) printf "%s=%d ", k, c[k]; print ""}' \
        "$EV/raw/disasm/$label.sites.tsv"
}

: >"$EV/raw/disasm/carriers.tsv"
dump mont_mul_ladder_into 'mont_mul_ladder_into$'
dump run_mont_ladder 'run_mont_ladder$'
dump bn_mod_exp_mont_impl 'bn_mod_exp_mont_impl'
dump dh_bn_mod_exp 'dh_bn_mod_exp$'

printf 'cand dso_sha256=%s\n' "$(sha256sum "$DSO" | awk '{print $1}')" \
    >"$EV/raw/disasm/carrier-identity.txt"
cat "$EV/raw/disasm/carrier-identity.txt"

ALLOW=/work/evidence/performance-frontier/campaigns/PFP-8/width-policy/audit/public-arith.json
for label in mont_mul_ladder_into run_mont_ladder bn_mod_exp_mont_impl dh_bn_mod_exp; do
    python3 "$CLASSIFY" "$label" "$ALLOW"
done

echo "branch audit: done"
