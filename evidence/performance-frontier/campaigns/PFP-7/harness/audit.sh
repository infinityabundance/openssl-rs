#!/usr/bin/env bash
# PFP-7 branch audit at the candidate digest: every jcc/setcc/cmovcc in the
# carriers of the RSA private path, re-derived from this digest's disassembly
# (no count inherited from PFP-5/PFP-6 even though the digest is identical).
set -euo pipefail
ROOT=/work
BUILD=${BUILD:-/work/court/tmp/pfp7/build}
DIR=/work/court/tmp/pfp7/audit
DSO="$BUILD/distribution/libcrypto.so.3"
SITES="$ROOT/evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27/disasm_sites.py"
mkdir -p "$DIR"

sym() { nm -S --defined-only "$1" | awk -v s="$2" '$NF ~ ("arith[0-9]+" s "$") {print $1, $2}'; }

dump() { # tag symbol
    tag=$1; s=$2
    got=$(sym "$DSO" "$s" || true)
    if [ -z "$got" ]; then
        echo "$tag $s ABSENT" | tee -a "$DIR/symbols.txt"
        return 0
    fi
    addr=$(echo "$got" | awk '{print $1}')
    size=$(echo "$got" | awk '{print $2}')
    end=$(printf '%x' $((0x$addr + 0x$size)))
    echo "$tag $s 0x$addr size=0x$size" | tee -a "$DIR/symbols.txt"
    objdump -d --no-show-raw-insn --start-address="0x$addr" --stop-address="0x$end" \
        "$DSO" >"$DIR/$tag-$s.dis"
    python3 "$SITES" "$DIR/$tag-$s.dis" "$s" >"$DIR/$tag-$s.sites.tsv"
    awk -F'\t' '{c[$7]++} END {for (k in c) printf "%s %s=%d\n", "'"$tag"'", k, c[k]}' \
        "$DIR/$tag-$s.sites.tsv" | sort | tee -a "$DIR/counts.txt"
}

: >"$DIR/symbols.txt"; : >"$DIR/counts.txt"
objdump -d --no-show-raw-insn --start-address=0x58af00 --stop-address=0x58ce60 "$DSO" >/dev/null 2>&1 || true
dump ladder mont_mul_ladder_into
dump sos mont_mul_sos_into
dump driver run_mont_ladder
dump window run_mont_ladder_window
dump select select_window_digit
dump fallible mont_mul_fallible
dump rsa_mod_exp rsa_ossl_mod_exp
sha256sum "$DSO" | tee "$DIR/dso.sha256"
echo AUDIT_OK
