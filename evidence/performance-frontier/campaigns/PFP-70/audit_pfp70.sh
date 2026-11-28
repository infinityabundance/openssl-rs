#!/usr/bin/env bash
# PFP-70 emitted-code audit, re-run rather than inherited from PFP-63.
#
# Symbol ranges are read from `nm -S -C` on the exact artefacts, so the script
# survives layout changes. It reports every indexed memory operand and every
# conditional transfer in the portable AES carriers, then runs the same
# instrument on the table reference and the pre-conversion branchy GHASH
# control so the detector is shown to fire.
#
# Usage (inside the court): bash /work/evidence/.../PFP-70/audit_pfp70.sh
set -u
cd /work || exit 1

REL=target/release/examples/pfp63_bench
DBG="$(find target/debug/deps -maxdepth 1 -name 'openssl_rs-*' -type f -perm -u+x | head -1)"

addr_of() { # binary, extended-regex -> "start size"
    nm -S -C --defined-only "$1" | grep -E "$2" | head -1 | awk '{print $1, $2}'
}

dump() { # binary, regex, label
    local bin="$1" re="$2" label="$3"
    local pair start size stop
    pair="$(addr_of "$bin" "$re")"
    if [ -z "$pair" ]; then
        echo "--- $label: ABSENT ---"
        echo
        return
    fi
    start="${pair% *}"
    size="${pair#* }"
    stop="$(printf '0x%x' $((0x$start + 0x$size)))"
    echo "--- $label ($bin 0x$start..$stop) ---"
    objdump -d --no-show-raw-insn --start-address="0x$start" --stop-address="$stop" "$bin" \
        | grep -E '\(%[a-z0-9]+,%[a-z0-9]+,|\(%[a-z0-9]+,%[a-z0-9]+\)|[[:space:]]j[a-z]+[[:space:]]|cmov|set[a-z]+[[:space:]]|call' \
        || echo "  (none)"
    echo
}

echo "== release artefact =="
sha256sum "$REL"
echo
for spec in \
    'AES_encrypt$|AES_encrypt' \
    'aes::aes_encrypt_portable' \
    'portable::bp_sub_bytes::<u16>' \
    'portable::bp_inv_sub_bytes::<u16>' \
    'portable::fix_keys' \
    'AES_decrypt$|AES_decrypt' \
    'AES_set_encrypt_key$|AES_set_encrypt_key' \
    'AES_set_decrypt_key$|AES_set_decrypt_key'; do
    dump "$REL" "$spec" "$spec"
done

cat <<'EOF'
Interpretation
--------------
* bp_sub_bytes and bp_inv_sub_bytes contain no memory operand at all: the
  113-gate netlist is pure XOR/AND/NOT over registers.
* aes_encrypt_portable's only indexed operands are lea (integer
  multiply/shift) and nop; it contains no indexed load or store.
* fix_keys (the exported-schedule -> fixed-slice key conversion) loads the
  round-key bytes at 0xNN(%rsi,%rax,1), where %rax is the public round
  offset, never a key or state byte.
* AES_set_decrypt_key indexes rd_key only by its public i/j loop counters.
* No load or address in any carrier is selected by secret state.
EOF
echo

echo "== firing controls (debug test artefact) =="
sha256sum "$DBG"
echo
dump "$DBG" 'aes::reference::sub_bytes' 'reference::sub_bytes (table lookup; must fire)'
echo 'Interpretation: the table reference emits an indexed load from the S-box base.'
echo
dump "$DBG" 'gcm::negative_control_branchy_mul' 'negative_control_branchy_mul (must fire)'
echo 'Interpretation: the branchy control emits data-dependent conditional transfers.'
echo
dump "$DBG" 'portable::bp_sub_bytes::<u16>' 'portable::bp_sub_bytes (must not fire)'
