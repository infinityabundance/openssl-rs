#!/bin/sh
# regen_wrappers.sh — disassemble each emitted BMI2 wrapper at its exact range.
set -eu
cd /work
EV=evidence/performance-frontier/campaigns/PFP-46
DSO="${1:-court/tmp/pfp46/after/libcrypto.so.3}"
mkdir -p "$EV/raw/after/disasm"
nm -S --defined-only -C "$DSO" \
    | awk '/mont_mul_cios_bmi2_[0-9]+$/ { name=$4; for (i=5;i<=NF;i++) name=name" "$i; print $1, $2, name }' \
    >"$EV/raw/after/wrappers.txt"
while read -r addr size name; do
    [ -n "$addr" ] || continue
    short=$(printf '%s' "$name" | sed 's/.*:://')
    objdump -d --no-show-raw-insn --start-address=0x$addr \
        --stop-address=$((0x$addr + 0x$size)) "$DSO" \
        >"$EV/raw/after/disasm/${short}.dis"
    printf '%-36s insns=%s mulx=%s mulq=%s adcx=%s adox=%s\n' "$short" \
        "$(grep -cE '^\s+[0-9a-f]+:\s' "$EV/raw/after/disasm/${short}.dis" || true)" \
        "$(grep -cE '^\s+[0-9a-f]+:\s+mulx' "$EV/raw/after/disasm/${short}.dis" || true)" \
        "$(grep -cE '^\s+[0-9a-f]+:\s+mulq' "$EV/raw/after/disasm/${short}.dis" || true)" \
        "$(grep -cE '^\s+[0-9a-f]+:\s+adcx' "$EV/raw/after/disasm/${short}.dis" || true)" \
        "$(grep -cE '^\s+[0-9a-f]+:\s+adox' "$EV/raw/after/disasm/${short}.dis" || true)"
done <"$EV/raw/after/wrappers.txt"
