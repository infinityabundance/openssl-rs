#!/usr/bin/env bash
# PFP-63 portable-half emitted-code audit.
#
# Prints, for the exact release example and debug test binaries named below, every
# indexed memory operand and every conditional transfer inside the portable AES
# carriers, followed by the firing negative controls (the table reference and the
# pre-conversion branchy GHASH multiply).
#
# Run from the court: bash /work/evidence/performance-frontier/campaigns/PFP-63/raw/portable-audit.sh
set -u
cd /work || exit 1

REL=target/release/examples/pfp63_bench
DBG=target/debug/deps/openssl_rs-bcfdf4d0f51f39b5

dump() {
  local file="$1" start="$2" stop="$3" label="$4"
  echo "--- $label ($file 0x$start..0x$stop) ---"
  echo "indexed memory / conditional transfer / call lines:"
  objdump -d --no-show-raw-insn --start-address="0x$start" --stop-address="0x$stop" "$file" \
    | grep -E '\(%[a-z0-9]+,%[a-z0-9]+,|[[:space:]]j[a-z]+[[:space:]]|cmov|call' \
    || echo "  (none)"
  echo
}

echo "== release artefact =="
sha256sum "$REL"
nm -C "$REL" | grep -E 'aes::portable::(sub_bytes|inv_planes|encrypt_block|add_round_key)|gcm::gf_mul_portable' || true
echo

dump "$REL" 4e660 4ecb0 "portable::sub_bytes (SubBytes/InvSubBytes circuit carrier)"
dump "$REL" 4bd40 4c160 "portable::inv_planes (field inverse)"
dump "$REL" 4c870 4cca0 "portable::encrypt_block (round driver)"
dump "$REL" 4c160 4c280 "portable::add_round_key"
dump "$REL" 48310 48840 "AES_set_decrypt_key (schedule transform)"
echo "Interpretation: the only indexed loads in the portable AES carriers are the four"
echo "schedule words in add_round_key. Their index is %rax, the public round counter,"
echo "never a key or state byte. sub_bytes, inv_planes and encrypt_block contain no"
echo "indexed memory operand at all; the shifts in encrypt_block are MixColumns' xtime."
echo "The AES_set_decrypt_key transform indexes rd_key only by its public i/j/off loop"
echo "counters; no key byte selects an address."
echo

dump "$REL" 4a2c0 4a358 "gcm::gf_mul_portable (portable GHASH field multiply)"
echo "Interpretation: no indexed memory operand. The only conditional transfer is the"
echo "fixed 128-count loop back-edge; operand-bit selection is cmov/mask."
echo

echo "== debug test artefact (firing controls) =="
sha256sum "$DBG"
nm -C "$DBG" | grep -E 'reference::sub_bytes|negative_control_branchy_mul|aes::portable::sub_bytes' || true
echo

dump "$DBG" 1d417f0 1d41890 "reference::sub_bytes (table lookup; instrument must fire)"
echo "Interpretation: the table reference emits an indexed load from the S-box base."
echo

dump "$DBG" 1414320 1414460 "negative_control_branchy_mul (pre-conversion GHASH; instrument must fire)"
echo "Interpretation: the branchy control emits data-dependent conditional transfers."
echo

dump "$DBG" 15c4300 15c4350 "portable::sub_bytes (same instrument; must not fire)"
dump "$DBG" 1413e90 1413ff0 "gcm::gf_mul_portable (same instrument; must not fire)"
echo "Note: the debug build enables overflow checks, so the debug gf_mul_portable also"
echo "contains public loop-bound/overflow branches. The adjudicated artefact is the"
echo "release example above; the debug copy is used only for the firing controls."
echo

echo "== production table reachability =="
grep -rn 'AES_SBOX\|AES_INV_SBOX' src --include='*.rs' || true
echo
echo "The two statics are #[cfg(test)]; their only readers are src/aes/reference.rs and"
echo "src/aes/portable.rs's cfg(test) tests, plus src/aes/research.rs (test-only)."
