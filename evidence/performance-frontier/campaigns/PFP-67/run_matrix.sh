#!/usr/bin/env bash
# PFP-67 Step 3 — run the same capability scenarios against the authority's static
# libcrypto.a and the candidate's static archive, and against the candidate's Rust
# dispatchers. Every command runs inside the court container (see RECEIPT.md).
set -euo pipefail
cd /work

export CARGO_BUILD_JOBS=1
export CARGO_PROFILE_TEST_DEBUG=0

OUT=evidence/performance-frontier/campaigns/PFP-67/raw
AUTH=forensics/authorities/prefix/openssl-3.6.4-production
SRC=evidence/performance-frontier/campaigns/PFP-67/probe.c
WORK=court/pfp67
mkdir -p "$OUT" "$WORK"

echo "=== build the candidate archive (debug; behaviour, not performance) ==="
cargo build --lib

echo "=== compile the authority probe (static libcrypto.a) ==="
clang -std=c11 -O1 -Wall -Wno-deprecated-declarations -D_GNU_SOURCE \
  -I "$AUTH/include" -o "$WORK/probe.authority" "$SRC" \
  "$AUTH/lib/libcrypto.a" \
  -Wl,-u,OPENSSL_ia32cap_P -Wl,-u,OPENSSL_cpuid_setup \
  -ldl -lpthread -lm

echo "=== compile the candidate probe (static archive) ==="
clang -std=c11 -O1 -Wall -Wno-deprecated-declarations -D_GNU_SOURCE \
  -I artifacts/phase2/include -o "$WORK/probe.candidate" "$SRC" \
  target/debug/libopenssl_rs.a -ldl -lpthread -lm

scenarios=(
  "default|"
  "aes_off|~0x200000000000000:::::"
  "pclmul_off|~0x200000000:::::"
  "sha_off|:~0x20000000"
  "fxsr_off|~0x1000000:::::"
  "value_set|0x0:0x0"
)

for row in "${scenarios[@]}"; do
  name="${row%%|*}"
  value="${row#*|}"
  echo "=== scenario $name (OPENSSL_ia32cap=${value:-<unset>}) ==="
  if [ -z "$value" ]; then
    env -u OPENSSL_ia32cap "$WORK/probe.authority" >"$OUT/authority_$name.txt"
    env -u OPENSSL_ia32cap "$WORK/probe.candidate" >"$OUT/candidate_$name.txt"
    env -u OPENSSL_ia32cap PFP67_CHILD=1 OPENSSL_RS_PFP67_CHILD=1 \
      cargo test --lib -- --exact runtime::cpu::tests::pfp67_child_performs_the_calls --nocapture \
      | grep -E '^(caps |caller=|sel )' >"$OUT/candidate_paths_$name.txt"
  else
    OPENSSL_ia32cap="$value" "$WORK/probe.authority" >"$OUT/authority_$name.txt"
    OPENSSL_ia32cap="$value" "$WORK/probe.candidate" >"$OUT/candidate_$name.txt"
    OPENSSL_ia32cap="$value" OPENSSL_RS_PFP67_CHILD=1 \
      cargo test --lib -- --exact runtime::cpu::tests::pfp67_child_performs_the_calls --nocapture \
      | grep -E '^(caps |caller=|sel )' >"$OUT/candidate_paths_$name.txt"
  fi
done

echo "=== output-byte comparison (authority vs candidate) ==="
status=0
for row in "${scenarios[@]}"; do
  name="${row%%|*}"
  if diff -u \
      <(grep '^out\.' "$OUT/authority_$name.txt") \
      <(grep '^out\.' "$OUT/candidate_$name.txt"); then
    echo "outputs agree: $name"
  else
    echo "OUTPUT MISMATCH: $name"
    status=1
  fi
done
exit "$status"
