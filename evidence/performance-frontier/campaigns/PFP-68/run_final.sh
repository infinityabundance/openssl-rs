#!/bin/sh
# PFP-68/62 final measurement and differential for the AES-GCM conversion.
set -eu
cd /work
OUT=evidence/performance-frontier/campaigns/PFP-68/raw
OUT62=evidence/performance-frontier/campaigns/PFP-62/raw
mkdir -p "$OUT" "$OUT62" court/tmp/pfp68/final
export CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0

echo "=== build ==="
cargo build --release --lib --offline 2>&1 | tail -n 2
cc -shared -o court/tmp/pfp68/final/libcrypto.so.3 \
  -Wl,--whole-archive target/release/libopenssl_rs.a -Wl,--no-whole-archive \
  court/tmp/pfp68/shell/libcrypto.shell.o \
  -Wl,--version-script=artifacts/phase2/libcrypto.ld \
  -Wl,-soname,libcrypto.so.3 -lpthread -ldl -lm -lrt -lutil
B=court/tmp/pfp68/bench
A=forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
C=court/tmp/pfp68/final/libcrypto.so.3
{
  echo "source_commit=$(git rev-parse HEAD)"
  echo "candidate_dso=$(sha256sum "$C" | awk '{print $1}')"
  echo "authority_dso=$(sha256sum "$A" | awk '{print $1}')"
  echo "bench_binary=$(sha256sum "$B" | awk '{print $1}')"
  echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
} | tee "$OUT/identity.txt"

echo "=== paired timing (cand/auth, >1 = slower) ==="
: > "$OUT/timing-final.txt"
for op in aes128gcm-64 aes128gcm-16k aes256gcm-64 aes256gcm-16k; do
  rep=1
  while [ "$rep" -le 3 ]; do
    if [ $((rep % 2)) -eq 1 ]; then order="auth cand"; else order="cand auth"; fi
    for tag in $order; do
      if [ "$tag" = cand ]; then d=$C; else d=$A; fi
      r=$(taskset -c 1 "$B" --lib "$d" --op "$op" --runs 9)
      echo "$op rep=$rep $tag $r" >> "$OUT/timing-final.txt"
    done
    rep=$((rep + 1))
  done
done
python3 - "$OUT/timing-final.txt" <<'PY' | tee "$OUT/timing-summary.txt"
import sys, re, statistics
rows={}
for ln in open(sys.argv[1]):
    m=re.search(r'(\S+) rep=\d+ (auth|cand) RESULT \S+ bytes=\d+ median_us=([0-9.]+)', ln)
    if m:
        rows.setdefault(m.group(1),{}).setdefault(m.group(2),[]).append(float(m.group(3)))
print("op                 auth_us   cand_us   ratio")
for op in ["aes128gcm-64","aes128gcm-16k","aes256gcm-64","aes256gcm-16k"]:
    a=statistics.median(rows[op]["auth"]); c=statistics.median(rows[op]["cand"])
    print(f"{op:18s} {a:9.4f} {c:9.4f} {c/a:7.3f}")
PY

echo "=== aggregation width table (final) ==="
: > "$OUT62/width-table.txt"
for op in aes128gcm-64 aes128gcm-16k; do
  for w in 2 3 4 5 6 7 8; do
    r=$(OPENSSL_RS_GCM_WIDTH=$w taskset -c 1 "$B" --lib "$C" --op "$op" --runs 9)
    echo "width=$w $op $r" >> "$OUT62/width-table.txt"
  done
done
cp "$OUT62/width-table.txt" "$OUT/width-table.txt"

echo "=== VAES contribution (clear VAES LV1 bit 41) ==="
: > "$OUT/vaes-contribution.txt"
for op in aes128gcm-64 aes128gcm-16k; do
  echo "vaes_on  $op $(taskset -c 1 "$B" --lib "$C" --op "$op" --runs 9)" >> "$OUT/vaes-contribution.txt"
  echo "vaes_off $op $(OPENSSL_ia32cap=':~0x20000000000' taskset -c 1 "$B" --lib "$C" --op "$op" --runs 9)" >> "$OUT/vaes-contribution.txt"
done
cat "$OUT/vaes-contribution.txt"

echo "=== differential vs authority across capability arms ==="
status=0
: > "$OUT/diff-summary.txt"
for arm in default aes_off pclmul_off both_off value_set; do
  case $arm in
    default) cap=""; ;;
    aes_off) cap="~0x2000000"; ;;
    pclmul_off) cap="~0x2"; ;;
    both_off) cap="~0x2000002"; ;;
    value_set) cap="0x0:0x0"; ;;
  esac
  D="$OUT/diff-$arm"; mkdir -p "$D"
  for op in aes128gcm-64 aes128gcm-16k aes256gcm-16k; do
    if [ -z "$cap" ]; then
      "$B" --lib "$A" --once --op "$op" > "$D/auth-$op.out"
      "$B" --lib "$C" --once --op "$op" > "$D/cand-$op.out"
    else
      OPENSSL_ia32cap="$cap" "$B" --lib "$A" --once --op "$op" > "$D/auth-$op.out"
      OPENSSL_ia32cap="$cap" "$B" --lib "$C" --once --op "$op" > "$D/cand-$op.out"
    fi
    if cmp -s "$D/auth-$op.out" "$D/cand-$op.out"; then
      echo "arm=$arm op=$op once=IDENTICAL" >> "$OUT/diff-summary.txt"
    else
      echo "arm=$arm op=$op once=MISMATCH" >> "$OUT/diff-summary.txt"; status=1
    fi
  done
  if [ -z "$cap" ]; then
    "$B" --lib "$A" --kat > "$D/auth-kat.out"
    "$B" --lib "$C" --kat > "$D/cand-kat.out"
  else
    OPENSSL_ia32cap="$cap" "$B" --lib "$A" --kat > "$D/auth-kat.out"
    OPENSSL_ia32cap="$cap" "$B" --lib "$C" --kat > "$D/cand-kat.out"
  fi
  if cmp -s "$D/auth-kat.out" "$D/cand-kat.out"; then
    echo "arm=$arm kat=IDENTICAL" >> "$OUT/diff-summary.txt"
  else
    echo "arm=$arm kat=MISMATCH" >> "$OUT/diff-summary.txt"; status=1
  fi
done
cat "$OUT/diff-summary.txt"
echo "DIFF_STATUS=$status"
exit "$status"
