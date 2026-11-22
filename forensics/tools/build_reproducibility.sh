#!/usr/bin/env bash
# openssl-rs — prove the release library is a function of its inputs.
#
# Two *independent* release builds are made from the same committed source
# (`HEAD`) with every environment difference that must not matter varied:
#
#     build A: <out>/build-a            LC_ALL=C.UTF-8  TMPDIR=<out>/tmp-a  HOME=<out>/home-a  HOSTNAME=repro-a
#     build B: <out>/build-b/nested     LC_ALL=C        TMPDIR=<out>/tmp-b  HOME=<out>/home-b  HOSTNAME=repro-b
#
# The distinct build roots give distinct `CARGO_TARGET_DIR`s (`<root>/target`).
# Both builds pin SOURCE_DATE_EPOCH, remap the (different) absolute source and
# target roots to the same `/build/src` and `/build/target` prefixes, compile the
# C adapters with `-ffile-prefix-map`, and archive with `ar` in deterministic
# mode. The static archive and the linked DSO are then compared byte-for-byte.
# No byte is normalised or stripped to manufacture equality: the claim is that
# two separately produced files are identical.
#
# Usage (inside the forensic court):
#
#     bash docker/openssl-rs-court.sh exec bash forensics/tools/build_reproducibility.sh
#     bash docker/openssl-rs-court.sh exec bash forensics/tools/build_reproducibility.sh \
#         --out /court/repro --build-id none
#
# Options:
#   --out DIR        output root (default /court/repro)
#   --build-id MODE  `auto` (default: the linker derives it from the loadable
#                    segments) or `none` (`-Wl,--build-id=none`). `auto` is the
#                    production shape and is reproducible when the loadable
#                    segments are; `none` isolates the build-id as a variable.
#   --keep           keep both build trees after comparison (default: keep them;
#                    pass --clean to remove, for CI disk economy)
#   --clean          remove both build trees before exiting
#   --distribution   also link the distribution DSO twice from the Phase-2 shell
#                    source regenerated from its tracked generator and tracked
#                    inputs (the artefact D255 is about) and compare it, closing
#                    the `.symtab` question as well.
#   --self-test      exercise only the archive/comparison machinery on a tiny
#                    fixture: two archives built from the same object must be
#                    byte-identical, and an archive built from a different object
#                    must be detected as different. It does not build the crate
#                    and makes no reproducibility claim about it; the qualification
#                    control uses it to show that the comparison can fail.
#
# Exit status: 0 iff both the `.a` and the `.so` are byte-identical (or, with
# --self-test, if the comparison behaves correctly in both directions); 1
# otherwise. 97 when run outside the court. Nothing here executes on the host.
set -euo pipefail

. "$(dirname "$0")/require_court.sh"

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=/court/repro
BUILD_ID=auto
KEEP=1
DISTRIBUTION=0
SELFTEST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT=$2; shift 2 ;;
    --build-id) BUILD_ID=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --clean) KEEP=0; shift ;;
    --distribution) DISTRIBUTION=1; shift ;;
    --self-test) SELFTEST=1; shift ;;
    *) echo "build_reproducibility: unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$BUILD_ID" in auto|none) ;; *) echo "--build-id must be auto or none" >&2; exit 2 ;; esac

if [ "$SELFTEST" = 1 ]; then
  d=$(mktemp -d)
  trap 'rm -rf "$d"' EXIT
  printf '.text\n.globl F\nF:\n ret\n' >"$d/a.S"
  printf '.text\n.globl F\nF:\n xorl %%eax,%%eax\n ret\n' >"$d/b.S"
  cc -c -o "$d/a.o" "$d/a.S"
  cc -c -o "$d/b.o" "$d/b.S"
  mkdir -p "$d/x" "$d/y" "$d/z"
  cp "$d/a.o" "$d/x/a.o"; cp "$d/a.o" "$d/y/a.o"; cp "$d/b.o" "$d/z/a.o"
  ( cd "$d/x" && ar rcsD ../one.a a.o )
  ( cd "$d/y" && ar rcsD ../one2.a a.o )
  ( cd "$d/z" && ar rcsD ../two.a a.o )
  status=0
  if cmp -s "$d/one.a" "$d/one2.a"; then
    echo "SELFTEST identical-archives OK"
  else
    echo "SELFTEST identical-archives FAILED" >&2; status=1
  fi
  if cmp -s "$d/one.a" "$d/two.a"; then
    echo "SELFTEST differing-archives NOT detected" >&2; status=1
  else
    echo "SELFTEST differing-archives detected"
  fi
  exit "$status"
fi

SDE=${SOURCE_DATE_EPOCH:-1609459200}
JOBS=${CARGO_BUILD_JOBS:-4}
# One heavy command at a time, bounded parallelism (AGENTS.md §6.1).
[ "$JOBS" -le 4 ] || JOBS=4
TARGET_NAME=libcrypto.so.3

# Exactly the build-relevant tracked inputs: the crate, its build script and the
# constitution documents + registry it reads. `forensics/atlas` and `artifacts`
# are not inputs to the release library.
SRC_PATHS=(Cargo.toml Cargo.lock build.rs rust-toolchain.toml README.md src docs
           forensics/authorities/AUTHORITIES.json
           forensics/multitrack/default-authority.json
           forensics/multitrack/abi-facades.json)

rm -rf "$OUT"
mkdir -p "$OUT/build-a" "$OUT/build-b/nested" "$OUT/tmp-a" "$OUT/tmp-b" \
         "$OUT/home-a" "$OUT/home-b" "$OUT/artefacts"

# Two extractions from the committed tree, at deliberately different depths.
git -C "$REPO_ROOT" archive HEAD -- "${SRC_PATHS[@]}" | tar -x -C "$OUT/build-a"
git -C "$REPO_ROOT" archive HEAD -- "${SRC_PATHS[@]}" | tar -x -C "$OUT/build-b/nested"

make_cc_wrapper() { # root out
  cat >"$2" <<EOF
#!/bin/sh
# Hermetic C adapter compile: map the build root out of every embedded path.
exec cc -ffile-prefix-map=$1=/build/src "\$@"
EOF
  chmod +x "$2"
}
make_ar_wrapper() { # out
  cat >"$1" <<'EOF'
#!/bin/sh
# Deterministic archive mode: zero timestamps, uid/gid and stable member order.
op=$1; shift
exec ar "${op}D" "$@"
EOF
  chmod +x "$1"
}
make_cc_wrapper "$OUT/build-a" "$OUT/cc-a.sh"
make_cc_wrapper "$OUT/build-b/nested" "$OUT/cc-b.sh"
make_ar_wrapper "$OUT/ar.sh"

build() { # root tag locale tmpdir hostname ccwrap home
  local root=$1 tag=$2 locale=$3 tmp=$4 hostn=$5 ccwrap=$6 home=$7
  (
    cd "$root"
    env -i \
      PATH="${PATH:-/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}" \
      HOME="$home" \
      CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}" \
      RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}" \
      SOURCE_DATE_EPOCH="$SDE" \
      CARGO_BUILD_JOBS="$JOBS" \
      RUSTFLAGS="--remap-path-prefix=$root=/build/src --remap-path-prefix=$root/target=/build/target" \
      CC="$ccwrap" AR="$OUT/ar.sh" \
      LC_ALL="$locale" LANG="$locale" TMPDIR="$tmp" HOSTNAME="$hostn" \
      cargo build --release --lib --offline
  ) >"$OUT/$tag.build.log" 2>&1

  local idflag=()
  [ "$BUILD_ID" = none ] && idflag=(-Wl,--build-id=none)
  cc -shared -o "$OUT/artefacts/$tag.$TARGET_NAME" \
    -Wl,--whole-archive "$root/target/release/libopenssl_rs.a" -Wl,--no-whole-archive \
    -Wl,-soname,"$TARGET_NAME" "${idflag[@]}"
  cp "$root/target/release/libopenssl_rs.a" "$OUT/artefacts/$tag.a"
}

echo "=== release reproducibility: SOURCE_DATE_EPOCH=$SDE build-id=$BUILD_ID jobs=$JOBS"
echo "MemAvailable: $(awk '/MemAvailable/{print $2 " kB"}' /proc/meminfo)"
build "$OUT/build-a"       a C.UTF-8 "$OUT/tmp-a" repro-a "$OUT/cc-a.sh" "$OUT/home-a"
build "$OUT/build-b/nested" b C      "$OUT/tmp-b" repro-b "$OUT/cc-b.sh" "$OUT/home-b"

report_diff() { # label pathA pathB
  local label=$1 A=$2 B=$3
  local off
  off=$(cmp -l "$A" "$B" 2>/dev/null | sed -n '1p' | awk '{print $1-1}')
  echo "  $label DIFFERS (first byte offset $off / 0x$(printf '%x' "${off:-0}"))"
  if [ -n "${off:-}" ]; then
    # Map the offset to an ELF section using the section-header file offsets.
    readelf -SW "$A" | python3 -c '
import sys
off = int(sys.argv[1])
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("[") or "]" not in line:
        continue
    f = line.split("]", 1)[1].split()
    if len(f) < 5 or f[1] == "NOBITS":
        continue
    try:
        lo, size = int(f[3], 16), int(f[4], 16)
    except ValueError:
        continue
    if lo <= off < lo + size:
        print("    section: " + f[0])
' "$off" || true
  fi
  sha256sum "$A" "$B" || true
}

ok=0
for pair in "libopenssl_rs.a:a.a:b.a" "libcrypto.so.3:a.$TARGET_NAME:b.$TARGET_NAME"; do
  label=${pair%%:*}; rest=${pair#*:}; A=${rest%%:*}; B=${rest#*:}
  if cmp -s "$OUT/artefacts/$A" "$OUT/artefacts/$B"; then
    echo "IDENTICAL  $label  $(sha256sum "$OUT/artefacts/$A" | cut -d' ' -f1)"
  else
    ok=1
    report_diff "$label" "$OUT/artefacts/$A" "$OUT/artefacts/$B"
  fi
done

# --- the distribution DSO (D255's artefact) --------------------------------
# `build_phase2.sh` compiles the committed Phase-2 shell to an object with a
# direct `rustc` invocation and links it, whole-archive, against the crate
# archive. That shell object is where LLVM-internalised local names
# (`anon.<hash>.<n>.llvm.<hash>`) enter `.symtab`; D255 recorded a `.symtab`
# difference with identical `.text`/`.dynsym`/build-id there. Two independent
# compiles + links are made here from the same shell regenerated from tracked
# inputs. The shell directory is gitignored, so copying it would leave this arm
# unable to run from a clean checkout; `phase2_shell.py --emit-shell` derives it
# from `forensics/atlas/implemented-surface.json` and the authority symbol atlas.
if [ "$DISTRIBUTION" = 1 ]; then
  for tag in a b; do
    dir=$OUT/dist-$tag
    [ "$tag" = b ] && dir=$OUT/dist-b/nested
    mkdir -p "$dir"
    cp "$REPO_ROOT/artifacts/phase2/libcrypto.ld" "$dir/"
    python3 "$REPO_ROOT/forensics/tools/phase2_shell.py" --emit-shell "$dir" \
      >"$OUT/dist-$tag.shell.log" 2>&1
    ( cd "$dir" && rustc --edition 2021 --emit=obj --crate-type lib -O \
        --remap-path-prefix="$dir"=/build/src \
        --crate-name libcrypto_shell -o libcrypto.shell.o libcrypto.shell.rs ) \
        >"$OUT/dist-$tag.rustc.log" 2>&1
    idflag=(); [ "$BUILD_ID" = none ] && idflag=(-Wl,--build-id=none)
    cc -shared -o "$OUT/artefacts/$tag-distribution.$TARGET_NAME" \
      -Wl,--whole-archive "$OUT/artefacts/$tag.a" -Wl,--no-whole-archive \
      "$dir/libcrypto.shell.o" \
      -Wl,--version-script="$dir/libcrypto.ld" -Wl,-soname,"$TARGET_NAME" \
      "${idflag[@]}" -lpthread -ldl -lm -lrt -lutil
  done
  A=distribution.$TARGET_NAME
  if cmp -s "$OUT/artefacts/a-distribution.$TARGET_NAME" "$OUT/artefacts/b-distribution.$TARGET_NAME"; then
    echo "IDENTICAL  $A  $(sha256sum "$OUT/artefacts/a-distribution.$TARGET_NAME" | cut -d' ' -f1)"
  else
    ok=1
    report_diff "$A" "$OUT/artefacts/a-distribution.$TARGET_NAME" \
      "$OUT/artefacts/b-distribution.$TARGET_NAME"
  fi
fi

# Preserve the measured binaries as content-addressed artefacts.
( cd "$OUT/artefacts"
  for f in a.a b.a a.$TARGET_NAME b.$TARGET_NAME \
           a-distribution.$TARGET_NAME b-distribution.$TARGET_NAME; do
    [ -f "$f" ] || continue
    d=$(sha256sum "$f" | cut -d' ' -f1)
    cp "$f" "$d-${f#*.}"
  done
  sha256sum *.a *."$TARGET_NAME" > SHA256SUMS 2>/dev/null || true
  true )

if [ "$BUILD_ID" = auto ]; then
  echo "--- build-id: $(readelf -n "$OUT/artefacts/a.$TARGET_NAME" | sed -n 's/.*Build ID: //p')"
fi

if [ "$KEEP" = 0 ]; then rm -rf "$OUT/build-a" "$OUT/build-b" "$OUT/dist-a" "$OUT/dist-b"; fi

if [ "$ok" = 0 ]; then
  msg="REPRODUCIBLE: the release archive and the linked DSO are byte-identical."
  [ "$DISTRIBUTION" = 1 ] && msg="$msg The distribution DSO is too."
  echo "$msg"
  exit 0
fi
echo "NOT REPRODUCIBLE: see the differing sections above." >&2
exit 1
