#!/bin/sh
# build_dsos.sh — PFP-3 mutation control: build the admission-switched DSO.
#
# A is the candidate at 04611380 (rebuilt from clean 289f11187).
# B is built here from a COPY of the crate source; the repository's src/ is not
# modified.  The single difference is the admission switch: `admits` returns
# `false` unconditionally (the one-line `true` -> `false` at the end of the
# predicate), so `try_fixed_base_mul` returns None and the unchanged ladder
# runs.  Nothing else changes.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g CARGO_BUILD_JOBS=4 \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-3/mutation/build_dsos.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-3/mutation
MUT=/work/court/tmp/pfp3-mut/srcroot
OUT=/work/court/tmp/pfp3-mut
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$EV/raw" "$OUT"

fp_repo() { ( cd /work && find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum ); }
fp_repo >"$OUT/repo-src-before.sha256"

rm -rf "$MUT"
mkdir -p "$MUT"
cp -a Cargo.toml Cargo.lock build.rs rust-toolchain.toml "$MUT"/
cp -a src "$MUT"/src
# build.rs reads the constitution docs and the authority registry; symlink them
# read-only so the copied tree is complete without duplicating the repository.
ln -s /work/docs "$MUT"/docs
ln -s /work/forensics "$MUT"/forensics

python3 - "$MUT/src/ec/p256/fixed_base.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = """        if (*generator.x).d.as_slice() != tracked_gx().as_slice()
            || (*generator.y).d.as_slice() != tracked_gy().as_slice()
        {
            return false;
        }
        true"""
new = old[:-5] + "false"
if s.count(old) != 1:
    raise SystemExit("admission switch anchor not unique")
open(p, "w").write(s.replace(old, new))
PY
diff -u src/ec/p256/fixed_base.rs "$MUT/src/ec/p256/fixed_base.rs" \
    >"$EV/raw/admission-switch.diff" || true

echo "=== B: cargo build (admission switched off) ==="
( cd "$MUT" && CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$OUT/target" \
    cargo build --release --lib --offline )
ARCHIVE="$OUT/target/release/libopenssl_rs.a"
mkdir -p "$OUT/shell" "$OUT/distribution"
rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/shell/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$OUT/distribution/libcrypto.so.3" \
    -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
    "$OUT/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

DSO="$OUT/distribution/libcrypto.so.3"
B_SHA="$(sha256sum "$DSO" | awk '{print $1}')"
A_SHA="$(sha256sum /work/court/tmp/pfp3-ctgrind/a/libcrypto.so.3 | awk '{print $1}')"
[ "$A_SHA" = "04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4" ] \
    || { echo "FATAL: candidate A digest $A_SHA" >&2; exit 1; }
[ "$B_SHA" != "$A_SHA" ] || { echo "FATAL: mutation B has the candidate digest" >&2; exit 1; }

fp_repo >"$OUT/repo-src-after.sha256"
cmp -s "$OUT/repo-src-before.sha256" "$OUT/repo-src-after.sha256" \
    || { echo "FATAL: repository src changed" >&2; exit 90; }

{
    echo "candidate_a_sha256=$A_SHA"
    echo "mutation_b_sha256=$B_SHA"
    echo "mutation_b_path=$DSO"
    echo "mutation_b_size=$(stat -c %s "$DSO")"
    echo "mutation_b_build_id=$(readelf -n "$DSO" | sed -n 's/^ *Build ID: //p')"
    echo "mutation_archive_sha256=$(sha256sum "$ARCHIVE" | awk '{print $1}')"
    echo "switch=src/ec/p256/fixed_base.rs admits final true -> false (B only)"
    echo "repository_src_fingerprint_before=$(sha256sum "$OUT/repo-src-before.sha256" | awk '{print $1}')"
    echo "repository_src_fingerprint_after=$(sha256sum "$OUT/repo-src-after.sha256" | awk '{print $1}')"
    echo "rustc=$(rustc --version)"
} | tee "$EV/raw/dso-digests.txt"

sha256sum "$DSO"
echo "build: done"
