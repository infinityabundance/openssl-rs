#!/bin/sh
# PFP-56 candidate DSO identity. Builds the frozen working tree once with the
# PFP-8 link recipe (staticlib + phase2 shell + version script).
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-56/build_dso.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp56
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-1}"
[ "$JOBS" -le 4 ] || JOBS=4
mkdir -p "$OUT"
rm -rf "$OUT/target" "$OUT/libcrypto.shell.o" "$OUT/libcrypto.so.3"

for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

CARGO_BUILD_JOBS="$JOBS" CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR="$OUT/target" \
    cargo build --release --lib --offline 2>&1 | tail -n 3

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/libcrypto.shell.o" \
    "$SHELL_RS"
cc -shared -o "$OUT/libcrypto.so.3" \
    -Wl,--whole-archive "$OUT/target/release/libopenssl_rs.a" \
    -Wl,--no-whole-archive \
    "$OUT/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

printf 'candidate_archive_sha256=%s\n' "$(sha256sum "$OUT/target/release/libopenssl_rs.a" | awk '{print $1}')"
printf 'candidate_dso_sha256=%s\n' "$(sha256sum "$OUT/libcrypto.so.3" | awk '{print $1}')"
printf 'candidate_dso_size=%s\n' "$(stat -c %s "$OUT/libcrypto.so.3")"
printf 'candidate_build_id=%s\n' "$(readelf -n "$OUT/libcrypto.so.3" | sed -n 's/.*Build ID: //p')"
printf 'source_commit=%s\n' "$(git -C /work rev-parse HEAD)"
printf 'src_fingerprint=%s\n' "$(find /work/src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
