#!/bin/sh
# build.sh — PFP-54 / PFP-55: one release compilation, shipped DSO + detached DWARF.
#
# Route: objcopy --only-keep-debug + --add-gnu-debuglink (not split-debuginfo).
# Why: the product is a *hand-linked* DSO built from the crate's staticlib
# archive, not a rustc-linked dylib. `-C split-debuginfo` describes how rustc
# emits debug info for a linked binary/dylib; it does not produce a detached
# DWARF companion for the `cc -shared` link we ship. objcopy operates on the
# exact linked DSO, so the retained DWARF and the shipped bytes come from one
# link, and `--add-gnu-debuglink` leaves the standard CRC fallback binding.
#
# The only build-flag change is CARGO_PROFILE_RELEASE_DEBUG=1: without it the
# crate emits no crate DWARF at all (PFP-54 finding), so there is no
# DW_TAG_inlined_subroutine to resolve. Level 1 is line-tables + scope info
# (function names, line structure, inlined-subroutine DIEs); it does not add
# local variable names. The product codegen is unchanged.
#
#   free -g must show available>=24 and swap free>=16 first (brief).
#   OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g CARGO_BUILD_JOBS=2 \
#     CARGO_PROFILE_TEST_DEBUG=0 \
#     bash docker/openssl-rs-court.sh exec \
#       sh evidence/performance-frontier/campaigns/PFP-54/build.sh
set -eu

# Run a command with its output captured, propagating its status.  Piping the
# build through `tail` made the pipeline status that of `tail`, so a failed
# cargo build could be concealed (PFP-86).  Under `set -e` a failure here exits
# the script.
run_checked() {
    _log=$1; shift
    if ! "$@" >"$_log" 2>&1; then
        echo "FATAL: command failed: $*" >&2
        tail -n 3 "$_log" >&2 || true
        return 1
    fi
    tail -n 3 "$_log" || true
}

# Mutation control for PFP-86(3): a failing command must fail the script.  It
# runs before the court requirement so it is exercisable on a clean checkout.
if [ "${1:-}" = "--self-test-failing-build" ]; then
    _control_log=$(mktemp)
    if run_checked "$_control_log" sh -c 'echo "fake cargo output"; exit 7'; then
        echo "FATAL: control did not see the failing command" >&2
        rm -f "$_control_log"
        exit 1
    fi
    rm -f "$_control_log"
    echo "control ok: a failing build command fails the script"
    exit 0
fi

cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-54
OUT="$EV/raw"
ART="$OUT/artefacts"
BASE=/work/court/tmp/pfp54
T="$BASE/target"
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
mkdir -p "$OUT" "$ART" "$BASE/shell"

for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

sha() { sha256sum "$1" | awk '{print $1}'; }
textsha() { tmp="$BASE/text.$$.bin"; objcopy --dump-section .text="$tmp" "$1" >/dev/null 2>&1 || { rm -f "$tmp"; echo ERR; return; }; sha "$tmp"; rm -f "$tmp"; }

{
    echo "date=$(date -u +%FT%TZ)"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "source_tree=$(git -C /work rev-parse 'HEAD^{tree}')"
    echo "src_tree=$(git -C /work rev-parse HEAD:src)"
    echo "dirty_build_relevant=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs artifacts/phase2/shell artifacts/phase2/libcrypto.ld | tr '\n' ';')"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "cc=$(cc --version | head -1)"
    echo "ld=$(ld --version | head -1)"
    echo "objcopy=$(objcopy --version | head -1)"
    echo "target_triple=$(rustc -vV | sed -n 's/^host: //p')"
    echo "profile=release"
    echo "cargo_profile_release_debug=1"
    echo "cargo_profile_test_debug=0"
    echo "cargo_build_jobs=2"
    echo "rustflags="
    echo "shell_rs_sha256=$(sha "$SHELL_RS")"
    echo "version_script_sha256=$(sha "$VERSION_SCRIPT")"
} >"$OUT/build-inputs.txt"

echo "=== cargo build --release --lib --offline (debug=1) ==="
run_checked "$BASE/cargo-build.log" \
    env CARGO_BUILD_JOBS=2 CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_PROFILE_TEST_DEBUG=0 \
        CARGO_TARGET_DIR="$T" cargo build --release --lib --offline

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$BASE/shell/libcrypto.shell.o" "$SHELL_RS"

LINKED="$BASE/libcrypto.so.3.linked"
cc -shared -o "$LINKED" \
    -Wl,--whole-archive "$T/release/libopenssl_rs.a" -Wl,--no-whole-archive \
    "$BASE/shell/libcrypto.shell.o" \
    -Wl,--build-id=sha1 \
    -Wl,--version-script="$VERSION_SCRIPT" -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

SHIP="$BASE/libcrypto.so.3"
DBG="$BASE/libcrypto.so.3.debug"
# 1. Detach the DWARF from the exact linked artefact.
objcopy --only-keep-debug "$LINKED" "$DBG"
# 2. Ship a debug-stripped DSO (keeps .symtab the auditor needs; removes .debug_*).
objcopy --strip-debug "$LINKED" "$SHIP"
# 3. Standard build-id/debuglink binding for the stripped file.
objcopy --add-gnu-debuglink="$DBG" "$SHIP"

TEXTLINKED=$(textsha "$LINKED")
TEXTSHIP=$(textsha "$SHIP")
{
    echo "archive_path=$T/release/libopenssl_rs.a"
    echo "archive_sha256=$(sha "$T/release/libopenssl_rs.a")"
    echo "linked_path=$LINKED"
    echo "linked_sha256=$(sha "$LINKED")"
    echo "linked_size=$(stat -c %s "$LINKED")"
    echo "shipped_path=$SHIP"
    echo "shipped_sha256=$(sha "$SHIP")"
    echo "shipped_size=$(stat -c %s "$SHIP")"
    echo "debug_path=$DBG"
    echo "debug_sha256=$(sha "$DBG")"
    echo "debug_size=$(stat -c %s "$DBG")"
    echo "text_sha256_linked=$TEXTLINKED"
    echo "text_sha256_shipped=$TEXTSHIP"
    echo "shipped_build_id=$(readelf -n "$SHIP" | sed -n 's/.*Build ID: //p')"
    echo "debug_build_id=$(readelf -n "$DBG" | sed -n 's/.*Build ID: //p')"
    echo "shipped_gnu_debuglink=$(readelf -x .gnu_debuglink "$SHIP" 2>/dev/null | tr -d '\n' | sed 's/.*0x[0-9a-f]*//')"
    echo "shipped_debug_sections=$(readelf -S --wide "$SHIP" | grep -c '\.debug_')"
    echo "debug_debug_sections=$(readelf -S --wide "$DBG" | grep -c '\.debug_')"
} >>"$OUT/build-inputs.txt"

# Retain both as evidence (the shipped DSO is the audited subject; the debug
# file is the detached DWARF the auditor maps through). Neither is a crate
# package input: Cargo.toml excludes evidence/**.
cp -f "$SHIP" "$ART/libcrypto.so.3"
cp -f "$DBG"  "$ART/libcrypto.so.3.debug"

echo "=== shipped_sha256=$(sha "$SHIP") ==="
echo "=== debug_sha256=$(sha "$DBG") ==="
echo "=== shipped_build_id=$(readelf -n "$SHIP" | sed -n 's/.*Build ID: //p') ==="
echo "=== debug_build_id=$(readelf -n "$DBG" | sed -n 's/.*Build ID: //p') ==="
echo "=== text_sha256_shipped=$TEXTSHIP ==="
