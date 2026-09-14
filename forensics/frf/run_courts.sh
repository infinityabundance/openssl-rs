#!/usr/bin/env bash
# openssl-rs — run every FRF court and emit the whole evidence chain.
#
# Runs inside the FRF tooling container (docker/openssl-rs-frf-court.sh), never
# on the host: the courts execute the authority binaries, and no authority binary
# is ever executed on the host.
#
#     bash docker/openssl-rs-frf-court.sh exec bash forensics/frf/run_courts.sh
#
# This script performs the mechanical half of the FRF loop:
#
#   authority admit -> court run -> challenge -> receipt emit -> claim compile
#
# The judgement half is deliberately explicit rather than automated. FRF refuses
# `open` as a settable disposition and refuses to compile a claim while any
# residual is open, unknown or harness, so a disposition has to be stated with a
# reason. The one disposition this script performs is the oracle-version
# trajectory for the release banner, which is the call already recorded in
# `docs/SECURITY_DIVERGENCE_POLICY.md` §1 and D1. Everything else is left to a
# human, and the command lines are in `forensics/frf/README.md`.
#
# Why the store is recreated
# --------------------------
# Authority admission and run identities are content-addressed. Re-running over an
# existing store would reuse captures rather than take a fresh observation, and
# FRF's run identity does **not** vary with the hashes of the `execution_context`
# artifacts — measured: rebuilding the candidate library did not change any
# runtime court's run id, so the stored captures still recorded the previous
# library's hash. Re-creating the store from clean is therefore the only way to
# observe a rebuilt candidate, and it is what a release does.
set -euo pipefail

# Nothing runs on the host (docs/REPRODUCIBILITY.md §1). Enforced, not assumed.
. "$(dirname "$0")/../tools/require_court.sh"

cd /work
ROOT="${FRF_ROOT:-.frf}"

# Phase 1 trajectory courts: oracle-versus-oracle, 3.6.3 against 3.6.4.
TRAJECTORY_COURTS="openssl-cli-version openssl-cli-dgst openssl-cli-inventory"
# Phase 2 ABI court: both sides report what their own libcrypto binds.
#
# The runtime courts below span two strata, and each court's own manifest declares
# which staging directory its probes live in (the second `fixture.arguments`
# entry), so this runner does not need to know which phase a court belongs to.
ABI_COURTS="openssl-abi-surface"
# Phase 3 and Phase 4 runtime courts: the authority against openssl-rs itself.
RUNTIME_COURTS="openssl-rs-rt-mem openssl-rs-rt-exdata openssl-rs-rt-err \
openssl-rs-rt-stack openssl-rs-rt-thread openssl-rs-rt-secure openssl-rs-rt-lhash \
openssl-rs-rt-bio openssl-rs-rt-err-bio openssl-rs-rt-bio-addr \
openssl-rs-rt-bio-resolve openssl-rs-rt-bio-sock openssl-rs-rt-bio-comp \
openssl-rs-rt-bio-debug openssl-rs-rt-bio-print openssl-rs-rt-bio-file \
openssl-rs-rt-bio-filter openssl-rs-rt-bio-pair openssl-rs-rt-bio-dgram-pair \
openssl-rs-rt-bio-dgram openssl-rs-rt-bio-conn openssl-rs-rt-obj-stream \
openssl-rs-rt-conf openssl-rs-rt-bn"
ALL_COURTS="$TRAJECTORY_COURTS $ABI_COURTS $RUNTIME_COURTS"

RUNS=/tmp/openssl-rs-frf-runs.txt
RECEIPTS=/tmp/openssl-rs-frf-receipts.txt
: > "$RUNS"
: > "$RECEIPTS"

echo "=== [1/5] admit authorities ==="
rm -rf "$ROOT"
admit() { frf --root "$ROOT" authority admit "$@"; }
admit forensics/frf/refs/openssl-3.6.3.sh --name openssl --version 3.6.3
admit forensics/frf/refs/openssl-3.6.4.sh --name openssl --version 3.6.4
admit forensics/frf/refs/authority-cli-inventory.sh --name openssl-cli --version 3.6.3
admit forensics/frf/refs/authority-abi-report.sh --name openssl-abi --version 3.6.4
admit forensics/frf/refs/authority-runtime-probe.sh --name openssl-rt --version 3.6.4-r2

echo
echo "=== [2/5] run the courts ==="
for c in $ALL_COURTS; do
    echo "--- court $c ---"
    out=$(frf --root "$ROOT" court run "forensics/frf/courts/$c/manifest.yaml" 2>&1)
    printf '%s\n' "$out"
    # `frf court run` prints the bare run id as its final line.
    printf '%s\n' "$out" | tail -1 >> "$RUNS"
done

echo
echo "=== [3/5] emit receipts ==="
while IFS= read -r run; do
    [ -n "$run" ] || continue
    receipt=$(frf --root "$ROOT" receipt emit "$run" 2>&1 | tail -1)
    printf '%s\n' "$receipt" >> "$RECEIPTS"
    printf '  %s -> %s\n' "$run" "$receipt"
done < "$RUNS"

echo
echo "=== [4/5] challenge every court (negative controls) ==="
# A refusal is a result, not a script failure: FRF refuses when a court cannot
# demonstrate axis isolation, and docs/DECISIONS.md D13 records why an honestly
# refused court is better than a falsely passing one.
for c in $ALL_COURTS; do
    echo "--- challenge $c ---"
    frf --root "$ROOT" court challenge "forensics/frf/courts/$c/manifest.yaml" 2>&1 | tail -3 || true
done

echo
echo "=== [4b/5] dispose the oracle-version trajectory ==="
# Discover the residual by content rather than by quoting a content address, so
# this stays correct when the store is recreated.
VERSION_RESIDUAL=$(grep -l 'OpenSSL 3.6.3 9 Jun 2026' "$ROOT"/residuals/*.json 2>/dev/null | head -1 || true)
if [ -n "$VERSION_RESIDUAL" ]; then
    rid=$(basename "$VERSION_RESIDUAL" .json)
    frf --root "$ROOT" residual dispose "$rid" \
        --disposition oracle_version \
        --reason "OpenSSL version banner differs between the admitted historical authority 3.6.3 and the production target 3.6.4. This is an intended upstream release-identity change, not a candidate defect: it is the expected content of the oracle-version trajectory (docs/SECURITY_DIVERGENCE_POLICY.md, docs/DECISIONS.md D1). Retained as the baseline observation for the 3.6.3 -> 3.6.4 movement." \
        2>&1 | tail -2
else
    echo "  (no release-banner residual found; nothing to dispose)"
fi

echo
echo "=== [5/5] compile claims ==="
# The claims bind one authority each, so they are compiled separately: a claim
# asserts parity against ONE reference and FRF refuses mixed premises.
runtime_receipts=$(grep -E 'receipt-run-openssl-rs-rt-' "$RECEIPTS" | tr '\n' ' ')
dgst_receipt=$(grep -E 'receipt-run-openssl-cli-dgst-' "$RECEIPTS" | head -1)
inventory_receipt=$(grep -E 'receipt-run-openssl-cli-inventory-' "$RECEIPTS" | head -1)
abi_receipt=$(grep -E 'receipt-run-openssl-abi-surface-' "$RECEIPTS" | head -1)
version_receipt=$(grep -E 'receipt-run-openssl-cli-version-' "$RECEIPTS" | head -1)

compile() {
    echo "--- claim compile $* ---"
    frf --root "$ROOT" claim compile "$@" 2>&1 | tail -2
}

# shellcheck disable=SC2086
compile --policy sensitivity-backed $runtime_receipts
compile --policy sensitivity-backed $abi_receipt
compile --policy sensitivity-backed $dgst_receipt
compile --policy sensitivity-backed $inventory_receipt
# The version court's axis is the release banner, which diverges by design, so it
# is a baseline premise alongside the digest court.
compile --policy baseline $version_receipt $dgst_receipt

echo
echo "=== evidence status ==="
frf --root "$ROOT" evidence status 2>&1 | head -12
