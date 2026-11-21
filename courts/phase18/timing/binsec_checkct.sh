#!/usr/bin/env bash
# T16 — validated BINSEC -checkct invocation.
#
# Run inside the court tools image, e.g.:
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#     bash docker/openssl-rs-court.sh exec \
#     bash courts/phase18/timing/binsec_checkct.sh <sse-script.cfg> <elf> [extra binsec args]
#
# Why each part is required (measured on Binsec 0.11.3, 2026-11-21):
#   -sse            `-checkct` alone starts no symbolic engine. It exits 0 with
#                   ZERO bytes on stdout and stderr — the T16 non-result. A
#                   silent tool is not a pass.
#   -sse-script     without a script nothing is reachable: status `unknown`,
#                   0 instructions, "[sse:warning] Nothing to reach".
#   -smt-solver z3  `auto` falls back to an incomplete internal solver when no
#                   solver is on PATH (1 query unknown + "Threat to
#                   completeness"). The tools image ships z3 but does not put it
#                   on PATH; this script does.
#
# The SSE script this repo uses supplies:
#   starting from <symbol>        entry point
#   with concrete stack pointer   concrete initial stack
#   secret global <name>          symbolic input that must not influence
#                                 control flow or memory addresses
#   public global <name>          symbolic but attacker-visible input
#   assume <constraint>           restrict inputs (e.g. reduced operands)
#   halt at <symbol>              stop at a named, noinline halt point
#   explore all
#
# Leakage model: BINSEC's default -checkct-features, i.e. control-flow and
# memory-access checks (multiplication/division checks are experimental and off
# by default). `-checkct-leak-info instr` (default) reports each leaky
# instruction once. This is a binary-level model: it does not model
# microarchitectural timing or value-only constant-latency effects.
#
# Verdict handling: `secure` and `insecure` are verdicts; `unknown` means the
# exploration was incomplete (SMT timeout, unresolved indirect jump, bounded
# -sse-timeout) and is NOT a pass. This script exits 0 only for a verdict.
#
# Version recorded at run time:
#   BINSEC 0.11.3 (opam switch 4.14.2)
#   z3     4.13.0 (/opt/z3-solver/z3-4.13.0-x64-glibc-2.35/bin)
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <sse-script.cfg> <elf> [extra binsec args...]" >&2
    exit 2
fi

cfg=$1
elf=$2
shift 2

if [ ! -r "$cfg" ]; then echo "error: cannot read script '$cfg'" >&2; exit 2; fi
if [ ! -r "$elf" ]; then echo "error: cannot read binary '$elf'" >&2; exit 2; fi
if ! command -v binsec >/dev/null 2>&1; then
    echo "error: binsec not found; run inside the tools court image" >&2
    exit 2
fi

# The image installs z3 under /opt but does not export it. Prefer PATH if the
# caller already provided a solver, otherwise add the pinned directory.
if ! command -v z3 >/dev/null 2>&1; then
    for d in "${BINSEC_Z3_DIR:-}" /opt/z3-solver/z3-4.13.0-x64-glibc-2.35/bin; do
        if [ -n "$d" ] && [ -x "$d/z3" ]; then
            export PATH="$d:$PATH"
            break
        fi
    done
fi
if ! command -v z3 >/dev/null 2>&1; then
    echo "error: z3 not found; without a solver -checkct cannot reach a verdict" >&2
    exit 2
fi

smt_timeout=${BINSEC_SMT_TIMEOUT:-30}
sse_timeout=${BINSEC_SSE_TIMEOUT:-600}

echo "# binsec: $(binsec -version 2>&1 | head -n 1)" >&2
echo "# z3:     $(z3 --version 2>&1 | head -n 1)" >&2
echo "# script: $cfg" >&2
echo "# binary: $elf" >&2

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

set +e
binsec -sse -checkct -sse-script "$cfg" -smt-solver z3 \
    -smt-timeout "$smt_timeout" -sse-timeout "$sse_timeout" \
    "$@" "$elf" >"$tmp/out" 2>"$tmp/err"
rc=$?
set -e

cat "$tmp/out"
cat "$tmp/err" >&2

if grep -q '\[checkct:result\] Program status is : secure' "$tmp/out"; then
    echo "T16 verdict: secure" >&2
    exit "$rc"
elif grep -q '\[checkct:result\] Program status is : insecure' "$tmp/out"; then
    echo "T16 verdict: insecure" >&2
    exit "$rc"
elif grep -q '\[checkct:result\] Program status is : unknown' "$tmp/out"; then
    echo "T16 verdict: unknown (incomplete; NOT a pass)" >&2
    exit 4
else
    echo "T16 verdict: none (no [checkct:result] line; NOT a pass)" >&2
    exit 3
fi
