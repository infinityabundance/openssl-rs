#!/usr/bin/env bash
# T16 — validated BINSEC -checkct invocation, fail-closed.
#
# Run inside the court tools image, e.g.:
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#     bash docker/openssl-rs-court.sh exec \
#     bash courts/phase18/timing/binsec_checkct.sh <sse-script.cfg> <elf> [extra binsec args]
#
#   # require a secure verdict, not merely "some verdict"
#   bash courts/phase18/timing/binsec_checkct.sh --require-secure <cfg> <elf>
#
#   # bind the run to one candidate artefact
#   BINSEC_EXPECT_SHA256=<hex> bash courts/phase18/timing/binsec_checkct.sh <cfg> <elf>
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
# Verdict handling.  `secure` and `insecure` are verdicts; `unknown` means the
# exploration was incomplete (SMT timeout, unresolved indirect jump, bounded
# -sse-timeout) and is NOT a pass.  This script's exit status is authoritative:
#
#   0  secure (tool exited 0)
#   1  insecure — always nonzero.  A verdict-bearing script that reported a
#      failure and exited 0 was the fail-open defect this closes.
#   2  invocation/venue refusal: bad arguments, unreadable input, not an ELF
#      file, binsec or z3 absent, `timeout` absent
#   3  no single well-formed [checkct:result] status line: silence, a crash
#      before the verdict, a truncated/malformed result line, or an ambiguous
#      verdict line carrying additional text.  NOT a pass.
#   4  unknown: the exploration did not finish.  NOT a pass.
#   5  BINSEC_EXPECT_SHA256 did not match the binary
#   6  inconsistent transcript: two or more verdicts, mixed secure/insecure,
#      a duplicated secure verdict, a secure verdict with a nonzero tool
#      status, or a wall-clock timeout
#   8  --require-secure was given and the verdict was not secure
#
# The complete verdict population is parsed before any verdict is accepted.
# The canonical status line is
#
#   [checkct:result] Program status is : <verdict>[ (<seconds>)]
#
# where the optional parenthesised field is BINSEC's own elapsed time.  This
# is an exact full-line grammar: a status line with any other trailing text is
# refused (reason `verdict-trailing-text`), not matched as a prefix.  Exactly
# one verdict is required.  Zero verdicts is `no-verdict-line`; two or more is
# `multiple-verdicts`; both secure and insecure is `mixed-verdicts`; two secure
# verdicts is `duplicate-secure`.  The earlier parser searched for the secure
# line first, so a transcript containing both a secure and an insecure line was
# accepted as secure when the tool exited zero.
#
# Every refusal names the target binary and the reason on stderr.
#
# Injection seams for the refusal controls (forensics/tools/instrument_qualify.py):
#   BINSEC_BIN            the binsec executable (default: binsec)
#   BINSEC_Z3             the z3 executable (default: z3, then BINSEC_Z3_DIR)
#   BINSEC_Z3_DIR         directory containing z3
#   BINSEC_EXPECT_SHA256  refuse unless sha256(elf) matches
#   BINSEC_WALL_TIMEOUT   overall wall-clock bound, seconds (default 900)
#   BINSEC_SMT_TIMEOUT    per-query SMT bound (default 30)
#   BINSEC_SSE_TIMEOUT    symbolic exploration bound (default 600)
set -euo pipefail

prog=binsec_checkct
refuse() { # code reason...
    local code=$1 reason=$2
    echo "$prog: REFUSED target='${elf:-<unset>}' reason=$reason" >&2
    exit "$code"
}

require_secure=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --require-secure) require_secure=1; shift ;;
        --) shift; break ;;
        -h|--help)
            sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        -*) echo "$prog: unknown option: $1" >&2; exit 2 ;;
        *) break ;;
    esac
done

if [ "$#" -lt 2 ]; then
    echo "usage: $0 [--require-secure] <sse-script.cfg> <elf> [extra binsec args...]" >&2
    exit 2
fi

cfg=$1
elf=$2
shift 2

[ -r "$cfg" ] || refuse 2 "cannot-read-script '$cfg'"
[ -f "$elf" ] && [ -r "$elf" ] || refuse 2 "cannot-read-binary '$elf'"

ELF_MAGIC=$(od -An -tx1 -N4 "$elf" 2>/dev/null | tr -d ' \n' || true)
[ "$ELF_MAGIC" = "7f454c46" ] || \
    refuse 2 "unsupported-format: not an ELF file (first bytes '${ELF_MAGIC:-<unreadable>}')"

BINSEC_BIN=${BINSEC_BIN:-binsec}
if ! command -v "$BINSEC_BIN" >/dev/null 2>&1; then
    refuse 2 "binsec-not-found '$BINSEC_BIN'; run inside the tools court image"
fi

# The image installs z3 under /opt but does not export it. An explicit
# BINSEC_Z3 / BINSEC_Z3_DIR wins, then PATH, then the pinned directory.
if [ -n "${BINSEC_Z3:-}" ]; then
    [ -x "$BINSEC_Z3" ] || refuse 2 "z3-not-executable '$BINSEC_Z3'"
    z3=$BINSEC_Z3
elif command -v z3 >/dev/null 2>&1; then
    z3=$(command -v z3)
else
    z3=
    for d in "${BINSEC_Z3_DIR:-}" /opt/z3-solver/z3-4.13.0-x64-glibc-2.35/bin; do
        if [ -n "$d" ] && [ -x "$d/z3" ]; then
            export PATH="$d:$PATH"
            z3=$d/z3
            break
        fi
    done
    [ -n "$z3" ] || refuse 2 "z3-not-found; without a solver -checkct cannot reach a verdict"
fi

command -v timeout >/dev/null 2>&1 || \
    refuse 2 "timeout-not-found; an unbounded exploration is not run"

wall_timeout=${BINSEC_WALL_TIMEOUT:-900}
case "$wall_timeout" in ''|*[!0-9]*) refuse 2 "BINSEC_WALL_TIMEOUT is not a number: '$wall_timeout'" ;; esac
[ "$wall_timeout" -gt 0 ] || refuse 2 "BINSEC_WALL_TIMEOUT must be positive"
smt_timeout=${BINSEC_SMT_TIMEOUT:-30}
sse_timeout=${BINSEC_SSE_TIMEOUT:-600}

if [ -n "${BINSEC_EXPECT_SHA256:-}" ]; then
    command -v sha256sum >/dev/null 2>&1 || refuse 2 "sha256sum-not-found"
    observed=$(sha256sum "$elf" | cut -d' ' -f1)
    expected=$(printf '%s' "$BINSEC_EXPECT_SHA256" | tr 'A-F' 'a-f')
    [ "$observed" = "$expected" ] || \
        refuse 5 "candidate-identity-mismatch expected=$expected observed=$observed"
fi

echo "# binsec: $("$BINSEC_BIN" -version 2>&1 | head -n 1 || true)" >&2
echo "# z3:     $("$z3" --version 2>&1 | head -n 1 || true)" >&2
echo "# script: $cfg" >&2
echo "# binary: $elf ($(sha256sum "$elf" | cut -d' ' -f1))" >&2
echo "# wall:   ${wall_timeout}s" >&2

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

set +e
timeout --signal=TERM --kill-after=10s "$wall_timeout" \
    "$BINSEC_BIN" -sse -checkct -sse-script "$cfg" -smt-solver z3 \
    -smt-timeout "$smt_timeout" -sse-timeout "$sse_timeout" \
    "$@" "$elf" >"$tmp/out" 2>"$tmp/err"
rc=$?
set -e

cat "$tmp/out"
cat "$tmp/err" >&2

if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    refuse 6 "timeout: wall bound ${wall_timeout}s exceeded (binsec status $rc)"
fi

# Parse the COMPLETE verdict population before deciding anything.  A
# transcript with two status lines is not resolved by the order in which they
# appear; `grep -Fq secure` accepted a mixed transcript as soon as a secure
# line existed.  The grammar below is anchored to the whole line, with only
# BINSEC's parenthesised elapsed-time field permitted after the verdict.
verdict_counts=$(awk '
  /^\[checkct:result\] Program status is : secure( \([0-9]+(\.[0-9]+)?\))?$/   { s++; next }
  /^\[checkct:result\] Program status is : insecure( \([0-9]+(\.[0-9]+)?\))?$/ { i++; next }
  /^\[checkct:result\] Program status is : unknown( \([0-9]+(\.[0-9]+)?\))?$/  { u++; next }
  /^\[checkct:result\] Program status is : (secure|insecure|unknown)/        { t++; next }
  /^\[checkct:result\] Program status is :/                                  { m++; next }
  END { printf "%d %d %d %d %d\n", s+0, i+0, u+0, t+0, m+0 }
' "$tmp/out")
read -r n_secure n_insecure n_unknown n_trailing n_malformed <<EOF
$verdict_counts
EOF

if [ "$n_trailing" -gt 0 ]; then
    refuse 3 "verdict-trailing-text:${n_trailing}-line(s): a status line carries text after the verdict"
fi
if [ "$n_malformed" -gt 0 ]; then
    refuse 3 "no-verdict-line:malformed-verdict-line:${n_malformed}-line(s)"
fi

verdict_total=$((n_secure + n_insecure + n_unknown))
if [ "$verdict_total" -eq 0 ]; then
    if [ ! -s "$tmp/out" ] && [ ! -s "$tmp/err" ]; then
        refuse 3 "no-output: binsec produced nothing on stdout or stderr (status $rc)"
    fi
    refuse 3 "no-verdict-line: no [checkct:result] result on stdout (status $rc)"
fi

if [ "$verdict_total" -gt 1 ]; then
    if [ "$n_secure" -gt 0 ] && [ "$n_insecure" -gt 0 ]; then
        refuse 6 "mixed-verdicts: secure=$n_secure insecure=$n_insecure"
    fi
    if [ "$n_secure" -gt 1 ]; then
        refuse 6 "duplicate-secure: secure=$n_secure"
    fi
    refuse 6 "multiple-verdicts: secure=$n_secure insecure=$n_insecure unknown=$n_unknown"
fi

if [ "$n_secure" -eq 1 ]; then
    if [ "$rc" -ne 0 ]; then
        refuse 6 "secure-verdict-with-tool-status-$rc: inconsistent output"
    fi
    echo "T16 verdict: secure" >&2
    exit 0
fi

if [ "$n_insecure" -eq 1 ]; then
    echo "T16 verdict: insecure" >&2
    if [ "$require_secure" = 1 ]; then
        refuse 8 "required-secure but verdict=insecure"
    fi
    exit 1
fi

echo "T16 verdict: unknown (incomplete; NOT a pass)" >&2
if [ "$require_secure" = 1 ]; then
    refuse 8 "required-secure but verdict=unknown"
fi
exit 4
