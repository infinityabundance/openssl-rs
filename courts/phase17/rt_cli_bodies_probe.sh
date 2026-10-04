#!/bin/sh
# openssl-rs RT-CLI-BODIES probe: drive one side's `openssl` over the court's fixed `errstr`
# argv and print one `case.N.*` line per observation. `$1` is the side's `openssl`, `$2` its
# `ossl-modules/`; the fixture (`probe-list.txt`) names this probe, which is what makes it
# challengeable (docs/DECISIONS.md D13).
#
# It is a shell probe rather than a compiled C program because the subject is the CLI
# *executable*, which is not linkable. The transcript format matches the court venue's
# `cli_transcript`: key=value, newline -> `|`, CR -> `^`.
#
# `errstr 0xdeadbeef` is deliberately absent: it renders an unknown system error, whose
# `ERR_error_string_n` value diverges (see `forensics/tools/phase17_courts.py`'s
# RECORDED_DIVERGENCES and `src/apps/errstr.rs`).
set -u
BIN="${1:?usage: rt_cli_bodies_probe.sh <openssl> <ossl-modules>}"
MODULES="${2:-}"
if [ -n "$MODULES" ]; then
    OPENSSL_MODULES="$MODULES"
    export OPENSSL_MODULES
fi
i=0
while IFS= read -r argv; do
    [ -n "$argv" ] || continue
    case "$argv" in \#*) continue ;; esac
    out=$(mktemp)
    err=$(mktemp)
    # shellcheck disable=SC2086
    "$BIN" $argv >"$out" 2>"$err"
    code=$?
    so=$(tr '\n' '|' <"$out" | tr '\r' '^')
    se=$(tr '\n' '|' <"$err" | tr '\r' '^')
    rm -f "$out" "$err"
    printf 'case.%s.argv=%s\n' "$i" "$argv"
    printf 'case.%s.exit=%s\n' "$i" "$code"
    printf 'case.%s.stdout=%s\n' "$i" "$so"
    printf 'case.%s.stderr=%s\n' "$i" "$se"
    i=$((i + 1))
done <<'ARGS'
errstr 0x03000041 0x0308010C 0x0A000041 1 0x00000000 nothex
errstr
errstr 0x00000000
ARGS
