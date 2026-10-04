#!/bin/sh
# openssl-rs RT-CLI-BODIES probe: drive one side's `openssl` over the court's fixed command argv
# and print one `case.N.*` line per observation. `$1` is the side's `openssl`, `$2` its
# `ossl-modules/`; the fixture (`probe-list.txt`) names this probe, which is what makes it
# challengeable (docs/DECISIONS.md D13).
#
# It is a shell probe rather than a compiled C program because the subject is the CLI
# *executable*, which is not linkable. The transcript format matches the court venue's
# `cli_transcript`: key=value, newline -> `|`, CR -> `^`.
#
# The divergent inputs (`errstr 0xdeadbeef`, `info -seeds`/`-cpusettings`/`-configdir`/
# `-enginesdir`/`-modulesdir`, `prime 2 3 4`/`-hex FF`) are deliberately absent: each renders a
# surface this stratum does not own (see `forensics/tools/phase17_courts.py`'s
# RECORDED_DIVERGENCES and the per-command module headers).
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
info -dsoext
info -dirnamesep
info -listsep
info -windowscontext
info
info -dsoext -listsep
prime 97
prime -hex 0xFF
prime abc
prime
prime -generate
skeyutl
skeyutl -genkey
skeyutl -skeymgmt foo
configutl -config /work/courts/phase17/fixtures/configutl.cnf -noheader
configutl -config /work/courts/phase17/fixtures/configutl.cnf
pkeyparam -in /work/courts/phase17/fixtures/dhparams.pem
pkeyparam -in /work/courts/phase17/fixtures/dhparams.pem -noout
pkeyparam -in /work/courts/phase17/fixtures/dhparams.pem -text
pkeyparam -in /work/courts/phase17/fixtures/dhparams.pem -check
nseq -toseq -in /work/courts/phase17/fixtures/certs.pem
nseq -in /work/courts/phase17/fixtures/seq.pem
ARGS
