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
# `-enginesdir`/`-modulesdir`, `prime 2 3 4`/`-hex FF`, the `ciphers` list arms,
# `sess_id ... -text -cert`, `kdf nonexistent`, `mac NOPE`, `spkac ... -spkac NOPE` and
# `genrsa -bogus`) are deliberately absent: each renders a surface this stratum does not own
# (see `forensics/tools/phase17_courts.py`'s RECORDED_DIVERGENCES and the per-command module
# headers).
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
crl2pkcs7 -nocrl -certfile /work/courts/phase17/fixtures/certs.pem
ciphers -convert TLS_AES_256_GCM_SHA384
ciphers -convert ECDHE-RSA-AES256-GCM-SHA384
ciphers -convert NOPE
sess_id -in /work/courts/phase17/fixtures/session.pem
sess_id -in /work/courts/phase17/fixtures/session.pem -text
sess_id -in /work/courts/phase17/fixtures/session.pem -cert
sess_id -in /work/courts/phase17/fixtures/session.pem -noout
sess_id -in /work/courts/phase17/fixtures/session.pem -text -noout
sess_id -in /work/courts/phase17/fixtures/session.pem -context abc
sess_id -in /work/courts/phase17/fixtures/session.pem -context 123456789012345678901234567890123
kdf -keylen 16 -kdfopt pass:password -kdfopt salt:NaCl -kdfopt iter:1 PBKDF2
kdf -keylen 0 PBKDF2
kdf -keylen -1 PBKDF2
kdf -keylen 16 -kdfopt pass:p -kdfopt salt:s -kdfopt iter:1 -kdfopt digest:SHA256 PBKDF2
kdf PBKDF2
kdf
mac -macopt key:secret HMAC -in /work/courts/phase17/fixtures/certs.pem
mac -macopt key:secret -macopt digest:SHA1 HMAC -in /work/courts/phase17/fixtures/certs.pem
mac HMAC -in /work/courts/phase17/fixtures/certs.pem
mac
spkac -in /work/courts/phase17/fixtures/spkac.cnf
spkac -in /work/courts/phase17/fixtures/spkac.cnf -noout
spkac -in /work/courts/phase17/fixtures/spkac.cnf -verify
spkac -in /work/courts/phase17/fixtures/spkac.cnf -pubkey
spkac -in /work/courts/phase17/fixtures/spkac.cnf -verify -pubkey
genrsa abc
genrsa 0
genrsa 99999999999999999999
dsaparam abc
dsaparam 1 2 3
dsaparam -text abc
ARGS
