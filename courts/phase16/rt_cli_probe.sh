#!/bin/sh
# openssl-rs RT-CLI probe: drive one side's `openssl` over the court's fixed argv and
# print one `case.N.*` line per observation. `$1` is the side's `openssl`, `$2` its
# `ossl-modules/`; the fixture (`probe-list.txt`) names this probe, which is what makes
# it challengeable (docs/DECISIONS.md D13).
#
# It is a shell probe rather than a compiled C program because the subject is the CLI
# *executable*, which is not linkable. The transcript format matches the court venue's
# `cli_transcript`: key=value, newline -> `|`, CR -> `^`.
set -u
BIN="${1:?usage: rt_cli_probe.sh <openssl> <ossl-modules>}"
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
version
version -v
help
list -commands -1
list -options bogus
zzz-not-a-command
no-version
no-zzz-not-a-command
list -options asn1parse
list -options ca
list -options ciphers
list -options cmp
list -options cms
list -options configutl
list -options crl
list -options crl2pkcs7
list -options dgst
list -options dhparam
list -options dsa
list -options dsaparam
list -options ec
list -options ecparam
list -options enc
list -options engine
list -options errstr
list -options fipsinstall
list -options gendsa
list -options genpkey
list -options genrsa
list -options help
list -options info
list -options kdf
list -options list
list -options mac
list -options nseq
list -options ocsp
list -options passwd
list -options pkcs12
list -options pkcs7
list -options pkcs8
list -options pkey
list -options pkeyparam
list -options pkeyutl
list -options prime
list -options rand
list -options rehash
list -options req
list -options rsa
list -options rsautl
list -options s_client
list -options s_server
list -options s_time
list -options sess_id
list -options skeyutl
list -options smime
list -options speed
list -options spkac
list -options srp
list -options storeutl
list -options ts
list -options verify
list -options version
list -options x509
ARGS
