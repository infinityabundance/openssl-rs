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
# `sess_id ... -text -cert`, `kdf nonexistent`, `mac NOPE`, `spkac ... -spkac NOPE`,
# `genrsa -bogus`, `ecparam -name <invalid>`, `rsa`/`dsa -modulus`, the `rsautl`
# operation arm, the 17.1e `rand` random-stream arms, the `gendsa`/`genpkey`/`dhparam`
# generation arms, `passwd` without `-salt` and the `engine` listing/`-pre` arms) are
# deliberately absent: each renders a surface this stratum does not own
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
asn1parse -in /work/courts/phase17/fixtures/certs.pem
asn1parse -in /work/courts/phase17/fixtures/certs.pem -noout
asn1parse -in /work/courts/phase17/fixtures/cert.der -inform DER
asn1parse -in /work/courts/phase17/fixtures/cert.der -inform DER -i
ecparam -list_curves
ecparam -name prime256v1 -noout -text
ecparam -name prime256v1 -noout
rsa -in /work/courts/phase17/fixtures/rsa-key.pem -noout -text
rsa -in /work/courts/phase17/fixtures/rsa-key.pem -noout
rsa -in /work/courts/phase17/fixtures/rsa-key.pem -check -noout
rsa -in /work/courts/phase17/fixtures/rsa-key.pem -pubin -noout -text
rsa -check -pubin
rsa -in /work/courts/phase17/fixtures/rsa-key.pem
dsa -in /work/courts/phase17/fixtures/dsa-key.pem -noout -text
dsa -in /work/courts/phase17/fixtures/dsa-key.pem -noout
dsa -in /work/courts/phase17/fixtures/dsa-pub.pem -pubin -noout -text
dsa -in /work/courts/phase17/fixtures/dsa-key.pem
ec -in /work/courts/phase17/fixtures/ec-key.pem -noout -text
ec -in /work/courts/phase17/fixtures/ec-key.pem -noout
ec -in /work/courts/phase17/fixtures/ec-key.pem -check -noout
ec -in /work/courts/phase17/fixtures/ec-pub.pem -pubin -noout -text
ec -in /work/courts/phase17/fixtures/ec-key.pem
pkey -in /work/courts/phase17/fixtures/rsa-key.pem -noout -text
pkey -in /work/courts/phase17/fixtures/rsa-key.pem -check -noout
pkey -in /work/courts/phase17/fixtures/rsa-key.pem -pubout -noout -text
pkey -in /work/courts/phase17/fixtures/rsa-pub.pem -pubin -noout -text
pkey -in /work/courts/phase17/fixtures/rsa-key.pem
pkcs8 -topk8 -nocrypt -in /work/courts/phase17/fixtures/rsa-key.pem
pkcs8 -topk8 -nocrypt -in /work/courts/phase17/fixtures/rsa-key-trad.pem
pkcs8 -in /work/courts/phase17/fixtures/rsa-key.pem -nocrypt
verify -no-CApath -no-CAstore -CAfile /work/courts/phase17/fixtures/ca.pem /work/courts/phase17/fixtures/leaf.pem
verify -CAfile /work/courts/phase17/fixtures/ca.pem /work/courts/phase17/fixtures/leaf.pem
crl -in /work/courts/phase17/fixtures/crl.pem -noout
crl -in /work/courts/phase17/fixtures/crl.pem -text -noout
crl -in /work/courts/phase17/fixtures/crl.pem -issuer -noout
crl -in /work/courts/phase17/fixtures/crl.pem -lastupdate -noout
crl -in /work/courts/phase17/fixtures/crl.pem -nextupdate -noout
crl -in /work/courts/phase17/fixtures/crl.pem -crlnumber -noout
crl -in /work/courts/phase17/fixtures/crl.pem -hash -noout
crl -in /work/courts/phase17/fixtures/crl.pem -fingerprint -noout
crl -in /work/courts/phase17/fixtures/crl.pem
rsautl -sign -pubin
rsautl -decrypt -certin
rsautl -bogus
gendsa
rand
rand 0
rand abc
rand -hex abc
rehash /nonexistent-phase17e
rehash -v /nonexistent-phase17e
storeutl -noout -keys /work/courts/phase17/fixtures/rsa-key.pem
storeutl -noout -certs /work/courts/phase17/fixtures/certs.pem
dhparam -in /work/courts/phase17/fixtures/dhparams.pem -text -noout
dhparam -in /work/courts/phase17/fixtures/dhparams.pem -noout
dhparam -in /work/courts/phase17/fixtures/dhparams.pem -check
genpkey
passwd -1 -salt abcdefgh secret
passwd -5 -salt abcdefgh01234567 secret
passwd -6 -salt abcdefgh01234567 secret
passwd -1 -salt abcdefgh -in /work/courts/phase17/fixtures/pwfile.txt
passwd -1 -salt abcdefgh -table secret
passwd -1 -salt abcdefgh -table -reverse secret
pkeyutl -sign -inkey /work/courts/phase17/fixtures/rsa-key.pem -in /work/courts/phase17/fixtures/small.bin
pkeyutl -verify -pubin -inkey /work/courts/phase17/fixtures/rsa-pub.pem -in /work/courts/phase17/fixtures/small.bin -sigfile /work/courts/phase17/fixtures/small.sig
pkeyutl -encrypt -pubin -inkey /work/courts/phase17/fixtures/rsa-pub.pem -in /work/courts/phase17/fixtures/rsa256.bin -pkeyopt rsa_padding_mode:none
pkeyutl -decrypt -inkey /work/courts/phase17/fixtures/rsa-key.pem -in /work/courts/phase17/fixtures/rsa256.ct -pkeyopt rsa_padding_mode:none
enc -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv 000102030405060708090a0b0c0d0e0f -in /work/courts/phase17/fixtures/small.bin
enc -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv 000102030405060708090a0b0c0d0e0f -in /work/courts/phase17/fixtures/small.enc -d
enc -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv 000102030405060708090a0b0c0d0e0f -in /work/courts/phase17/fixtures/small.bin -a
enc -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv 000102030405060708090a0b0c0d0e0f -in /work/courts/phase17/fixtures/small.bin -a -A
enc -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv 000102030405060708090a0b0c0d0e0f -in /work/courts/phase17/fixtures/small.bin -nopad
enc -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv 000102030405060708090a0b0c0d0e0f -in /work/courts/phase17/fixtures/small.bin -P -nosalt
ARGS
