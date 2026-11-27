#!/usr/bin/env bash
# PFP-7 fault-injection matrix: corrupt each CRT half and the recombination.
set -euo pipefail
ROOT=/work
BUILD=${BUILD:-/work/court/tmp/pfp7/build}
DIR=/work/court/tmp/pfp7/fault
DSO="$BUILD/distribution/libcrypto.so.3"
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
mkdir -p "$DIR"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/evidence/performance-frontier/campaigns/PFP-7/harness/pfp7_fault.c" \
   -ldl -o "$DIR/pfp7_fault"
sha256sum "$DSO" "$AUTH" >"$DIR/identity.sha256"
"$DIR/pfp7_fault" --lib "$DSO" --rsa-der "$RSA_DER" | tee "$DIR/candidate.txt"
"$DIR/pfp7_fault" --lib "$AUTH" --rsa-der "$RSA_DER" >"$DIR/authority.txt"
python3 - "$DIR/candidate.txt" "$DIR/authority.txt" <<'PY'
import sys, re
def load(p):
    d = {}
    for line in open(p):
        m = re.match(r'CASE (\S+)\s+rc=(-?\d+) out=(\w+)', line)
        if m: d[m.group(1)] = (int(m.group(2)), m.group(3))
    return d
cand, auth = load(sys.argv[1]), load(sys.argv[2])
print('fault,blinding,verdict')
bad = 0
for mode in ('blind', 'noblind'):
    ref = cand['clean'] if mode == 'blind' else cand['clean-noblind']
    for tag, badd in (('halfA', 0), ('halfB', 0), ('combine', 0),
                      ('halfA+badD', 1), ('halfB+badD', 1),
                      ('combine+badD', 1), ('badD', 1)):
        got = cand[f'{tag}-{mode}']
        same = got[1] == ref[1]
        if tag == 'badD':
            v = 'NO_FAULT_UNCHANGED' if same else 'UNEXPECTED_CHANGE'
            if not same: bad += 1
        elif badd:
            v = 'EXPECTED_WRONG' if not same else 'CONTROL_DID_NOT_CORRUPT'
            if same: bad += 1
        else:
            v = 'DETECTED' if same else 'UNDETECTED'
            if not same: bad += 1
        print(f'{tag},{mode},{v}')
# With a corrupt d and blinding on, the unblinding factor no longer cancels and
# the returned bytes carry the (independent, random) blinding factor, so those
# cases are not comparable across implementations by construction.  Everything
# else must match the authority byte for byte.
mism = [k for k in cand if k in auth and cand[k] != auth[k]
        and not (k.endswith('-blind') and '+badD' in k)]
print('lines', len(cand), 'cross_impl_mismatches', len(mism))
for k in mism[:8]:
    print('MISMATCH', k, cand[k], auth[k])
print('VERDICT', 'FAIL' if (bad or mism) else 'PASS')
PY
