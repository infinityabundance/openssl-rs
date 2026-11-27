#!/bin/sh
# run_differential_wp.sh — PFP8-WIDTH-POLICY: compile the DH harness and run the
# differential against the OpenSSL 3.6.4 authority.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash courts/performance-frontier/pfp8/run_differential_wp.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8/width-policy
OUT=/work/court/tmp/pfp8-wp
AUTH_INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
mkdir -p "$OUT" "$EV/raw"

cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   /work/courts/performance-frontier/pfp8/bench_pfp8.c -ldl -o "$OUT/bench_pfp8_wp"

{
    echo "cand_dso_sha256=$(sha256sum /work/court/tmp/pfp8-wp-build/cand/distribution/libcrypto.so.3 | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum /work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3 | awk '{print $1}')"
    echo "harness_source_sha256=$(sha256sum /work/courts/performance-frontier/pfp8/bench_pfp8.c | awk '{print $1}')"
    echo "harness_binary_sha256=$(sha256sum "$OUT/bench_pfp8_wp" | awk '{print $1}')"
    echo "driver_sha256=$(sha256sum /work/courts/performance-frontier/pfp8/differential_wp.py | awk '{print $1}')"
    echo "cc=$(cc --version | head -1)"
} >"$EV/raw/differential-meta.env"

python3 /work/courts/performance-frontier/pfp8/differential_wp.py
echo DIFFERENTIAL_OK
