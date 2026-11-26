#!/bin/sh
# run_domain_court.sh — re-run the PFP-22/PFP-24 differential domain against
# the PFP-27 artefact A (DSO 5e75b694, which is byte-identical to the PFP-24
# candidate digest).
#
# The runner, harness source and case populations are the PFP-24 copies,
# unchanged except for OUT (this campaign's evidence directory).  The PFP-24
# record is not overwritten (Earned Trust article 10): the copy runs into
# evidence/performance-frontier/campaigns/PFP-6/artefact-audit/domain.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec bash \
#       evidence/performance-frontier/campaigns/PFP-6/artefact-audit/run_domain_court.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

SRC=/work/evidence/performance-frontier/campaigns/PFP-2/dso-differential/pfp24-domain-5e75b694
EV=/work/evidence/performance-frontier/campaigns/PFP-6/artefact-audit
RUN=/work/court/tmp/pfp27/domain-run

rm -rf "$RUN"
mkdir -p "$RUN" "$EV/domain"
cp "$SRC/run_domain.sh" "$SRC/pfp24_domain_differential.c" "$SRC/domain_record.py" "$RUN/"
cp "$SRC/pfp24_domain_differential.c" "$SRC/domain_record.py" "$EV/domain/"
chmod +x "$RUN/run_domain.sh"

sed -i 's#^OUT=.*#OUT="/work/evidence/performance-frontier/campaigns/PFP-6/artefact-audit/domain"#' \
    "$RUN/run_domain.sh"
grep -n '^OUT=' "$RUN/run_domain.sh"

# The candidate is this campaign's artefact A; the digest pin inside the copy
# (5e75b694) is the same artefact and is left in place as the assertion.
PFP24_DOMAIN_CAND=/work/court/tmp/pfp27/a/distribution/libcrypto.so.3 \
    bash "$RUN/run_domain.sh"
