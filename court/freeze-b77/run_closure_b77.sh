#!/usr/bin/env bash
# Freeze b77: re-measure the consumer closure for both OpenSSH families.
#
# S = ada7df257 (src_content 88cd8067…; census court/freeze-b77/census-b77.json).
# The install under test is artifacts/phase2/install (libcrypto
# b9cfb9e5…, rebuilt at the digest repair).  The consumer trees
# court/tmp/openssh-closure/{client,server}-b77 were verified in place as
# `OpenSSH_9.9p1, OpenSSL 3.6.4`, libcrypto under that install, no libssl.
#
# Modelled on court/freeze-b76/run_closure_b76.sh.  The flags are kept
# identical apart from the paths that moved and the carry-forward sources,
# which are named explicitly (never inferred from the newest receipt in
# court/inventory): b77 carries from the b76c receipts, the last set measured
# at a *fully accepted* closure (290/290 sshd, element 7 PASS).
#
# Must be executed inside the court, from the repository root:
#   bash docker/openssl-rs-court.sh exec bash court/freeze-b77/run_closure_b77.sh ssh
#
# The closure needs a larger per-process RLIMIT_DATA than the 4 GiB launcher
# default: the b76 runs died late with a SystemError under 4 GiB, so callers
# set OPENSSL_RS_COURT_DATA=6291456 (6 GiB) for this script.
set -uo pipefail
cd /work
which="${1:?usage: run_closure_b77.sh <ssh|sshd>}"
case "$which" in
  ssh)  artifact=court/tmp/openssh-closure/client-b77/openssh-9.9p1/ssh
        carry=evidence/closure-ssh-b76c.json ;;
  sshd) artifact=court/tmp/openssh-closure/server-b77/openssh-9.9p1/sshd
        carry=evidence/closure-sshd-b76c.json ;;
  *) echo "unknown consumer: $which" >&2; exit 2 ;;
esac
install=artifacts/phase2/install
inventory=court/freeze-b77/census-b77.json
blockers=forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-enrolment-blockers.json
log="court/tmp/closure-$which-b77.log"
out="evidence/closure-$which-b77.json"
mkdir -p court/tmp

echo "COURT_DATA_KIB=$(ulimit -d)"
echo "MEM_PEAK_BEFORE=$(cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo n/a)"
start=$SECONDS
python3 forensics/tools/consumer_closure.py --family openssh \
  --artifact "$artifact" \
  --install "$install" \
  --inventory "$inventory" \
  --enrolment-blockers "$blockers" \
  --carry-forward-closure "$carry" \
  --enforce-disposition-conflicts \
  --workdir "court/tmp/closure-b77-$which" \
  --output "$out" --summary > "$log" 2>&1
rc=$?
end=$SECONDS
echo "CONSUMER=$which"
echo "ARTIFACT=$artifact"
echo "CARRY_FORWARD_SOURCE=$carry"
echo "INVENTORY=$inventory"
echo "INSTALL=$install"
echo "RC=$rc"
echo "WALL_SECONDS=$((end - start))"
echo "ARTIFACT_SHA256=$(sha256sum "$artifact" | cut -d' ' -f1)"
echo "TOOL_SHA256=$(sha256sum forensics/tools/consumer_closure.py | cut -d' ' -f1)"
echo "MEM_PEAK_AFTER=$(cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo n/a)"
echo "MEM_EVENTS=$(tr '\n' ' ' < /sys/fs/cgroup/memory.events 2>/dev/null || echo n/a)"
if [ -f "$out" ]; then
  echo "OUTPUT_BYTES=$(stat -c %s "$out")"
  echo "OUTPUT_SHA256=$(sha256sum "$out" | cut -d' ' -f1)"
fi
echo "--- log tail ---"
tail -n 40 "$log"
exit "$rc"
