#!/usr/bin/env bash
# Freeze b76, second pass (b76b): re-measure the consumer closure with the
# repaired `carry_forward_candidates` coordinate tolerance.
#
# Identical flags to run_closure_b76.sh; only the log and output paths differ so
# the pre-repair evidence (evidence/closure-ssh-b76.json) is preserved verbatim
# and the two can be compared side by side.
#
#   bash docker/openssl-rs-court.sh exec bash court/freeze-b76/run_closure_b76b.sh ssh
set -uo pipefail
cd /work
which="${1:?usage: run_closure_b76b.sh <ssh|sshd>}"
case "$which" in
  ssh)  artifact=court/tmp/openssh-closure/client-b76/openssh-9.9p1/ssh
        carry=evidence/closure-ssh-b74.json ;;
  sshd) artifact=court/tmp/openssh-closure/server-b76/openssh-9.9p1/sshd
        carry=evidence/closure-sshd-b73-r2.json ;;
  *) echo "unknown consumer: $which" >&2; exit 2 ;;
esac
install=artifacts/phase2/install
inventory=court/freeze-b76/census-b76.json
blockers=forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-enrolment-blockers.json
log="court/tmp/closure-$which-b76b.log"
out="evidence/closure-$which-b76b.json"
mkdir -p court/tmp

start=$SECONDS
python3 forensics/tools/consumer_closure.py --family openssh \
  --artifact "$artifact" \
  --install "$install" \
  --inventory "$inventory" \
  --enrolment-blockers "$blockers" \
  --carry-forward-closure "$carry" \
  --enforce-disposition-conflicts \
  --workdir "court/tmp/closure-b76b-$which" \
  --output "$out" --summary > "$log" 2>&1
rc=$?
end=$SECONDS
echo "CONSUMER=$which"
echo "ARTIFACT=$artifact"
echo "CARRY_FORWARD_SOURCE=$carry"
echo "INVENTORY=$inventory"
echo "INSTALL=$install"
echo "TOOL_SHA256=$(sha256sum forensics/tools/consumer_closure.py | cut -d' ' -f1)"
echo "RC=$rc"
echo "WALL_SECONDS=$((end - start))"
if [ -f "$out" ]; then
  echo "OUTPUT_BYTES=$(stat -c %s "$out")"
  echo "OUTPUT_SHA256=$(sha256sum "$out" | cut -d' ' -f1)"
fi
echo "--- log tail ---"
tail -n 40 "$log"
exit "$rc"
