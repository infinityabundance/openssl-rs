#!/usr/bin/env bash
# Freeze b73: re-measure the consumer closure for both families at S.
#
# S = 15bebabc9 (`src/` byte-identical to 0d39697ae, which repaired
# src/engine/eng_list.rs).  Every earlier measurement named a source without
# that repair, so the install, the consumer binaries and the census are all
# rebuilt here: S moved, and consumer_closure.py binds span hashes to
# inventory.identity.source_head, so a b58/b61 census would describe the wrong
# coordinates.
#
# b61 could only resolve the carry-forward source implicitly, and the implicit
# default (the most recent ACCEPTED receipt in court/inventory) turned out to be
# a b51-era receipt, so 150 obligations were carried from b51 rather than from
# the previous measurement.  Here the source is named explicitly.
set -uo pipefail
cd /work
which="${1:?usage: run_closure_b73.sh <ssh|sshd>}"
case "$which" in
  ssh)  artifact=court/tmp/openssh-closure/client-b73/openssh-9.9p1/ssh
        carry=evidence/closure-ssh-b61.json ;;
  sshd) artifact=court/tmp/openssh-closure/server-b73/openssh-9.9p1/sshd
        carry=evidence/closure-sshd-b61.json ;;
  *) echo "unknown consumer: $which" >&2; exit 2 ;;
esac
start=$SECONDS
python3 forensics/tools/consumer_closure.py --family openssh \
  --artifact "$artifact" \
  --install court/freeze-b73/install \
  --inventory court/freeze-b73/census-b73.json \
  --enrolment-blockers forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-enrolment-blockers.json \
  --carry-forward-closure "$carry" \
  --enforce-disposition-conflicts \
  --workdir "court/tmp/closure-b73-$which" \
  --output "evidence/closure-$which-b73.json" --summary > "/tmp/closure-$which-b73.log" 2>&1
rc=$?
end=$SECONDS
echo "CONSUMER=$which"
echo "CARRY_FORWARD_SOURCE=$carry"
echo "RC=$rc"
echo "WALL_SECONDS=$((end - start))"
tail -n 40 "/tmp/closure-$which-b73.log"
exit "$rc"
