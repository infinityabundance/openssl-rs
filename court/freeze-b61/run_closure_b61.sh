#!/usr/bin/env bash
# Freeze b61: re-measure the consumer closure for both families at S with the
# declared-definition-set instrument.
#
# Same source (S = b6f38f134), same census, same install and same relinked
# consumer binaries as b58/b59; only forensics/tools/consumer_closure.py changed
# (the `declared_spans` mechanism).  The tool is build-relevant evidence, so the
# freeze identity moves even though no Rust source did.
set -uo pipefail
cd /work
which="${1:?usage: run_closure_b61.sh <ssh|sshd>}"
case "$which" in
  ssh)  artifact=court/tmp/openssh-closure/client-b58/openssh-9.9p1/ssh ;;
  sshd) artifact=court/tmp/openssh-closure/server-b58/openssh-9.9p1/sshd ;;
  *) echo "unknown consumer: $which" >&2; exit 2 ;;
esac
start=$SECONDS
python3 forensics/tools/consumer_closure.py --family openssh \
  --artifact "$artifact" \
  --install court/freeze-b58/install \
  --inventory court/freeze-b58/census-b58.json \
  --enrolment-blockers forensics/memory-safety/campaign/safe-c33/atlas-refresh/callback-enrolment-blockers.json \
  --workdir "court/tmp/closure-b61-$which" \
  --output "evidence/closure-$which-b61.json" --summary > "/tmp/closure-$which-b61.log" 2>&1
rc=$?
end=$SECONDS
echo "CONSUMER=$which"
echo "RC=$rc"
echo "WALL_SECONDS=$((end - start))"
tail -n 40 "/tmp/closure-$which-b61.log"
exit "$rc"
