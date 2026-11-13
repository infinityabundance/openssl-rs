#!/usr/bin/env bash
# Freeze b76: re-measure the consumer closure for both OpenSSH families.
#
# S = c809d94f1 (census court/freeze-b76/census-b76.json, source_head 0238c6e4a,
# src_content 66c1e9ae).  The install under test is artifacts/phase2/install
# (libcrypto 8f188717…, libssl b7f72c5a…, legacy.so 185979c0…, openssl 6ac9e41c…),
# and the consumer trees court/tmp/openssh-closure/{client,server}-b76 were
# verified in place as `OpenSSH_9.9p1, OpenSSL 3.6.4` linked against that install.
#
# Modelled on court/freeze-b73/run_closure_b73.sh.  The b73 flags are kept
# identical apart from the paths that moved: b73 used a freeze-local install
# (court/freeze-b73/install) that no longer exists; the b76 install lives at
# artifacts/phase2/install.  Carry-forward sources are named explicitly, never
# inferred from the most recent receipt in court/inventory.
#
# Must be executed inside the court, from the repository root:
#   bash docker/openssl-rs-court.sh exec bash court/freeze-b76/run_closure_b76.sh ssh
set -uo pipefail
cd /work
which="${1:?usage: run_closure_b76.sh <ssh|sshd>}"
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
log="court/tmp/closure-$which-b76.log"
out="evidence/closure-$which-b76.json"
mkdir -p court/tmp

start=$SECONDS
python3 forensics/tools/consumer_closure.py --family openssh \
  --artifact "$artifact" \
  --install "$install" \
  --inventory "$inventory" \
  --enrolment-blockers "$blockers" \
  --carry-forward-closure "$carry" \
  --enforce-disposition-conflicts \
  --workdir "court/tmp/closure-b76-$which" \
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
if [ -f "$out" ]; then
  echo "OUTPUT_BYTES=$(stat -c %s "$out")"
  echo "OUTPUT_SHA256=$(sha256sum "$out" | cut -d' ' -f1)"
fi
echo "--- log tail ---"
tail -n 40 "$log"
exit "$rc"
