#!/bin/sh
# openssl-rs FRF CANDIDATE side for the Phase 3 runtime courts.
#
# The sibling of `authority-runtime-probe.sh`: the *same* probe source, compiled
# against the candidate's generated headers and its `libcrypto.so.3`, is run over
# the same fixture list. FRF compares the two transcripts.
#
# `LD_LIBRARY_PATH` binds `artifacts/phase2`, the built distribution shell — the
# candidate library, not a copy of the system OpenSSL. A candidate that only
# worked when the authority's library happened to be found first would produce a
# transcript agreeing with the authority for the wrong reason, so the binding is
# explicit and is declared in each manifest's `execution_context`.
#
# The binding is applied to the probe invocation only, never exported: Debian's
# `sha256sum` links libcrypto, so exporting it would make this harness's own
# digest tool load the library under test instead of the system one. See the
# authority wrapper for the measurement that established this.
set -eu
LIST="${1:?usage: candidate-runtime-probe.sh <probe-list>}"

CAND=/work/artifacts/phase2
PROBES=/work/artifacts/phase3/probes

status=0
while IFS= read -r name; do
    [ -n "$name" ] || continue
    case "$name" in \#*) continue ;; esac
    if [ ! -x "$PROBES/$name.candidate" ]; then
        printf 'openssl-rs: no staged candidate probe %s\n' "$name" >&2
        exit 2
    fi
    transcript=$(OPENSSL_CONF=/dev/null TZ=UTC LC_ALL=C \
        LD_LIBRARY_PATH="$CAND" "$PROBES/$name.candidate") || status=$?
    printf 'transcript.sha256=%s\n' "$(printf '%s' "$transcript" | sha256sum | cut -d' ' -f1)"
    printf '%s\n' "$transcript"
done < "$LIST"
exit "$status"
