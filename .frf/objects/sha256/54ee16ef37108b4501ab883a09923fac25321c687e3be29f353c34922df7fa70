#!/bin/sh
# openssl-rs FRF AUTHORITY side for the Phase 3 runtime courts.
#
# The subject is the *transcript of a differential probe*: each probe is a C
# program that exercises one runtime subsystem and prints one `key=value`
# observation per line. The same probe source is compiled twice — once against
# the admitted authority's headers and library, once against the candidate's —
# and the two transcripts are what FRF compares.
#
# The probe list is the fixture, and it is load-bearing: it selects which staged
# binaries run. That also means the court can be challenged (FRF needs a
# `{fixture}` reference to locate its mutant target; docs/DECISIONS.md D13).
#
# The binaries are pre-staged by `forensics/tools/phase3_courts.py` (the court
# container has a compiler; this tooling container does not).
#
# Two deliberate environment choices:
#
#   1. `LD_LIBRARY_PATH` binds the authority's own `libcrypto.so.3` — but only
#      for the probe invocation, never for the script as a whole. Debian's
#      `sha256sum` links libcrypto, so an exported `LD_LIBRARY_PATH` would make
#      the harness's own digest tool load the library under test. Measured the
#      hard way: with the binding exported, `sha256sum` aborted on the
#      candidate's scaffolded `SHA256_Init`, which is a true statement about the
#      candidate but not one this harness should be making.
#   2. the first stdout line is a digest of the whole transcript. FRF's
#      `stdout` observable is extracted as `stdout-first-line`, so the first line
#      is what the claim covers; making it a digest of every observation makes
#      the claimed axis cover the entire transcript. Nothing is discarded: the
#      transcript itself follows, so the raw capture is complete and readable.
#      This is a harness choice, not a normalizer, and it is computed identically
#      on both sides.
set -eu
LIST="${1:?usage: authority-runtime-probe.sh <probe-list>}"

PREFIX=/work/forensics/authorities/prefix/openssl-3.6.4-production
PROBES=/work/artifacts/phase3/probes

status=0
while IFS= read -r name; do
    [ -n "$name" ] || continue
    case "$name" in \#*) continue ;; esac
    if [ ! -x "$PROBES/$name.authority" ]; then
        printf 'openssl-rs: no staged authority probe %s\n' "$name" >&2
        exit 2
    fi
    transcript=$(OPENSSL_CONF=/dev/null TZ=UTC LC_ALL=C \
        LD_LIBRARY_PATH="$PREFIX/lib" "$PROBES/$name.authority") || status=$?
    printf 'transcript.sha256=%s\n' "$(printf '%s' "$transcript" | sha256sum | cut -d' ' -f1)"
    printf '%s\n' "$transcript"
done < "$LIST"
exit "$status"
