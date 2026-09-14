#!/bin/sh
# openssl-rs — court-only probe runner.
#
#   court/run_probe.sh <name> [authority|candidate|both]
#
# Compiles courts/phase4/<name>.c against the authority and/or the candidate
# distribution shell and prints the transcript. This is the archaeology loop:
# run against the authority first, read what it actually does, then implement.
#
# Nothing runs on the host: this script refuses unless it is inside the court
# container (forensics/tools/require_court.sh), because it executes candidate code.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

name="${1:?usage: run_probe.sh <name> [authority|candidate|both]}"
side="${2:-both}"

AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production
SRC=/work/courts/phase4/${name}.c

[ -f "$SRC" ] || { echo "no such probe: $SRC" >&2; exit 2; }

build_and_run() {
  which="$1"
  if [ "$which" = authority ]; then
    inc="$AUTH/include"; lib="$AUTH/lib"
  else
    inc=/work/artifacts/phase2/include; lib=/work/artifacts/phase2
  fi
  bin=/court/${name}.${which}
  if ! clang -std=c11 -O1 -D_GNU_SOURCE -I "$inc" -o "$bin" "$SRC" \
       -L "$lib" -lcrypto -Wl,-rpath,"$lib" -lpthread -ldl -lm -lrt -lutil 2>/tmp/${name}.${which}.cc; then
    echo "=== ${which}: COMPILE FAILED ==="
    sed -n '1,12p' /tmp/${name}.${which}.cc
    return 1
  fi
  echo "=== ${which} transcript ==="
  set +e
  timeout 60 "$bin"
  rc=$?
  set -e
  echo "=== ${which} exit=${rc} ==="
}

case "$side" in
  authority) build_and_run authority ;;
  candidate) build_and_run candidate ;;
  both)
    build_and_run authority || true
    build_and_run candidate || true
    ;;
  *) echo "unknown side: $side" >&2; exit 2 ;;
esac
