#!/usr/bin/env bash
# openssl-rs — refuse to run outside the court container.
#
# `docs/REPRODUCIBILITY.md` §1 says nothing runs on the host. That is a claim
# about practice, and claims about practice decay under pressure: the host has a
# full toolchain, and the repository is bind-mounted into the court, so a
# mistyped command would look like it worked.
#
# This file turns the claim into a fact. Build and court entry points source it
# and abort unless they are demonstrably inside a container. The check is
# deliberately unconditional and unoverridable -- there is no "just this once"
# escape hatch, because that is exactly how host execution starts.
#
# The marker is `/.dockerenv`, created by the container runtime and absent on the
# host. Note that repository files written inside the court still appear on the
# host through the bind mount; that is intended, because it is how evidence
# persists. It is *execution* on the host that is forbidden, and that is what
# this guard prevents.

if [ ! -f /.dockerenv ]; then
  cat >&2 <<'EOF'
REFUSED: openssl-rs tooling must run inside the court container.

  Nothing executes on the host -- not a build, not a test, not a probe, not the
  `openssl` CLI. See docs/REPRODUCIBILITY.md §1.

  Run it through the venue instead, from the repository root:

    bash docker/openssl-rs-court.sh exec bash <script...>          # forensic court
    bash docker/openssl-rs-frf-court.sh exec bash <script...>      # FRF/Gemel court
EOF
  exit 97
fi
