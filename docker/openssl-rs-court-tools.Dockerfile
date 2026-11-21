# syntax=docker/dockerfile:1
#
# openssl-rs-court-tools:1 — the court image with the timing instruments baked in
# =============================================================================
#
# WHY THIS IMAGE EXISTS. The timing-analysis instruments (valgrind/ctgrind, perf,
# dudect, BINSEC, TIMECOP's poison.h) were installed by hand into a *running*
# `openssl-rs-court:1` container and lived in its writable layer. The court is
# disposable by design — `docker/openssl-rs-court.sh down` removes the container and
# its /court scratch space (which is where the BINSEC opam root was) — so every
# recreation discarded the whole toolchain, and the inventory could only record
# "EPHEMERAL". This image is that toolchain as a layer, so a rebuilt court is warm.
#
# SCOPE. It is a SEPARATE tag and is never selected implicitly: the default image for
# `openssl-rs-court.sh` stays the minimal `openssl-rs-court:1`, so conversion gates,
# forensic regeneration and the OOM-bounded Rust test loop are byte-for-byte
# unchanged. Timing-instrument runs opt in with
# `OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1`. It inherits everything the base
# image asserts (no system `openssl` CLI, pinned Rust toolchain, libssl3 disclosed as
# a known contaminant) and adds no credentials, services or host state.
#
# BUILD. `docker/openssl-rs-court.sh build-tools`, which is
#   docker build -f docker/openssl-rs-court-tools.Dockerfile \
#     --build-arg BASE_IMAGE=openssl-rs-court:1 -t openssl-rs-court-tools:1 docker/
#
# The install itself lives in openssl-rs-court-tools-install.sh, which is copied into
# the image at /opt/timing-tools/install.sh: the image carries the exact commands that
# built it, and the opam switch is pinned by the recorded
# `opam switch export --full --freeze` file next to it (package versions, archive URLs
# and checksums all embedded, so the installed set does not come from the solver).
#
# MEASUREMENT IS STILL A RUN-TIME PROPERTY. Installing `perf` grants nothing: the
# kernel decides. perf_event_open(2) needs CAP_PERFMON in the container (docker's
# default capability set excludes it) and, for kernel-inclusive events,
# perf_event_paranoid <= 1. The capability is added at `docker run` time by
# docker/openssl-rs-court.sh (OPENSSL_RS_COURT_CAP_PERFMON, default on) and is printed
# by `status`; the image deliberately does not and cannot grant it.

ARG BASE_IMAGE=openssl-rs-court:1
FROM ${BASE_IMAGE}
# Re-declared after FROM: an ARG used before the first FROM is only in scope for
# FROM lines, so without this the value is empty in RUN.
ARG BASE_IMAGE=openssl-rs-court:1

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC \
    OPAMROOT=/opt/opam \
    OPAMYES=1 \
    OPAMJOBS=4 \
    OPAMCOLOR=never \
    PATH=/opt/opam/4.14.2/bin:/opt/dudect:${PATH}

COPY openssl-rs-court-tools-install.sh /opt/timing-tools/install.sh
COPY openssl-rs-court-tools.opam-switch.export /opt/timing-tools/opam-switch.export

# One layer: apt pins, the pinned dudect checkout, and the opam switch imported from
# the recorded export. The script verifies every pin and the exact installed opam set,
# so a drifted build fails here instead of producing a court whose instrument identity
# differs from the recorded one.
RUN BASE_IMAGE="${BASE_IMAGE}" bash /opt/timing-tools/install.sh

# Build-time assertion that the instruments are reachable on the default PATH, and
# that the non-authority OpenSSL CLI is still absent (inherited from the base image).
RUN valgrind --version \
 && perf --version \
 && binsec -version \
 && test -x /opt/dudect/dudect_donnabad_O2 \
 && ! command -v openssl
