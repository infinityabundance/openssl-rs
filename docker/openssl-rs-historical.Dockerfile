# syntax=docker/dockerfile:1
#
# openssl-rs-historical:1 — the historical-authority build venue
# ===============================================================
#
# A dedicated, separately pinned execution environment for acquiring and building
# **historical** OpenSSL releases (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2,
# subphase 23.2). It exists for one reason and is kept apart for one reason:
#
#   * the forensic court (`docker/openssl-rs-court.Dockerfile`) is pinned by digest and
#     its toolchain is recorded in receipts, so changing it would invalidate the
#     evidence it has already recorded. Building a release the court's modern compiler
#     rejects must not require that change.
#   * the historical lineage reaches back to releases whose era predates the court's
#     toolchain. The court pins Debian bookworm / GCC 12 / Perl 5.36; this venue pins an
#     **older** userspace (Debian bullseye / GCC 10 / Perl 5.32), so a release can be built
#     with an era-appropriate toolchain without moving the court's pin.
#
# QEMU user-mode is deliberately **not** installed here: the emulator set (qemu-user-static)
# is large, and on the landing host the docker storage layer is a shared, nearly-full tmpfs;
# the historical build this venue actually performs is native x86_64 and needs no emulation.
# A future foreign-architecture build adds qemu-user-static in a venue host that can hold it,
# rather than weakening this pin.
#
# Design constraints (the court's, applied to a separate image):
#
#   1. The base image is pinned by digest, not by tag. It is deliberately *not* the
#      court's digest: this venue may move independently, and a historical build is
#      never candidate evidence about the court's own platform.
#   2. The distribution `openssl` CLI is neutralised and asserted absent, exactly as the
#      court does, so a historical build cannot accidentally resolve against a
#      non-authority runtime.
#   3. OOM protection is applied at `docker run` time (docker/openssl-rs-historical.sh),
#      not baked into the image: memory, memory-swap, pids-limit, cpus, --restart=no and
#      no-new-privileges, over the same shared budget guard the other venues source.
#
# The image is intentionally boring: a C toolchain, perl, python3, binutils and QEMU
# user-mode. No network services, no credentials, no host state.

FROM debian@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

# --- base toolchain -----------------------------------------------------------
# build-essential/perl/make : building an old OpenSSL from source. Bullseye's gcc is
#                             GCC 10 and its perl is 5.32 — both older than the court's
#                             GCC 12 / Perl 5.36, so a release the modern compiler
#                             rejects has an era-appropriate toolchain here.
# binutils                  : nm/readelf/objdump over the produced DSOs
# python3                   : the acquisition/build harness
# curl/ca-certificates/xz   : authority acquisition
# Debian bullseye is EOL: its packages have moved off the live mirror to the Debian
# archive. Point apt at the archive and disable the Release-Valid-Until check (the
# archive's Release files are intentionally expired), so the older toolchain stays
# reproducibly installable instead of 404ing against a mirror that no longer carries it.
RUN printf 'deb http://archive.debian.org/debian bullseye main\n' > /etc/apt/sources.list \
 && printf 'deb http://archive.debian.org/debian-security bullseye-security main\n' >> /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      gcc \
      binutils \
      python3 \
      perl \
      make \
      pkg-config \
      curl \
      ca-certificates \
      git \
      xz-utils \
      zlib1g-dev \
      file \
      bsdmainutils \
      less \
 && rm -rf /var/lib/apt/lists/* \
 # Neutralise the non-authority OpenSSL CLI without purging the package (see the
 # court's design note): only its executables are removed, so the trust store stays.
 && rm -f /usr/bin/openssl /usr/bin/c_rehash \
 # Hard assertion: no non-authority openssl binary remains on PATH.
 && ! command -v openssl \
 # Record the venue's toolchain for the build receipts that cite it.
 && { mkdir -p /historical; \
      { echo "venue=openssl-rs-historical"; \
        echo "historical_toolchain:"; \
        echo "  cc=$(cc --version 2>/dev/null | head -1)"; \
        echo "  gcc=$(gcc --version 2>/dev/null | head -1)"; \
        echo "  ld=$(ld --version 2>/dev/null | head -1)"; \
        echo "  make=$(make --version 2>/dev/null | head -1)"; \
        echo "  perl=$(perl -e 'print \$]' 2>/dev/null)"; \
        echo "  python=$(python3 --version 2>/dev/null)"; \
      } > /historical/toolchain.txt; }

# --- venue conventions --------------------------------------------------------
# /work is the bind mount of the repository; /historical is scratch space inside the
# container, always discarded with the container.
#
# `safe.directory /work`: the repository is bind-mounted from the host and owned by the
# developer's uid, while this venue runs as root, so git refuses to read it with
# "detected dubious ownership". Configured here, system-wide, so the ability to read the
# repo does not depend on a hand-run command.
RUN git config --system --add safe.directory /work
WORKDIR /work

COPY openssl-rs-historical-entrypoint.sh /usr/local/bin/openssl-rs-historical-entrypoint.sh
RUN chmod +x /usr/local/bin/openssl-rs-historical-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/openssl-rs-historical-entrypoint.sh"]
CMD ["sleep", "infinity"]
