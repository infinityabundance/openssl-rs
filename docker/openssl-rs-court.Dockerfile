# syntax=docker/dockerfile:1
#
# openssl-rs-court:1 — the openssl-rs forensic court VM
# =====================================================
#
# A minimal, isolated, resource-capped execution environment for openssl-rs
# courts. Every test, court and fuzz campaign runs here; nothing is executed on
# the host.
#
# Design constraints (see docs/AUTHORITY_POLICY.md):
#
#   1. The base image is pinned by digest, not by tag.
#   2. Debian's libssl-dev / openssl packages are DELIBERATELY excluded. The
#      distribution OpenSSL on bookworm is 3.0.x, which is NOT an admitted
#      authority. All authorities are acquired from upstream and built inside
#      the court, content-addressed (forensics/tools/authority_acquire.py).
#   3. Even so, a non-authority OpenSSL runtime is unavoidable in a Debian
#      userspace: libcurl4 (needed for curl and git) links libssl3 3.0.x. We
#      therefore:
#        - delete the non-authority `openssl` CLI binaries so they cannot be
#          invoked by accident, and assert with `! command -v openssl` that they
#          are gone. We do NOT purge the package: ca-certificates Depends on
#          openssl (for `openssl rehash` in its dpkg trigger), so purging would
#          also remove the trust store and break HTTPS acquisition. The package
#          stays "installed" to dpkg; only its executables are removed.
#        - treat the remaining libssl3/libcrypto3 shared objects as a KNOWN
#          CONTAMINANT and make courts prove non-contamination explicitly
#          (courts/libcrypto-contamination). A produced artifact that resolves
#          against a non-authority libcrypto/libssl is a hard failure.
#   4. OOM protection is applied at `docker run` time (docker/openssl-rs-court.sh),
#      not baked into the image: memory, memory-swap, pids-limit, cpus.
#
# The image is intentionally boring: compilers, binutils, python3, perl and a
# Rust toolchain. No network services, no credentials, no host state.

FROM debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

# --- base toolchain -----------------------------------------------------------
# build-essential/perl/make : building OpenSSL authorities from source
# clang/lld                 : AST and header archaeology (Phase 1), and Phase 22's
#                             shadow per-TU analysis over the captured compile commands
# binutils                  : nm/readelf/objdump symbol and ABI archaeology
# python3                   : atlas generators and court harnesses
# curl/ca-certificates/xz   : authority acquisition
# file / bsdmainutils       : human- and machine-readable artifact inspection
# doxygen                   : Phase 22.2's entity-graph oracle. Doxygen is an
#                             *instrument*, not the authority: `docs/PHASE-22-SUBPHASES.md`
#                             section 6 makes the POD manual canonical for public APIs and
#                             the Doxygen block a navigation aid, and Doxygen absence must
#                             never be read as surface absence. Graphviz is deliberately
#                             NOT installed: Doxygen's HTML call graphs are for a human,
#                             while 22.3's Clang AST and 22.6's relocations are the
#                             machine-readable edge oracles, so the image stays minimal.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      clang \
      lld \
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
      doxygen \
 && rm -rf /var/lib/apt/lists/* \
 # Neutralise the non-authority OpenSSL CLI without purging the package
 # (see design note 3 above).
 && rm -f /usr/bin/openssl /usr/bin/c_rehash \
 # Hard assertion: no non-authority openssl binary remains on PATH.
 && ! command -v openssl \
 # Record the unavoidable non-authority runtime contaminant for the record.
 && { mkdir -p /court; \
      { echo "non_authority_openssl_shared_objects:"; \
        for f in /lib/x86_64-linux-gnu/libssl.so.3 /lib/x86_64-linux-gnu/libcrypto.so.3; do \
          if [ -e "$f" ]; then echo "  $(readlink -f "$f") sha256=$(sha256sum "$f" | cut -d' ' -f1)"; fi; \
        done; \
        echo "note: libssl3/libcrypto3 are present transitively via libcurl4 and are a KNOWN CONTAMINANT; courts must prove non-contamination."; \
      } > /court/non-authority-openssl.txt; }

# --- Rust toolchain -----------------------------------------------------------
# Installed via rustup into /usr/local. **The toolchain is the version
# `rust-toolchain.toml` pins, installed here rather than left to be auto-installed on the
# first `cargo` invocation.** The image used to install `stable` and rely on rustup's
# override, which meant the pinned toolchain arrived at run time: on a fresh container it
# auto-installed an incomplete 1.98.1 (rustc, rustdoc, rustfmt, clippy-driver and cargo-fmt,
# with no `cargo` binary) and every `cargo` command failed with "the 'cargo' binary ... is not
# applicable to the '1.98.1' toolchain" until the toolchain was reinstalled by hand. A court
# image whose toolchain is assembled by accident is not reproducible, so the pin is installed
# explicitly here and `cargo --version` is asserted at build time.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.98.1 \
 && rustup component add rustfmt clippy --toolchain 1.98.1 \
 && cargo --version && rustc --version

# --- court conventions --------------------------------------------------------
# /work is the bind mount of the repository. /court is scratch space inside the
# container, always discarded with the container.
#
# `safe.directory /work`: the repository is bind-mounted from the host and is owned
# by the developer's uid, while courts run as root, so git refuses to read it with
# "detected dubious ownership". That is configured **here**, system-wide, rather than
# by a hand-run `git config` in a live container: a court whose ability to read
# `origin/main` depends on somebody having typed a command into the box is not
# reproducible. The mount point is fixed by docker/openssl-rs-court.sh, so this is a
# constant, not an assumption about the host's username.
RUN git config --system --add safe.directory /work
WORKDIR /work

COPY openssl-rs-court-entrypoint.sh /usr/local/bin/openssl-rs-court-entrypoint.sh
RUN chmod +x /usr/local/bin/openssl-rs-court-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/openssl-rs-court-entrypoint.sh"]
CMD ["sleep", "infinity"]
