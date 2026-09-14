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
# clang                     : AST and header archaeology (Phase 1)
# binutils                  : nm/readelf/objdump symbol and ABI archaeology
# python3                   : atlas generators and court harnesses
# curl/ca-certificates/xz   : authority acquisition
# file / bsdmainutils       : human- and machine-readable artifact inspection
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
# Installed via rustup into /usr/local. The exact toolchain is pinned by
# rust-toolchain.toml in the repository; rustup honours it when cargo runs.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable \
 && rustup component add rustfmt clippy \
 && rustc --version && cargo --version

# --- court conventions --------------------------------------------------------
# /work is the bind mount of the repository. /court is scratch space inside the
# container, always discarded with the container.
WORKDIR /work

COPY openssl-rs-court-entrypoint.sh /usr/local/bin/openssl-rs-court-entrypoint.sh
RUN chmod +x /usr/local/bin/openssl-rs-court-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/openssl-rs-court-entrypoint.sh"]
CMD ["sleep", "infinity"]
