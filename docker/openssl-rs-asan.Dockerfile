# syntax=docker/dockerfile:1
#
# openssl-rs-asan:1 — the sanitizer execution environment
# =======================================================
#
# A dedicated, resource-capped container for AddressSanitizer (and only ASan;
# TSan/UBSan/MSan are a later step) runs over the *candidate*. It exists because
# the forensic court's OOM protection sets a hard 4 GiB per-process RLIMIT_DATA
# in every `exec` (docker/openssl-rs-court.sh, OPENSSL_RS_COURT_DATA), and ASan
# reserves a ~15.4 TB sparse virtual shadow before it tests anything:
#
#     AddressSanitizer failed to allocate 0xdfff0001000 (15392894357504) bytes
#     ... ReserveShadowMemoryRange failed while trying to map 0xdfff0001000 bytes.
#
# That limit is *kept* for hostile courts — it is what keeps a runaway court off
# the host, and it is enforced by forensics/tools/require_court.sh and recorded
# in docs/DECISIONS.md D105 — so ASan gets its own venue instead. See
# docs/UNSAFE.md §4 and artifacts/phase18/asan.json.
#
# The envelope is deliberately NOT weaker than the court's in any dimension that
# bounds *real* resources (docs/AUTHORITY_POLICY.md, docs/REPRODUCIBILITY.md):
#
#   * the container cgroup still caps physical memory (docker/openssl-rs-asan.sh,
#     --memory / --memory-swap), PIDs, CPU and wall clock;
#   * no-new-privileges is kept, exactly as the court keeps it;
#   * the network policy is the court's (the default bridge; no extra grants);
#   * only the per-process RLIMIT_DATA is absent, because ASan's shadow is
#     PROT_NONE and MAP_NORESERVE virtual address space that the cgroup does not
#     count against memory.current. Removing RLIMIT_DATA does not let a runaway
#     process allocate more *resident* memory; the cgroup ceiling still does.
#
# Design constraints:
#
#   1. The base image is pinned by digest, and it is the *same* Debian digest the
#      court pins, so the glibc the sanitizer artifacts link against is the glibc
#      the court's candidate is built against.
#   2. The Rust toolchain is a **pinned nightly**, separate from the product
#      MSRV / toolchain (rust-toolchain.toml pins 1.98.1). Sanitizers require a
#      nightly; a sanitizer build must never move the product's pin. The exact
#      resolved `rustc --version` is recorded in the container toolchain receipt
#      and in the evidence.
#   3. Clang/LLVM and `llvm-symbolizer` are installed so ASan reports resolve to
#      file:line rather than raw addresses. The probes and the canary are built
#      with clang; the Rust side is built by rustc with `-Zsanitizer=address`.
#   4. The distribution `openssl` CLI is neutralised and asserted absent, exactly
#      as the court does, so a sanitizer probe cannot accidentally resolve against
#      a non-authority runtime.
#
# The image is intentionally boring: a C/Rust sanitizer toolchain, python3 and
# binutils. No network services, no credentials, no host state.

FROM debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

# --- sanitizer toolchain ------------------------------------------------------
# clang/lld        : C compilation/linking of the probes, the canary and the
#                    first-party C adapters, all with -fsanitize=address
# libclang-rt-*-dev: clang's compiler-rt sanitizer runtime
#                    (libclang_rt.asan-x86_64.a). Debian ships it separately from
#                    clang, and without it every ASan link fails with "cannot find
#                    libclang_rt.asan-x86_64.a".
# llvm             : llvm-symbolizer, so an ASan report names file:line
# binutils         : nm/readelf/objdump, used by the instrumentation-closure
#                    receipt to prove every linked object is instrumented
# build-essential  : libc headers, `make`, and gcc as a fallback
# python3/perl     : harness; zlib1g-dev for the crate's optional zlib surface
# curl/ca-certs/xz : the pinned nightly toolchain
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      clang \
      libclang-rt-dev \
      lld \
      llvm \
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
 # Neutralise the non-authority OpenSSL CLI without purging the package.
 && rm -f /usr/bin/openssl /usr/bin/c_rehash \
 # Hard assertion: no non-authority openssl binary remains on PATH.
 && ! command -v openssl \
 # Hard assertion: the symbolizer the ASan reports depend on is on PATH.
 && command -v llvm-symbolizer

# --- Rust sanitizer toolchain (pinned nightly) --------------------------------
# Installed explicitly and pinned by date, so it cannot drift with `nightly`.
# `rust-src` is required for `-Zbuild-std`, which is how the standard library is
# rebuilt under ASan and the instrumentation is closed over `std` rather than
# only over the crate. The product toolchain (`rust-toolchain.toml`, 1.98.1) is
# deliberately NOT installed here: this venue runs `cargo +${ASAN_NIGHTLY}`, so a
# sanitizer run can never move the product pin.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ARG ASAN_NIGHTLY=nightly-2026-10-05
ENV ASAN_NIGHTLY=${ASAN_NIGHTLY}
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${ASAN_NIGHTLY}" \
 && rustup component add rust-src --toolchain "${ASAN_NIGHTLY}" \
 && rustup component add rustfmt clippy --toolchain "${ASAN_NIGHTLY}" \
 && cargo +"${ASAN_NIGHTLY}" --version \
 && rustc +"${ASAN_NIGHTLY}" --version \
 && clang --version | head -1 \
 && llvm-symbolizer --version | head -1

# --- venue conventions --------------------------------------------------------
# /work is the bind mount of the repository; /asan is scratch space inside the
# container, always discarded with the container, so an ASan build never reuses
# host-written artifacts and never writes its own into the candidate's `target/`.
#
# `safe.directory /work`: the repository is bind-mounted from the host and owned
# by the developer's uid, while this container runs as root, so git would refuse
# to read it with "detected dubious ownership". Configured here, system-wide, so
# the ability to read the repo does not depend on a hand-run command.
RUN git config --system --add safe.directory /work \
 && mkdir -p /asan
WORKDIR /work

COPY openssl-rs-asan-entrypoint.sh /usr/local/bin/openssl-rs-asan-entrypoint.sh
RUN chmod +x /usr/local/bin/openssl-rs-asan-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/openssl-rs-asan-entrypoint.sh"]
CMD ["sleep", "infinity"]
