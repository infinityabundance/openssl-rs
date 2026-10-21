# syntax=docker/dockerfile:1
#
# openssl-rs-court-expand:1 — L7 cohort *expansion* image
# ======================================================
#
# SCOPE. This image exists only to unblock the downstream-family expansion
# (33 -> 100 -> 1000). It is NOT the conversion image and must never be used for
# conversion gates, forensic regeneration or the OOM-bounded Rust test loop: those
# keep using the minimal `openssl-rs-court:1` built from
# `openssl-rs-court.Dockerfile`. The minimal image is untouched by this file.
#
# Why a separate image: five cohort candidates fail at *configure* time because the
# minimal image has no cmake/ninja/meson and no dev headers or .pc files for
# library dependencies that are unrelated to the OpenSSL candidate:
#
#   libjwt 2.1.3   -> needs jansson >= 2.0   (autoconf)
#   jose           -> needs jansson >= 2.10  (meson)
#   libzip 1.11.1  -> CMake-only, no configure script
#   libfido2 1.15.0-> CMake-only, no configure script
#   apr-util       -> APR could not be located (no libapr-1.pc)
#
# Deliberately NOT installed, for the same reason as the minimal image:
#   * libssl-dev / openssl — the subject OpenSSL is the candidate at
#     /work/artifacts/phase2/install; a distribution libssl-dev would let a
#     configure step silently bind a non-authority OpenSSL. Consumers must be
#     pointed at the subject prefix (CPPFLAGS/LDFLAGS/PKG_CONFIG_PATH) instead.
#     apt resolves no libssl-dev here; only the already-recorded libssl3 runtime
#     contaminant is pulled transitively, so /court/non-authority-openssl.txt
#     from the base image remains the complete disclosure.
#   * compilers/autotools/curl/git/python3/perl — inherited from the base image.
#
# Versions are pinned exactly (bookworm main/security as resolved at build time)
# and installed in a single layer; a pin that drifts is a build failure rather
# than a silent toolchain change. No network services, no credentials, no host
# state. Resource caps are applied at `docker run` time by
# docker/openssl-rs-court.sh, exactly as for the minimal image.
#
# Consumer recipes verified against this image (2026-10-21, libjwt 2.1.3):
#   * The subject prefix /work/artifacts/phase2/install ships libssl.pc and
#     libcrypto.pc but NOT openssl.pc, so autoconf consumers that do
#     PKG_CHECK_MODULES([OPENSSL], [openssl >= ...]) fail with "no crypto library
#     detected". A prefix shim .pc (Name: OpenSSL, Libs: -L${prefix}/lib -lssl
#     -lcrypto) on PKG_CONFIG_PATH, plus -Wl,-rpath=<prefix>/lib, is the recipe.
#     Setting OPENSSL_CFLAGS/OPENSSL_LIBS instead skips pkg.m4's action block and
#     libjwt then dies with "conditional HAVE_GNUTLS was never defined".
#   * libjwt 2.1.3 additionally needs --without-gnutls when gnutls is absent: its
#     configure.ac only defines the HAVE_GNUTLS conditional in the branches, not
#     when the automatic probe fails.
# The image deliberately does not encode either workaround; family harnesses do.

ARG BASE_IMAGE=openssl-rs-court:1
FROM ${BASE_IMAGE}
# Re-declared after FROM: an ARG used before the first FROM is only in scope for
# FROM lines, so without this the value is empty in RUN.
ARG BASE_IMAGE=openssl-rs-court:1

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

# --- expansion toolchain + dependency dev packages ---------------------------
# cmake / ninja-build / meson : CMake-only and meson-only upstreams
# libjansson-dev              : libjwt (>=2.0), jose (>=2.10) JSON backend
# libcbor-dev                 : libfido2 CBOR backend
# libapr1-dev/libaprutil1-dev : apr-util (provides apr-1.pc / apr-util-1.pc)
# zlib1g-dev / libbz2-dev / liblzma-dev : libzip compression backends
#   (zlib1g-dev is already in the base image; naming it keeps the set complete
#    and the pin explicit)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      cmake=3.25.1-1 \
      ninja-build=1.11.1-2~deb12u1 \
      meson=1.0.1-5 \
      pkg-config=1.8.1-1 \
      libjansson-dev=2.14-2 \
      libcbor-dev=0.8.0-2+b1 \
      libapr1-dev=1.7.2-3+deb12u1 \
      libaprutil1-dev=1.6.3-1+deb12u1 \
      zlib1g-dev=1:1.2.13.dfsg-1 \
      libbz2-dev=1.0.8-5+b1 \
      liblzma-dev=5.4.1-1+deb12u2 \
 && rm -rf /var/lib/apt/lists/* \
 # Build-time assertions: the image must fail to build if the toolchain or the
 # .pc files it exists to provide are missing. Kept to the declared purpose.
 && cmake --version \
 && meson --version \
 && ninja --version \
 && pkg-config --exists jansson apr-1 apr-util-1 libcbor zlib \
 && ! command -v openssl \
 # Record what this image adds, so a receipt can identify the venue. The base
 # entrypoint appends /court/non-authority-openssl.txt to /court/toolchain.txt;
 # this marker sits alongside it.
 && { mkdir -p /court; \
      { echo "court_variant=expand"; \
        echo "purpose=downstream-family-expansion (NOT conversion gates)"; \
        echo "base_image=${BASE_IMAGE}"; \
        echo "cmake=$(cmake --version | head -1)"; \
        echo "ninja=$(ninja --version)"; \
        echo "meson=$(meson --version)"; \
        echo "pkg-config_modules: jansson apr-1 apr-util-1 libcbor zlib"; \
      } > /court/expansion-image.txt; }
