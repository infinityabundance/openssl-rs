#!/usr/bin/env bash
# openssl-rs — timing-tools layer for the court image.
#
# Runs inside docker/openssl-rs-court-tools.Dockerfile, i.e. ONCE, at image build
# time, on top of the minimal court image. Its whole purpose is that the timing
# instruments stop living in a container's writable layer: `docker/openssl-rs-court.sh
# down` used to destroy valgrind/ctgrind/dudect/BINSEC/TIMECOP (and /court/opam with
# them), because they were installed by hand into a running container. Here the same
# installs are baked into a layer, so a court recreated from
# `openssl-rs-court-tools:1` starts warm.
#
# The commands are kept in this file — copied into the image at
# /opt/timing-tools/install.sh — so that the image itself carries the exact recipe it
# was built from, not only the Dockerfile that happened to invoke it.
#
# Determinism:
#   * apt packages are pinned to exact Debian (bookworm) versions and re-verified with
#     dpkg-query after the install; an unavailable pin is a build failure, never a
#     silent toolchain change.
#   * dudect is pinned to a commit and the checkout is asserted before and after build.
#   * the opam switch is installed from a `opam switch export --full --freeze` file
#     (openssl-rs-court-tools.opam-switch.export) which embeds every package
#     definition with its archive URL and checksum, so the package set does not come
#     from the solver. The installed set is then diffed against that file's
#     `installed:` list; any drift fails the build and is reported rather than
#     papered over.
#
# Nothing here is a source of safety evidence: it makes instruments available. The
# instrument validations live in evidence/timing-tools-inventory.json.
set -euo pipefail

BASE_IMAGE="${BASE_IMAGE:-openssl-rs-court:1}"
DUDECT_COMMIT="dc269651fb2567e46755cfb2a13d3875592968b5"
DUDECT_URL="https://github.com/oreparaz/dudect.git"
OPAM_SWITCH="4.14.2"
TOOLS_DIR="/opt/timing-tools"
EXPORT="${TOOLS_DIR}/opam-switch.export"

export DEBIAN_FRONTEND=noninteractive
export OPAMROOT="${OPAMROOT:-/opt/opam}"
export OPAMYES=1
export OPAMJOBS="${OPAMJOBS:-4}"
export OPAMCOLOR=never

say() { printf 'openssl-rs-court-tools: %s\n' "$*"; }

# --- apt: the instrument packages, pinned -------------------------------------
# valgrind        memcheck (the ctgrind/TIMECOP vehicle) and scripts/plugins;
#                 it also ships /usr/include/valgrind/{valgrind,memcheck}.h, which is
#                 what the ctgrind and TIMECOP techniques actually need — there is no
#                 separate "-dev" package and no patched valgrind fork is built.
# linux-perf      the `perf` binary. Installing it does not by itself permit
#                 measurement: perf_event_open(2) is gated by the container's
#                 capability set (see OPENSSL_RS_COURT_CAP_PERFMON in
#                 docker/openssl-rs-court.sh) and by /proc/sys/kernel/perf_event_paranoid.
# opam, bubblewrap, patch, m4, pkg-config, unzip, rsync, libgmp-dev
#                 BINSEC's OCaml toolchain prerequisites (libgmp-dev also satisfies
#                 the zarith dependency).
# gcc/clang and their build deps are inherited from the base court image; they are
# asserted below rather than reinstalled.
APT_PINS="valgrind=1:3.19.0-1 linux-perf=6.1.192-2 opam=2.1.2-1+deb12u2 \
bubblewrap=0.8.0-2+deb12u1 patch=2.7.6-7 m4=1.4.19-3 pkg-config=1.8.1-1 \
unzip=6.0-28+deb12u1 rsync=3.5.0+ds1-0+deb12u1 libgmp-dev=2:6.2.1+dfsg1-1.1"

say "apt-get update (http://deb.debian.org/debian bookworm main + bookworm-security)"
apt-get update -qq
say "installing pinned packages: ${APT_PINS}"
# shellcheck disable=SC2086  # word splitting of APT_PINS is intended
apt-get install -y --no-install-recommends ${APT_PINS}
rm -rf /var/lib/apt/lists/*

# A pin that apt satisfied with a different version would be a silent toolchain
# change; verify what is actually installed, not what was requested.
for pin in ${APT_PINS}; do
  pkg="${pin%%=*}"
  want="${pin#*=}"
  got="$(dpkg-query -W -f='${Version}' "${pkg}")"
  if [ "${got}" != "${want}" ]; then
    echo "openssl-rs-court-tools: FATAL: ${pkg} is ${got}, pinned ${want}" >&2
    exit 1
  fi
done

# The instruments' own presence/versions, and the ctgrind/TIMECOP headers.
valgrind --version
test -f /usr/include/valgrind/valgrind.h
test -f /usr/include/valgrind/memcheck.h
perf --version
cc --version | head -1
c++ --version | head -1
clang --version | head -1

# --- dudect: pinned commit, built once -----------------------------------------
say "git clone ${DUDECT_URL} (commit ${DUDECT_COMMIT}) -> /opt/dudect"
git clone "${DUDECT_URL}" /opt/dudect
git -C /opt/dudect checkout --detach "${DUDECT_COMMIT}"
got_commit="$(git -C /opt/dudect rev-parse HEAD)"
if [ "${got_commit}" != "${DUDECT_COMMIT}" ]; then
  echo "openssl-rs-court-tools: FATAL: dudect HEAD is ${got_commit}, pinned ${DUDECT_COMMIT}" >&2
  exit 1
fi
git -C /opt/dudect rev-parse HEAD > /opt/dudect/COMMIT
# dut_simple is the memcmp example (negative/non-detection case) and dut_donnabad is
# upstream's deliberately leaky curve25519 (positive control). Both are the binaries
# the inventory's dudect row validates.
make -C /opt/dudect dut_simple dut_donnabad
test -x /opt/dudect/dudect_simple_O0
test -x /opt/dudect/dudect_simple_O2
test -x /opt/dudect/dudect_donnabad_O2

# --- BINSEC via opam: pinned by the recorded switch export ----------------------
say "opam init (bare, sandboxing disabled) with OPAMROOT=${OPAMROOT}"
opam init --bare --disable-sandboxing -n
# The compiler package comes from the opam repository index at build time; the
# package *set* below is pinned by the embedded export. If the index ever stops
# offering ocaml-base-compiler 4.14.2, this step fails loudly and the image is not
# produced — that is the intended outcome, not a fallback.
say "opam switch create ${OPAM_SWITCH} ocaml-base-compiler.${OPAM_SWITCH} --jobs=${OPAMJOBS}"
opam switch create "${OPAM_SWITCH}" "ocaml-base-compiler.${OPAM_SWITCH}" --jobs="${OPAMJOBS}"
say "opam switch import ${EXPORT} (versions, URLs and checksums embedded)"
opam switch import --switch "${OPAM_SWITCH}" "${EXPORT}"

# The installed set must equal the exported set exactly: same packages, same
# versions. Anything else means the import drifted and BINSEC's identity is not the
# one recorded in evidence/timing-tools-inventory.json.
awk '/^installed: \[/{f=1; next} f && /^\]/{f=0}
     f { line=$0; gsub(/[",]/, "", line); gsub(/^ +| +$/, "", line);
         if (line != "") print line }' "${EXPORT}" | sort > /tmp/opam-want.txt
opam list --safe --installed --columns=name,version \
  | grep -v '^#' | awk 'NF == 2 { print $1 "." $2 }' | sort > /tmp/opam-got.txt
if ! diff -u /tmp/opam-want.txt /tmp/opam-got.txt; then
  echo "openssl-rs-court-tools: FATAL: installed opam set differs from the pinned export" >&2
  exit 1
fi

test -x "${OPAMROOT}/${OPAM_SWITCH}/bin/binsec"
"${OPAMROOT}/${OPAM_SWITCH}/bin/binsec" -version

# --- the image's own receipt ---------------------------------------------------
# A container from this image can therefore state its timing-tool identity without
# re-deriving it. The base entrypoint writes /court/toolchain.txt on every start;
# this file is a property of the image and sits beside it.
{
  echo "court_variant=timing-tools"
  echo "purpose=timing-analysis instruments (valgrind/ctgrind, perf, dudect, BINSEC, TIMECOP)"
  echo "base_image=${BASE_IMAGE}"
  echo "valgrind=$(valgrind --version)"
  echo "valgrind_headers=/usr/include/valgrind/{valgrind.h,memcheck.h}"
  echo "perf=$(perf --version)"
  echo "dudect_url=${DUDECT_URL}"
  echo "dudect_commit=$(cat /opt/dudect/COMMIT)"
  echo "dudect_binaries=$(cd /opt/dudect && ls dudect_*_O2 dudect_simple_O0 | tr '\n' ' ')"
  echo "opam_root=${OPAMROOT}"
  echo "opam_switch=${OPAM_SWITCH}"
  echo "opam_switch_export=${EXPORT} sha256=$(sha256sum "${EXPORT}" | cut -d' ' -f1)"
  echo "opam_packages=$(wc -l < /tmp/opam-got.txt) (identical to the export's installed set)"
  echo "binsec=$("${OPAMROOT}/${OPAM_SWITCH}/bin/binsec" -version | head -1) sha256=$(sha256sum "${OPAMROOT}/${OPAM_SWITCH}/bin/binsec" | cut -d' ' -f1)"
  echo "note=perf measurement additionally requires CAP_PERFMON at docker-run time (docker/openssl-rs-court.sh OPENSSL_RS_COURT_CAP_PERFMON, default on)"
} > /court/timing-tools.txt
cat /court/timing-tools.txt

rm -f /tmp/opam-want.txt /tmp/opam-got.txt
say "done"
