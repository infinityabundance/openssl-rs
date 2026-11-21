#!/usr/bin/env bash
# run_timecop_supercop.sh — T18: build and run the real TIMECOP harness.
#
# TIMECOP is a patch to SUPERCOP plus Valgrind client-request wrappers
# (poison.h).  Upstream lists patches for exactly three SUPERCOP versions:
# supercop-20181113, supercop-20190110 and supercop-20190816.  This runner uses
# 20190816, the newest of them.
#
#   TIMECOP project:       https://www.post-apocalyptic-crypto.org/timecop/
#   SUPERCOP tarball:      https://bench.cr.yp.to/supercop/supercop-20190816.tar.xz
#   SUPERCOP sha256:       e4fe70eb2a24928a7bbd3fb133787f982f7fead959dd6521c2d42c52b69e96ac
#   TIMECOP patch:         https://post-apocalyptic-crypto.org/timecop/supercop-20190816.diff
#   TIMECOP patch sha256:  cc22f39dce8dba449dff9bbe6aaeb7d538102b0e083283bc44fcfc85cda1fbdf
#
# The patch is applied to a pristine tree, but no *measurement* is patched: the
# harness is SUPERCOP's own try program compiled with -DSUPERCOP -DTIMECOP (that
# is what do-part does when Valgrind is present).  The one addition is a
# test-only variable-time control implementation, copied from
# courts/phase18/timing/fixtures/timecop/.
#
# Must run inside the tools court image (Valgrind 3.15+ and its headers).
#
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#     bash docker/openssl-rs-court.sh exec bash courts/phase18/timing/run_timecop_supercop.sh
#
# Optional first argument: work directory.  Default court/tmp/t1718/t18.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../../.." && pwd)"
WORK="${1:-${ROOT}/court/tmp/t1718/t18}"
VERSION="${SUPERCOP_VERSION:-20190816}"
TARBALL="supercop-${VERSION}.tar.xz"
PATCH="timecop-supercop-${VERSION}.diff"
TARBALL_URL="https://bench.cr.yp.to/supercop/${TARBALL}"
TARBALL_SHA256="e4fe70eb2a24928a7bbd3fb133787f982f7fead959dd6521c2d42c52b69e96ac"
PATCH_URL="https://post-apocalyptic-crypto.org/timecop/supercop-${VERSION}.diff"
PATCH_SHA256="cc22f39dce8dba449dff9bbe6aaeb7d538102b0e083283bc44fcfc85cda1fbdf"

section() { printf '\n===== %s =====\n' "$*"; }

mkdir -p "${WORK}"
cd "${WORK}"

section "toolchain"
command -v valgrind && valgrind --version
command -v cc && cc --version | head -1

section "fetch and verify the authorities"
if [ ! -f "${TARBALL}" ]; then
    curl -fsSL -o "${TARBALL}" "${TARBALL_URL}"
fi
echo "${TARBALL_SHA256}  ${TARBALL}" | sha256sum -c -
if [ ! -f "${PATCH}" ]; then
    curl -fsSL -o "${PATCH}" "${PATCH_URL}"
fi
echo "${PATCH_SHA256}  ${PATCH}" | sha256sum -c -

section "extract a pristine tree"
rm -rf "supercop-${VERSION}"
tar -xJf "${TARBALL}"
TREE="${WORK}/supercop-${VERSION}"

section "install Valgrind headers (upstream preparation step)"
VG_INC="$(dirname "$(find /usr -name memcheck.h -path '*valgrind*' 2>/dev/null | head -1)")"
if [ -z "${VG_INC}" ] || [ ! -r "${VG_INC}/valgrind.h" ]; then
    echo "cannot find valgrind/memcheck.h + valgrind.h" >&2
    exit 3
fi
echo "valgrind headers: ${VG_INC}"
cp -v "${VG_INC}/valgrind.h" "${VG_INC}/memcheck.h" "${TREE}/include/"
# TIMECOP's poison.h is published inline on its web page, not as a separate
# file; the fixture is a verbatim transcription (public domain).
cp -v "${HERE}/fixtures/timecop/poison.h" "${TREE}/include/poison.h"
sha256sum "${TREE}/include/poison.h"

section "apply the TIMECOP patch (dry run first)"
set +e
patch --dry-run -p1 -d "${TREE}" < "${PATCH}" 2>&1 | tee "${WORK}/patch-dryrun.log"
dry_rc=${PIPESTATUS[0]}
set -e
echo "patch_dry_run_exit=${dry_rc}"
if [ "${dry_rc}" -ne 0 ]; then
    echo "TIMECOP patch does not apply to supercop-${VERSION}" >&2
    exit 4
fi
patch -p1 -d "${TREE}" < "${PATCH}" 2>&1 | tee "${WORK}/patch-apply.log"
echo "files_patched=$(grep -c '^patching file ' "${WORK}/patch-apply.log" || true)"
echo "hunks_in_patch=$(grep -c '^@@' "${PATCH}" || true)"
echo "rejects=$(find "${TREE}" -name '*.rej' | wc -l)"
echo "merge_rejects=$(find "${TREE}" -name '*.orig' | wc -l)"

section "add the test-only variable-time control"
mkdir -p "${TREE}/crypto_verify/16/zz-leaky-control"
cp -v "${HERE}/fixtures/timecop/zz-leaky-control/"* \
      "${TREE}/crypto_verify/16/zz-leaky-control/"

section "build the SUPERCOP harness (do-part init)"
cd "${TREE}"
# do-part always ends with `cat "$work/errors"`; on a run that compiled no
# implementation that file is absent and the script exits non-zero even though
# the toolchain was built.  Judge success by bin/okabi, not by that exit code.
set +e
SUPERCOP_SKIP_MEASUREMENTS=true ./do-part init 2>&1 | tee "${WORK}/do-part-init.log"
init_rc=${PIPESTATUS[0]}
set -e
echo "do_part_init_exit=${init_rc}"
if [ ! -x "$(find bench -name okabi -type f | head -1)" ]; then
    echo "do-part init did not produce the okabi toolchain" >&2
    exit 5
fi

section "run TIMECOP on crypto_verify/16 (reference + leaky control)"
# do-part's second argument selects the primitive (16), not an implementation;
# the run covers every api.h beneath crypto_verify/16, including our control.
set +e
SUPERCOP_SKIP_MEASUREMENTS=true ./do-part crypto_verify 16 \
    2>&1 | tee "${WORK}/do-part-crypto_verify-16.log"
verify_rc=${PIPESTATUS[0]}
set -e
echo "do_part_crypto_verify_16_exit=${verify_rc}"

section "verdicted results (SUPERCOP data table)"
DATA="$(find bench -name data -type f | head -1)"
echo "data=${DATA}"
awk 'NF >= 9 && $7 ~ /^valgrind_/ { print $7, $8, $9 }' "${DATA}" \
    | sort -u \
    | tee "${WORK}/verdicts.txt"
echo "reference_pass_configs=$(grep -c '^valgrind_pass crypto_verify/16/ref ' "${WORK}/verdicts.txt" || true)"
echo "control_fail_configs=$(grep -c '^valgrind_fail crypto_verify/16/zz-leaky-control ' "${WORK}/verdicts.txt" || true)"
if grep -q 'valgrind_fail' "${WORK}/verdicts.txt"; then
    echo "control_fired=YES"
else
    echo "control_fired=NO"
fi
if grep -q '^valgrind_pass crypto_verify/16/ref ' "${WORK}/verdicts.txt"; then
    echo "reference_clean=YES"
else
    echo "reference_clean=NO"
fi

section "valgrind report excerpt for the control"
grep -n -m 1 -A 12 'Conditional jump or move depends on uninitialised' "${DATA}" || true
grep -n 'ERROR SUMMARY' "${DATA}" | tail -5 || true

section "done"
echo "artefacts in ${WORK}"
