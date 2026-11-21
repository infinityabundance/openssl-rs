#!/usr/bin/env bash
#
# build_trees.sh — O4: two OpenSSH builds from the same unmodified source, in
# isolated trees, one against the pinned authority and one against this crate.
#
#   ARCHIVE=/path/to/libopenssl_rs.a bash courts/phase18/interop/build_trees.sh
#
# Inputs:
#   ARCHIVE       the crate's release static archive (required)
#   O4_WORK       scratch root (default court/tmp/o4)
#   B_INCLUDE     the include tree for the candidate prefix (default
#                 artifacts/phase2/include, the layout the Phase-2 court
#                 generates from the authority's headers)
#   AUTH_PREFIX   the pinned OpenSSL authority prefix
#
# Isolation rules this script enforces rather than documents:
#   * the two trees are separate copies of the same extracted tarball, and each
#     is configured with its own --with-ssl-dir;
#   * neither build sets LD_LIBRARY_PATH. Neither tree gets a RUNPATH either, so
#     the runtime library is chosen per process at execution time and a shared
#     LD_LIBRARY_PATH would silently give both cells one library — which is why
#     O5 checks /proc/<pid>/maps rather than trusting `ldd`.
#
# The receipt names both DSOs by digest. The candidate DSO here is linked from
# the archive with `cc -shared`; that is the measurement build, not the
# distribution artefact, whose identity is the court's own.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="${O4_WORK:-$ROOT/court/tmp/o4}"
AUTH="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
B_INCLUDE="${B_INCLUDE:-$ROOT/artifacts/phase2/include}"
SRC_TGZ="${SRC_TGZ:-$ROOT/court/tmp/o2/openssh-9.9p1.tar.gz}"
TOOLS="${TOOLS_PREFIX:-$ROOT/court/tmp/o3/prefix}"
RECEIPT="${O4_RECEIPT:-$ROOT/courts/phase18/interop/RECEIPT-o4.json}"

die() { echo "build_trees: $*" >&2; exit 2; }

[ -n "${ARCHIVE:-}" ] || die "set ARCHIVE to the crate's release static archive"
[ -f "$ARCHIVE" ] || die "no archive at $ARCHIVE"
[ -f "$SRC_TGZ" ] || die "no OpenSSH tarball at $SRC_TGZ (run verify_pins.py --fetch)"
[ -d "$AUTH/lib" ] || die "no authority prefix at $AUTH"
[ -d "$B_INCLUDE/openssl" ] || die "no candidate headers at $B_INCLUDE/openssl"

mkdir -p "$WORK"
export PATH="$TOOLS/bin:$TOOLS/sbin:$PATH"

echo "=== candidate prefix (fresh DSO from the archive) ==="
rm -rf "$WORK/b-prefix"
mkdir -p "$WORK/b-prefix/lib" "$WORK/b-prefix/include"
cc -shared -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
   -Wl,-soname,libcrypto.so.3 -o "$WORK/b-prefix/lib/libcrypto.so.3" \
   || die "linking the candidate DSO failed"
ln -sf libcrypto.so.3 "$WORK/b-prefix/lib/libcrypto.so"
cp -a "$B_INCLUDE/." "$WORK/b-prefix/include/"

echo "=== two isolated source trees ==="
rm -rf "$WORK/src" "$WORK/tree-A" "$WORK/tree-B"
mkdir -p "$WORK/src"
tar xzf "$SRC_TGZ" -C "$WORK/src" || die "extracting the OpenSSH tarball failed"
cp -a "$WORK/src/openssh-9.9p1" "$WORK/tree-A"
cp -a "$WORK/src/openssh-9.9p1" "$WORK/tree-B"

build() {
    local tree="$1" ssl="$2" log="$3"
    ( cd "$tree" \
      && ./configure --with-ssl-dir="$ssl" --without-openssl-header-check \
             --without-pam --without-selinux --without-libedit --without-ldns \
             >"${log}.configure" 2>&1 \
      && make -j4 >"$log" 2>&1 )
}

echo "=== build A: reference OpenSSL ==="
build "$WORK/tree-A" "$AUTH" "$WORK/build-A.log"; rc_a=$?
echo "build A exit=$rc_a"

echo "=== build B: openssl-rs ==="
build "$WORK/tree-B" "$WORK/b-prefix" "$WORK/build-B.log"; rc_b=$?
echo "build B exit=$rc_b"

dso_a="$(sha256sum "$AUTH/lib/libcrypto.so.3" | cut -d' ' -f1)"
dso_b="$(sha256sum "$WORK/b-prefix/lib/libcrypto.so.3" | cut -d' ' -f1)"

echo "=== static linkage (no RUNPATH is expected in either tree) ==="
rows=""
for t in tree-A tree-B; do
    for b in ssh sshd sshd-session ssh-keygen ssh-agent sftp-server; do
        [ -x "$WORK/$t/$b" ] || continue
        needed="$(readelf -d "$WORK/$t/$b" 2>/dev/null | sed -n 's/.*Shared library: \[\(libcrypto[^]]*\)\].*/\1/p' | tr '\n' ' ')"
        rpath="$(readelf -d "$WORK/$t/$b" 2>/dev/null | sed -n 's/.*(R\(UN\)\?PATH).*\[\(.*\)\].*/\2/p' | tr '\n' ' ')"
        [ -n "$rpath" ] || rpath="-"
        rows+="${rows:+,}
    {\"cell\": \"$t\", \"binary\": \"$b\", \"needed_crypto\": \"${needed% }\", \"rpath\": \"$rpath\"}"
    done
done

cat > "$RECEIPT" <<EOF
{
  "schema": "openssl-rs/interop-build-receipt/1",
  "item": "O4 of docs/ETP-TODO.md",
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source": {"tarball": "$(basename "$SRC_TGZ")", "sha256": "$(sha256sum "$SRC_TGZ" | cut -d' ' -f1)", "version": "9.9p1"},
  "trees": {"A": "$WORK/tree-A", "B": "$WORK/tree-B", "separate_copies": true},
  "build_against": {
    "A": {"ssl_dir": "$AUTH", "libcrypto_sha256": "$dso_a"},
    "B": {"ssl_dir": "$WORK/b-prefix", "libcrypto_sha256": "$dso_b",
          "include_source": "$B_INCLUDE", "dso_from_archive": "$ARCHIVE"}
  },
  "ld_library_path_used_at_build": false,
  "exit_codes": {"A": $rc_a, "B": $rc_b},
  "binaries": [$rows
  ]
}
EOF

echo "receipt: $RECEIPT"
[ "$rc_a" -eq 0 ] && [ "$rc_b" -eq 0 ]
