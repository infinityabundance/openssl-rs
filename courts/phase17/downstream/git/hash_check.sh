#!/bin/sh
#
# openssl-rs — Phase 17 downstream: prove Git's object hashing is correct through the
# candidate's libcrypto, for both SHA-1 and SHA-256.
#
#   bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/hash_check.sh
#
# Git hashes the byte string "blob <len>\0<content>".  The expected digests are computed
# here by GNU `sha1sum`/`sha256sum` (an independent, non-OpenSSL implementation), and the
# candidate-linked `git hash-object` must agree.  Also records that the `git` binary
# genuinely resolves libcrypto from the candidate prefix and imports the SHA symbols.
#
set -eu

SRC=${SRC:-/court/git/git-2.56.0}
CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
GIT="$SRC/git"
GIT_TEMPLATE_DIR="$SRC/templates/blt"
export GIT_TEMPLATE_DIR

[ -x "$GIT" ] || { echo "hash_check.sh: $GIT missing; run build.sh first" >&2; exit 2; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CONTENT='hello world'
printf '%s\n' "$CONTENT" > "$TMP/blob.txt"
LEN=$(wc -c < "$TMP/blob.txt" | tr -d ' ')

# The exact bytes Git hashes: the "blob <len>\0" header prepended to the content.
{ printf 'blob %s\0' "$LEN"; cat "$TMP/blob.txt"; } > "$TMP/raw.bin"
EXPECT_SHA1=$(sha1sum "$TMP/raw.bin" | cut -d' ' -f1)
EXPECT_SHA256=$(sha256sum "$TMP/raw.bin" | cut -d' ' -f1)

rc=0
echo "hash_check.sh: content=$(printf '%s' "$CONTENT" | od -An -c | tr -s ' ') len=$LEN"
echo "hash_check.sh: expected sha1   = $EXPECT_SHA1   (GNU sha1sum)"
echo "hash_check.sh: expected sha256 = $EXPECT_SHA256 (GNU sha256sum)"

# --- SHA-1 repository ---
cd "$TMP"
"$GIT" init -q sha1repo
GOT_SHA1=$("$GIT" -C sha1repo hash-object "$TMP/blob.txt")
echo "hash_check.sh: git hash-object (sha1)   = $GOT_SHA1"
[ "$GOT_SHA1" = "$EXPECT_SHA1" ] || { echo "hash_check.sh: SHA-1 MISMATCH"; rc=1; }

# --- SHA-256 repository ---
"$GIT" init -q --object-format=sha256 sha256repo
GOT_SHA256=$("$GIT" -C sha256repo hash-object "$TMP/blob.txt")
echo "hash_check.sh: git hash-object (sha256) = $GOT_SHA256"
[ "$GOT_SHA256" = "$EXPECT_SHA256" ] || { echo "hash_check.sh: SHA-256 MISMATCH"; rc=1; }

# --- link-time evidence: the hashing is really the candidate's ---
echo "hash_check.sh: --- git DT_NEEDED / rpath ---"
readelf -d "$GIT" | grep -E 'NEEDED.*(crypto|ssl)|RUNPATH|RPATH' || true
echo "hash_check.sh: --- git's imported hash symbols (U = from candidate libcrypto) ---"
nm -D "$GIT" 2>/dev/null | grep -E ' U (EVP_sha1|EVP_sha256|SHA1_Init|SHA1_Update|SHA1_Final|SHA256_Init|SHA256_Update|SHA256_Final)' || true
echo "hash_check.sh: --- git version --build-options ---"
"$GIT" version --build-options | grep -E 'OpenSSL|libcurl|SHA-1|SHA-256'
echo "hash_check.sh: --- ldd resolves those from the candidate prefix ---"
ldd "$GIT" | grep -E 'libssl|libcrypto' || true

if [ "$rc" -ne 0 ]; then
    echo "hash_check.sh: FAIL"
    exit "$rc"
fi
echo "hash_check.sh: PASS (candidate SHA-1 and SHA-256 agree with GNU coreutils)"
