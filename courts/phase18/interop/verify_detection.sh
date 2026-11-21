#!/usr/bin/env bash
#
# verify_detection.sh — O3: assert that the OpenSSH harness can actually see the
# third-party tools, and record what it saw.
#
# Fails closed. `regress/test-exec.sh` hardcodes /usr/local/bin/* and overrides
# from TEST_SSH_*, and `configure` fills those from its `AC_PATH_PROG` results;
# the generated Makefile's `interop-tests` target is what passes them into the
# harness. The Makefile value is therefore configure's own answer, and it is
# what this script reads — not a re-run of `command -v`, which would only
# restate the shell's PATH and would "detect" a tool the harness cannot see.
#
# A tool that exists but is not the path the harness will use is `mismatch`;
# a tool the harness has an empty path for is `not_detected`. Both fail. conch
# is expected absent: it is not pinned by this campaign, so the harness tests
# that require it must be recorded skipped, never passed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="${O3_WORK:-$ROOT/court/tmp/o2}"
PREFIX="${PREFIX:-$ROOT/court/tmp/o3/prefix}"
SSHDIR="${O3_SSH_DIR:-$WORK/openssh-9.9p1}"
RECEIPT="${O3_RECEIPT:-$ROOT/courts/phase18/interop/RECEIPT-o3.json}"

die() { echo "verify_detection: $*" >&2; exit 1; }

[ -f "$SSHDIR/Makefile" ] || die "no configured OpenSSH tree at $SSHDIR"

makefile_value() {
    sed -n "s/^[[:space:]]*$1=\"\\(.*\\)\".*/\\1/p" "$SSHDIR/Makefile" | head -n 1
}

# role | makefile variable | installed binary | version argv
ROWS=(
  "plink|TEST_SSH_PLINK|$PREFIX/bin/plink|--version"
  "puttygen|TEST_SSH_PUTTYGEN|$PREFIX/bin/puttygen|--version"
  "dropbear|TEST_SSH_DROPBEAR|$PREFIX/sbin/dropbear|-V"
  "dbclient|TEST_SSH_DBCLIENT|$PREFIX/bin/dbclient|-V"
  "dropbearkey|TEST_SSH_DROPBEARKEY|$PREFIX/bin/dropbearkey|-V"
  "dropbearconvert|TEST_SSH_DROPBEARCONVERT|$PREFIX/bin/dropbearconvert|-V"
)

fail=0
json_rows=""
for row in "${ROWS[@]}"; do
    IFS='|' read -r role var bin vararg <<<"$row"
    detected="$(makefile_value "$var")"
    version=""
    if [ -x "$bin" ]; then
        version="$("$bin" "$vararg" 2>&1 | head -n 1 || true)"
    fi
    if [ -z "$detected" ]; then
        status="not_detected"
    elif [ "$detected" != "$bin" ]; then
        status="mismatch"
    elif [ ! -x "$bin" ]; then
        status="missing_binary"
    else
        status="ok"
    fi
    [ "$status" = ok ] || fail=$((fail + 1))
    printf '%-16s %-14s %s\n' "$role" "$status" "${detected:-<empty>}"
    v="${version//\\/}"; v="${v//\"/}"
    d="${detected//\"/}"
    json_rows+="${json_rows:+,}
  {\"role\": \"$role\", \"status\": \"$status\", \"detected\": \"$d\", \"version\": \"$v\"}"
done

conch="$(sed -n 's/.*checking for conch\.*\.\.\. //p' "$SSHDIR/config.log" | tail -n 1)"
case "$conch" in
    /*) fail=$((fail + 1))
        json_rows+=",
  {\"role\": \"conch\", \"status\": \"unexpectedly_present\", \"detected\": \"$conch\"}";;
    *)  json_rows+=",
  {\"role\": \"conch\", \"status\": \"absent\", \"note\": \"not pinned by this campaign; harness tests that require it must be recorded skipped, never passed\"}";;
esac

cat > "$RECEIPT" <<EOF
{
  "schema": "openssl-rs/interop-detection-receipt/1",
  "item": "O3 of docs/ETP-TODO.md",
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "openssh_tree": "$SSHDIR",
  "prefix": "$PREFIX",
  "mechanism": "regress/test-exec.sh defaults to /usr/local/bin/* and overrides from TEST_SSH_*; configure fills those from AC_PATH_PROG and the generated Makefile's interop-tests target carries them into the harness",
  "counts": {"tools": 6, "failed": $fail},
  "tools": [$json_rows
  ]
}
EOF

echo "receipt: $RECEIPT"
exit $((fail == 0 ? 0 : 1))
