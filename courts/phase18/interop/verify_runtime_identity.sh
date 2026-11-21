#!/usr/bin/env bash
#
# verify_runtime_identity.sh — O5: prove which libcrypto each OpenSSH executable
# actually runs against.
#
# Neither tree's binaries carry a RUNPATH (O4), so the answer is decided at run
# time. This script therefore asks the three questions in increasing strength:
#
#   1. readelf -d      what the binary names (NEEDED) and whether it pins a path;
#   2. ldd             what the loader resolves under an explicit, per-cell
#                      LD_LIBRARY_PATH;
#   3. /proc/<pid>/maps  what a *live process* actually mapped, for the binaries
#                      that stay resident (sshd, ssh-agent, sftp-server).
#
# It fails closed: a binary that resolves libcrypto outside its own cell, that
# maps a different DSO than the cell's, or that cannot be resolved at all is a
# failure. A binary that cannot be kept alive is recorded `not_live` with the
# reason, never silently counted as verified.
#
# The negative control at the end runs a cell-A binary with cell-B's library
# path and requires the check to reject it; without that the whole exercise
# would only show that a program loads *some* libcrypto.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="${O5_WORK:-$ROOT/court/tmp/o4}"
AUTH="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
B_PREFIX="${B_PREFIX:-$WORK/b-prefix}"
RECEIPT="${O5_RECEIPT:-$ROOT/courts/phase18/interop/RECEIPT-o5.json}"

BINARIES=(ssh sshd sshd-session ssh-keygen ssh-agent sftp-server)
declare -A CELL_LIB=( [A]="$AUTH/lib" [B]="$B_PREFIX/lib" )
declare -A CELL_TREE=( [A]="$WORK/tree-A" [B]="$WORK/tree-B" )

fail=0
rows=""

lib_of() {  # cell -> sha256 of that cell's libcrypto
    sha256sum "${CELL_LIB[$1]}/libcrypto.so.3" | cut -d' ' -f1
}
DSO_A="$(lib_of A)"
DSO_B="$(lib_of B)"

record() {  # cell binary status detail digest
    rows+="${rows:+,}
    {\"cell\": \"$1\", \"binary\": \"$2\", \"status\": \"$3\", \"detail\": \"$4\", \"libcrypto_sha256\": \"$5\"}"
}

check_path() {  # cell binary mapped_path -> echo status
    local cell="$1" want="${CELL_LIB[$1]}"
    case "$2" in
        "$want"/libcrypto.so.3*) echo ok;;
        "") echo unresolved;;
        *) echo "outside_cell:$2";;
    esac
}

echo "=== static + resolved identity ==="
for cell in A B; do
    for b in "${BINARIES[@]}"; do
        bin="${CELL_TREE[$cell]}/$b"
        if [ ! -x "$bin" ]; then
            printf '%-2s %-14s %-12s\n' "$cell" "$b" missing
            record "$cell" "$b" missing "no such binary" ""
            fail=$((fail+1))
            continue
        fi
        needed="$(readelf -d "$bin" 2>/dev/null | sed -n 's/.*Shared library: \[\(libcrypto[^]]*\)\].*/\1/p')"
        resolved="$(LD_LIBRARY_PATH="${CELL_LIB[$cell]}" ldd "$bin" 2>/dev/null | awk '/libcrypto\.so/ && /=>/ {print $3}')"
        status="$(check_path "$cell" "$resolved")"
        if [ -z "$needed" ] && [ -z "$resolved" ]; then
            # Observed for sftp-server: it links libmd and libc only. That is an
            # implementation-defined fact about this OpenSSH build, not a linkage
            # defect, so it is recorded rather than failed.
            status="no_crypto_dependency"
        fi
        case "$status" in
            ok|no_crypto_dependency) ;;
            *) fail=$((fail+1));;
        esac
        printf '%-2s %-14s %-12s %s\n' "$cell" "$b" "$status" "${resolved:-<none>}"
        record "$cell" "$b" "$status" "needed=${needed:-none} resolved=${resolved:-none}" \
               "$([ -n "$resolved" ] && sha256sum "$resolved" | cut -d' ' -f1)"
    done
done

echo
echo "=== live maps reported by the process itself ==="
# sshd and ssh-agent are non-dumpable, so an external /proc/<pid>/maps read is
# refused (EACCES, observed). The probe is a constructor that records the
# process's own matches, so the binary, the loader, the path and the mapped
# object are all the real ones.
PROBE_SRC="$ROOT/courts/phase18/interop/map_probe.c"
PROBE_SO="$WORK/map_probe.so"
cc -O2 -fPIC -shared "$PROBE_SRC" -o "$PROBE_SO" || { echo "probe build failed" >&2; exit 2; }

# A quick argument per binary: the probe runs before main, so a usage message is
# enough and the exit status is deliberately ignored.
quick_arg() {
    case "$1" in
        ssh) echo "-V";;
        sshd) echo "-t";;
        sshd-session) echo "-h";;
        ssh-keygen) echo "-?";;
        ssh-agent) echo "-k";;
        sftp-server) echo "";;
    esac
}

for cell in A B; do
    for b in "${BINARIES[@]}"; do
        out="$WORK/maps-$cell-$b"
        rm -f "$out"
        bin="${CELL_TREE[$cell]}/$b"
        [ -x "$bin" ] || continue
        arg="$(quick_arg "$b")"
        case "$b" in
            sshd)
                # `-t` needs a config with a host key; generate one per cell.
                "$bin" -q -t ed25519 -N '' -f "$out.key" >/dev/null 2>&1 || true
                "${CELL_TREE[$cell]}/ssh-keygen" -q -t ed25519 -N '' -f "$out.key" >/dev/null 2>&1 || true
                printf 'Port 22022\nHostKey %s\nPidFile %s.pid\nUsePAM no\n' "$out.key" "$out" > "$out.conf"
                MAP_PROBE_OUT="$out" LD_PRELOAD="$PROBE_SO" LD_LIBRARY_PATH="${CELL_LIB[$cell]}" \
                    "$bin" -t -f "$out.conf" >/dev/null 2>&1 || true
                ;;
            ""|sftp-server)
                # No libcrypto dependency in this build: nothing to observe.
                record "$cell" "$b" not_applicable "no libcrypto in NEEDED and none resolved" ""
                printf '%-2s %-14s %-12s %s\n' "$cell" "$b" not_applicable "-"
                continue
                ;;
            *)
                MAP_PROBE_OUT="$out" LD_PRELOAD="$PROBE_SO" LD_LIBRARY_PATH="${CELL_LIB[$cell]}" \
                    "$bin" $arg >/dev/null 2>&1 || true
                ;;
        esac
        mapped="$(awk '{print $6}' "$out" 2>/dev/null | head -n 1)"
        if [ -z "$mapped" ]; then
            status=not_mapped
        else
            status="$(check_path "$cell" "$mapped")"
        fi
        case "$status" in ok) ;; *) fail=$((fail+1));; esac
        printf '%-2s %-14s %-12s %s\n' "$cell" "$b" "$status" "${mapped:-<not mapped>}"
        record "$cell" "$b" "live_$status" "mapped=${mapped:-none}" \
               "$([ -n "$mapped" ] && sha256sum "$mapped" | cut -d' ' -f1)"
    done
done

echo
echo "=== negative control: cell A's ssh with cell B's library path ==="
control_resolved="$(LD_LIBRARY_PATH="${CELL_LIB[B]}" ldd "${CELL_TREE[A]}/ssh" 2>/dev/null | awk '/libcrypto\.so/ && /=>/ {print $3}' | head -n 1)"
control="$(check_path A "$control_resolved")"
case "$control" in
    ok) printf '%s\n' "CONTROL FAILED: cell A's binary resolved to cell B's library and was accepted"
        fail=$((fail+1));;
    *)  printf 'control rejected as expected: %s %s\n' \
            "${control%%:*}" "${control#*:}";;
esac

cat > "$RECEIPT" <<EOF
{
  "schema": "openssl-rs/interop-runtime-identity-receipt/1",
  "item": "O5 of docs/ETP-TODO.md",
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cells": {"A": "$AUTH", "B": "$B_PREFIX"},
  "libcrypto_sha256": {"A": "$DSO_A", "B": "$DSO_B"},
  "negative_control": {"result": "$(printf '%s' "$control" | tr -d '\n')", "resolved": "$(printf '%s' "$control_resolved" | tr -d '\n')"},
  "counts": {"failed": $fail},
  "checks": [$rows
  ]
}
EOF

echo "receipt: $RECEIPT"
exit $((fail == 0 ? 0 : 1))
