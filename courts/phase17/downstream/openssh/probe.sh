#!/bin/sh
#
# openssl-rs — Phase 17 downstream: live-behavior probe for the candidate-linked
# OpenSSH. Runs entirely inside the court container.
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/openssh/probe.sh
#
# What it proves:
#   1. BIN           — the built binaries run and report the candidate OpenSSL.
#   2. HOSTKEY/USERKEY — ssh-keygen generates RSA, ECDSA and Ed25519 keys, and
#                        prints SHA256/MD5 fingerprints, using the candidate's
#                        libcrypto primitives (BN, EC, Ed25519, digests).
#   3. HANDSHAKE     — a real sshd listens on localhost and a real ssh completes
#                        a public-key login; both ends link the candidate.
#   4. MATRIX        — forced key-exchange / cipher / MAC / host-key algorithms
#                        exercise X25519, P-256 ECDH, finite-field DH (BN),
#                        AES-GCM/CTR, ChaCha20-Poly1305, HMAC-SHA2, UMAC,
#                        RSA/ECDSA/Ed25519 host-key signing, and the PQ hybrid
#                        kexes (sntrup761x25519, mlkem768x25519).
#   5. SIG           — ssh-keygen -Y sign/verify for RSA, ECDSA and Ed25519.
#   6. AGENT         — ssh-agent holds the keys and authenticates a login.
#
# The script does not abort on a failing case; it records each result and prints
# a summary, so a candidate-triggered crash or hang shows up as evidence rather
# than silence.
#
set -u

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
WORK=${WORK:-/court/openssh}
SRC=${SRC:-$WORK/openssh-10.5p1}
INSTALL=${INSTALL:-$WORK/install}
PORT=${PORT:-2222}
T=$WORK/probe

SSH=$SRC/ssh
SSHD=$SRC/sshd
KEYGEN=$SRC/ssh-keygen
AGENT=$SRC/ssh-agent
ADD=$SRC/ssh-add

fail=0
pass=0

say() { printf '%s\n' "$*"; }
ok()  { pass=$((pass+1)); say "  [PASS] $*"; }
bad() { fail=$((fail+1)); say "  [FAIL] $*"; }

rm -rf "$T"
mkdir -p "$T"

# kill_ours: SIGKILL leftover sshd/sshd-session from an aborted run so the new listener can bind
# PORT and a squatter cannot answer in its place.
for p in /proc/[0-9]*; do
    c=$(cat "$p/comm" 2>/dev/null || true)
    case "$c" in
        sshd|sshd-session) kill -9 "${p#/proc/}" 2>/dev/null || true ;;
    esac
done

AGENT_PID=""
SSHD_PID=""
cleanup() {
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
    [ -n "$SSHD_PID" ]  && kill "$SSHD_PID"  2>/dev/null
    [ -n "$SSHD_PID" ]  && wait "$SSHD_PID"  2>/dev/null
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
say "=== 1. binaries ==="
say "-- ssh -V --"
"$SSH" -V 2>&1
say "-- ldd sshd / ssh (candidate libcrypto, no libssl) --"
ldd "$SSHD" | grep -E "libcrypto|libssl" || true
ldd "$SSH"  | grep -E "libcrypto|libssl" || true

# ---------------------------------------------------------------------------
say ""
say "=== 2. ssh-keygen: host keys + user keys + fingerprints ==="
gen() {
    # gen <label> <keygen args...>
    label=$1; shift
    if "$KEYGEN" -q -N '' "$@" >"$T/keygen.$label.log" 2>&1; then
        ok "generate $label"
    else
        bad "generate $label: $(tr '\n' ' ' <"$T/keygen.$label.log")"
    fi
}
gen host_ed25519 -t ed25519 -f "$T/host_ed25519"
gen host_ecdsa   -t ecdsa -b 256 -f "$T/host_ecdsa"
gen host_rsa     -t rsa   -b 2048 -f "$T/host_rsa"
gen id_ed25519   -t ed25519 -f "$T/id_ed25519"
gen id_ecdsa     -t ecdsa -b 256 -f "$T/id_ecdsa"
gen id_rsa       -t rsa   -b 2048 -f "$T/id_rsa"

say "-- fingerprints (SHA256 and MD5) --"
for k in host_ed25519 host_ecdsa host_rsa id_ed25519 id_ecdsa id_rsa; do
    f=$("$KEYGEN" -lf "$T/$k.pub" 2>&1)
    m=$("$KEYGEN" -E md5 -lf "$T/$k.pub" 2>&1)
    say "  $k:"
    say "    sha256: $f"
    say "    md5:    $m"
done

# authorized_keys for root (login in the HANDSHAKE step)
cat "$T/id_ed25519.pub" "$T/id_ecdsa.pub" "$T/id_rsa.pub" > "$T/authorized_keys"
chmod 644 "$T/authorized_keys"

# ---------------------------------------------------------------------------
say ""
say "=== 3. sshd + ssh localhost handshake ==="
# privsep user + chroot dir (idempotent; the container is disposable)
groupadd -r sshd 2>/dev/null || true
useradd -r -g sshd -s /usr/sbin/nologin -d /var/empty sshd 2>/dev/null || true
mkdir -p "$INSTALL/var/empty" /var/empty
chown 0:0 "$INSTALL/var/empty" /var/empty
chmod 755 "$INSTALL/var/empty" /var/empty

cat > "$T/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
PidFile $T/sshd.pid
HostKey $T/host_ed25519
HostKey $T/host_ecdsa
HostKey $T/host_rsa
AuthorizedKeysFile $T/authorized_keys
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
AllowTcpForwarding no
LogLevel VERBOSE
# OpenSSH 10.5's sshd default deliberately omits finite-field DH; re-enable it so
# the probe actually exercises the candidate's BN modular-exponentiation path.
KexAlgorithms +diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
# Keep enough unauthenticated starts for the 16-way concurrency probe (default MaxStartups
# 10:30:100 would randomly drop simultaneous connections).
MaxStartups 64:30:100
EOF

say "-- sshd -t (config test) --"
if "$SSHD" -t -f "$T/sshd_config" >"$T/sshd_t.log" 2>&1; then
    ok "sshd -t"
else
    bad "sshd -t: $(tr '\n' ' ' <"$T/sshd_t.log")"
fi

"$SSHD" -f "$T/sshd_config" -D -e > "$T/sshd.log" 2>&1 &
SSHD_PID=$!
sleep 1
if kill -0 "$SSHD_PID" 2>/dev/null; then
    ok "sshd started (pid $SSHD_PID) on port $PORT"
else
    bad "sshd exited immediately; log:"; sed -n '1,20p' "$T/sshd.log"
fi

COMMON="-p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=$T/known_hosts \
 -o BatchMode=yes -o PreferredAuthentications=publickey \
 -o UpdateHostKeys=no -o ConnectTimeout=10"

say "-- straightforward login (ed25519 key) --"
if out=$(timeout 20 "$SSH" $COMMON -i "$T/id_ed25519" root@127.0.0.1 'echo PROBE_OK; id -u' 2>"$T/login.err"); then
    ok "login: $(printf '%s' "$out" | tr '\n' ' ')"
else
    bad "login rc=$?; stderr:"; sed -n '1,15p' "$T/login.err"
fi

# ---------------------------------------------------------------------------
say ""
say "=== 4. algorithm matrix (forced kex/cipher/mac/hostkey) ==="
run_case() {
    label=$1; shift
    log="$T/matrix.$(printf '%s' "$label" | tr ' /@' '___').log"
    if timeout 20 "$SSH" $COMMON -i "$IDENT" -v "$@" root@127.0.0.1 'true' >"$log.out" 2>"$log"; then
        tr -d '\r' < "$log" > "$log.clean"
        kex=$(sed -n 's/.*kex: algorithm: \([^ ]*\).*/\1/p' "$log.clean" | head -1)
        hk=$(sed -n 's/.*kex: host key algorithm: \([^ ]*\).*/\1/p' "$log.clean" | head -1)
        c2s=$(sed -n 's/.*kex: server->client cipher: \([^ ]*\) MAC: \([^ ]*\).*/\1\/\2/p' "$log.clean" | head -1)
        auth=$(sed -n 's/.*Authenticated to .* using "\([^"]*\)".*/\1/p' "$log.clean" | head -1)
        ok "$label: kex=$kex hostkey=$hk cipher/mac=$c2s auth=$auth"
    else
        rc=$?
        if [ "$rc" = 124 ]; then
            bad "$label: HANG (timeout 20s)"
        else
            bad "$label: rc=$rc; $(tr -d '\r' < "$log" | grep -iE 'error|fatal|no matching|kex_exchange|bad|invalid' | head -3 | tr '\n' ' ')"
        fi
    fi
}

IDENT="$T/id_ed25519"
run_case "default-negotiated"
run_case "x25519/ed25519/aes256-gcm" -o KexAlgorithms=curve25519-sha256 -o HostKeyAlgorithms=ssh-ed25519 -o Ciphers=aes256-gcm@openssh.com -o MACs=hmac-sha2-256
run_case "dh-group14-sha256(bn)/ed25519/aes128-ctr" -o KexAlgorithms=diffie-hellman-group14-sha256 -o HostKeyAlgorithms=ssh-ed25519 -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256
run_case "dh-group16-sha512(bn)" -o KexAlgorithms=diffie-hellman-group16-sha512 -o HostKeyAlgorithms=ssh-ed25519
run_case "dh-group18-sha512(bn)" -o KexAlgorithms=diffie-hellman-group18-sha512 -o HostKeyAlgorithms=ssh-ed25519
run_case "dh-gex-sha256(bn,moduli)" -o KexAlgorithms=diffie-hellman-group-exchange-sha256 -o HostKeyAlgorithms=ssh-ed25519
run_case "ecdh-nistp256(kex)/ed25519/aes128-ctr" -o KexAlgorithms=ecdh-sha2-nistp256 -o HostKeyAlgorithms=ssh-ed25519 -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256
run_case "ecdh-nistp384(kex)/ed25519" -o KexAlgorithms=ecdh-sha2-nistp384 -o HostKeyAlgorithms=ssh-ed25519
run_case "ecdh-nistp521(kex)/ed25519" -o KexAlgorithms=ecdh-sha2-nistp521 -o HostKeyAlgorithms=ssh-ed25519
run_case "ecdsa-hostkey(EXPECT FAIL: key parse defect)" -o KexAlgorithms=ecdh-sha2-nistp256 -o HostKeyAlgorithms=ecdsa-sha2-nistp256 -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256
run_case "chacha20-poly1305" -o Ciphers=chacha20-poly1305@openssh.com -o MACs=hmac-sha2-256
run_case "aes128-ctr/hmac-sha1" -o Ciphers=aes128-ctr -o MACs=hmac-sha1
run_case "aes128-ctr/umac-64-etm" -o Ciphers=aes128-ctr -o MACs=umac-64-etm@openssh.com
run_case "rsa-hostkey/rsa-sha2-512(EXPECT FAIL: key parse defect)" -o HostKeyAlgorithms=rsa-sha2-512
run_case "sntrup761x25519-sha512" -o KexAlgorithms=sntrup761x25519-sha512
run_case "mlkem768x25519-sha256(PQ)" -o KexAlgorithms=mlkem768x25519-sha256
IDENT="$T/id_ecdsa"; run_case "auth-ecdsa-userkey"; IDENT="$T/id_ed25519"
IDENT="$T/id_rsa";   run_case "auth-rsa-userkey";   IDENT="$T/id_ed25519"

say "-- advertised algorithm counts --"
say "  kex:    $("$SSH" -Q kex    | wc -l)"
say "  key:    $("$SSH" -Q key    | wc -l)"
say "  cipher: $("$SSH" -Q cipher | wc -l)"
say "  mac:    $("$SSH" -Q mac    | wc -l)"
say "  sig:    $("$SSH" -Q sig    | wc -l)"

# ---------------------------------------------------------------------------
say ""
say "=== 5. ssh-keygen -Y sign/verify (raw libcrypto signatures) ==="
printf 'openssl-rs openssh signature probe\n' > "$T/msg"
for k in id_ed25519 id_ecdsa id_rsa; do
    rm -f "$T/msg.sig"
    printf '%s %s\n' 'probe@openssl-rs' "$(cat "$T/$k.pub")" > "$T/allowed_signers.$k"
    if "$KEYGEN" -Y sign -q -f "$T/$k" -n file "$T/msg" >/dev/null 2>"$T/sign.$k.err" \
       && timeout 10 "$KEYGEN" -Y verify -f "$T/allowed_signers.$k" -n file -I probe@openssl-rs -s "$T/msg.sig" < "$T/msg" >/dev/null 2>"$T/verify.$k.err"; then
        ok "$k sign+verify"
    else
        bad "$k sign+verify: $(cat "$T/sign.$k.err" "$T/verify.$k.err" 2>/dev/null | tr '\n' ' ')"
    fi
done

# ---------------------------------------------------------------------------
say ""
say "=== 6. ssh-agent login ==="
eval "$("$AGENT" -s)" >/dev/null 2>&1
AGENT_PID=$SSH_AGENT_PID
"$ADD" "$T/id_ed25519" >/dev/null 2>&1
say "-- ssh-add -l --"
"$ADD" -l 2>&1
if timeout 20 "$SSH" $COMMON -o IdentitiesOnly=no root@127.0.0.1 'echo AGENT_OK' >"$T/agent.out" 2>"$T/agent.err"; then
    ok "agent login: $(cat "$T/agent.out")"
else
    bad "agent login rc=$?; stderr: $(head -5 "$T/agent.err" | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
say ""
say "=== 7. 16 concurrent ssh logins ==="
CONC=$T/conc
rm -rf "$CONC"; mkdir -p "$CONC"
SSH_PIDS=
i=1
while [ "$i" -le 16 ]; do
    ( timeout 30 "$SSH" -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o PreferredAuthentications=publickey -o UpdateHostKeys=no \
        -o LogLevel=ERROR -o ConnectTimeout=10 -i "$T/id_ed25519" root@127.0.0.1 'true' \
        >/dev/null 2>"$CONC/err.$i"; echo $? >"$CONC/rc.$i" ) &
    SSH_PIDS="$SSH_PIDS $!"
    i=$((i + 1))
done
# shellcheck disable=SC2086
wait $SSH_PIDS || true
CONC_OK=0
for f in "$CONC"/rc.*; do [ "$(cat "$f")" = "0" ] && CONC_OK=$((CONC_OK + 1)); done
say "concurrent_logins=$CONC_OK/16"

# ---------------------------------------------------------------------------
say ""
say "=== 8. sshd server log: errors/crashes ==="
if grep -iE "fatal|segmentation|Aborted|core dump|assert|SSL library error" "$T/sshd.log" >/dev/null 2>&1; then
    say "  [WARN] suspicious lines in sshd.log:"
    grep -inE "fatal|segmentation|Aborted|core dump|assert|SSL library error" "$T/sshd.log" | head -10
else
    say "  none"
fi
say "  last sshd.log lines:"
tail -3 "$T/sshd.log" | sed 's/^/    /'

say ""
say "=== SUMMARY: $pass pass, $fail fail ==="

cleanup
trap - EXIT INT TERM
exit 0
