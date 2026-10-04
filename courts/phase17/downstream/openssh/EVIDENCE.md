# Phase 17 downstream — unmodified portable OpenSSH built against the candidate shell

Status: **build/link PROVEN; a real sshd+ssh handshake WORKS (Ed25519); the
candidate's cipher/HMAC/KDF/DH/ECDH/PQ paths all work over live connections — but
OpenSSH surfaces one severe candidate defect: RSA and ECDSA signing/verification
(and the parsing of native `openssh-key-v1` RSA/ECDSA private keys) fails.** This
is a proof slice; nothing is wired into `forensics/tools/phase17_courts.py`.

OpenSSH is a *libcrypto-only* consumer (EVP ciphers/digests, HMAC, KDF, BN, EC,
RSA, Ed25519) and never links libssl, so this exercises a different corner of the
candidate than the TLS courts.

## What was built

- Candidate distribution surface: `artifacts/phase2/install/{include,lib}`.
- Unmodified upstream: **OpenSSH 10.5p1** (portable),
  `https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.5p1.tar.gz`
  sha256 `d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11`.
- Control: the same source and flags linked against the admitted authority
  (`forensics/authorities/prefix/openssl-3.6.4-production`).

## Build command

```
./configure --prefix=<install> --sysconfdir=<install>/etc \
    --with-ssl-dir=/work/artifacts/phase2/install \
    --with-privsep-user=sshd --with-privsep-path=<install>/var/empty
make && make install
```

Note: on Linux the released `configure` leaves `rpath_opt` empty, so `--with-ssl-dir`
alone only adds `-L<candidate>/lib` to the *link*; the configure-time "OpenSSL
library version" probe then loads the system libcrypto (Debian's 3.0.22) at run
time and the header/library check fails. `build.sh` therefore also
passes `LDFLAGS=-Wl,-rpath,<candidate>/lib`. `make install` is required because
OpenSSH 10.x execs `<prefix>/libexec/sshd-session` per connection.

## Link evidence (candidate build, PASS)

```
ssh -V  ->  OpenSSH_10.5p1, OpenSSL 3.6.4 25 Aug 2026
configure: OpenSSL header version ... 30600040 (OpenSSL 3.6.4)
           OpenSSL library version .... 30600040 (OpenSSL 3.6.4)
           headers match the library ... yes
ldd sshd/ssh/ssh-keygen/ssh-agent/ssh-add:
  libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
  (no libssl, no system libcrypto)
```

## Live sshd + ssh localhost handshake

Ed25519 host key + Ed25519 user key: **PASS** (`sshd -t` ok, `sshd` starts on a
high port, `ssh root@127.0.0.1` returns `PROBE_OK` / uid 0).

Algorithm matrix, forced kex/cipher/MAC/host-key (all **PASS** except where noted):

| case | negotiated | result |
|---|---|---|
| default | kex mlkem768x25519-sha256, hostkey ssh-ed25519, cipher chacha20-poly1305 | PASS |
| x25519 / aes256-gcm | curve25519-sha256 / aes256-gcm@openssh.com | PASS |
| DH group14 / group16 / group18 | diffie-hellman-group14-sha256 / -16-sha512 / -18-sha512 | PASS (BN) |
| DH group-exchange-sha256 | diffie-hellman-group-exchange-sha256 (moduli) | PASS (BN) |
| ECDH nistp256/384/521 | ecdh-sha2-nistp256/384/521 | PASS (EC) |
| chacha20-poly1305 | chacha20-poly1305@openssh.com | PASS |
| aes128-ctr + hmac-sha1 | aes128-ctr/hmac-sha1 | PASS |
| aes128-ctr + umac-64-etm | aes128-ctr/umac-64-etm@openssh.com | PASS |
| sntrup761x25519 | sntrup761x25519-sha512 | PASS (PQ) |
| ECDSA/RSA host key | — | FAIL, see defect |
| ECDSA/RSA user-key auth | — | FAIL, see defect |

(`ssh -Q` advertises 16 kex, 16 key, 10 cipher, 16 mac, 11 sig. Finite-field DH is
absent from the **server** default in 10.5 — the authority control reports the
same `sshd -T` list — so the probe re-enables DH in `sshd_config` to exercise BN.)

ssh-keygen: RSA/ECDSA/Ed25519 keys generate and print SHA256+MD5 fingerprints;
`ssh-keygen -Y sign`/`-Y verify` works for **Ed25519 only**; `ssh-agent`+`ssh-add`
Ed25519 login works. RSA/ECDSA sign/verify and native private-key load fail (below).

## OpenSSH regress/ suite

- `make unit`, run per-binary (`regress_unit.sh`), candidate vs authority:
  - candidate: **8 pass, 5 fail** — sshbuf, **sshkey**, **kex**, **hostkeys**,
    crypto, **sshsig**, authopt, bitmap, conversion, match, misc, servconf, **utf8**.
  - authority: **12 pass, 1 fail** — only `utf8` fails on both.
  - `utf8` is environmental: it `setlocale(LC_CTYPE,"en_US.UTF-8")`; the image has
    only `C`/`C.utf8`/`POSIX` (fails identically for the authority control).
- `make file-tests`: fails at `t1` (`do_convert_private_ssh2: signing with
  converted key failed: error in libcrypto: initialization error`).
- `make t-exec LTESTS="sshcfgparse cfgparse dhgex rekey try-ciphers"`:
  **all 5 pass** (incl. the full `rekey` kex/cipher/MAC matrix over live
  connections) — though 120 "Unable to load host key" warnings show every
  ECDSA/RSA host key in the regress tree is rejected and the harness falls back to
  Ed25519.

## Defect (candidate-specific; authority control is clean)

**RSA and ECDSA signing/verification fails with `error in libcrypto: initialization
error`, and native `openssh-key-v1` RSA/ECDSA private keys cannot be parsed
(`invalid format`). Ed25519 and legacy-PEM RSA/ECDSA (read-only) are unaffected.**

Evidence:
1. Upstream's own fixed signature vectors, verified with OpenSSH's own verifier
   (`keyformat_probe` + sshsig testdata; no private-key parsing involved):
   ```
   candidate ssh-keygen -Y verify ... rsa.sig    -> Signature verification failed: error in libcrypto: initialization error
   authority ssh-keygen -Y verify ... rsa.sig    -> Good "unittest" signature ... (RSA)
   candidate ssh-keygen -Y verify ... ecdsa.sig  -> Signature verification failed: error in libcrypto: initialization error
   authority ssh-keygen -Y verify ... ecdsa.sig  -> Good "unittest" signature ... (ECDSA)
   candidate ssh-keygen -Y verify ... ed25519.sig-> Good "unittest" signature ... (ED25519)
   ```
2. Native private-key parse, candidate vs authority (`ssh-keygen -y -f`):
   candidate reads its own native RSA/ECDSA and upstream native ECDSA as
   `invalid format`; authority reads the *same* candidate-written files fine
   (so the candidate's writer is valid and its native RSA/ECDSA *reader* is
   broken). `rsa_openssh.prv`, which the candidate *can* read, is legacy PEM, not
   native. Native Ed25519 and legacy-PEM RSA/ECDSA read fine.
3. Unit-test assertions (all SIGABRT + core, candidate; authority passes):
   - `sshkey` test #15 "equal KEY_RSA/demoted KEY_RSA": `sshkey_equal(kr,k1)=0`.
   - `kex` test #5 "kex": `ssh_packet_next: incorrect signature`, `r=-21`.
   - `hostkeys` test #1, entry 2/42: `sshkey_equal(l->key, expected->l.key)=0`.
   - `sshsig` test #2 "check RSA signature": `sshsig_verifyb(...)=-22`,
     "Signature verification failed: error in libcrypto: initialization error".
4. End-to-end: RSA/ECDSA host keys are rejected by sshd and RSA/ECDSA user-key
   auth fails; the handshake falls back to Ed25519.

## Reproducible commands

```sh
# 0. court container up (bash docker/openssl-rs-court.sh up)

# 1. build candidate-linked OpenSSH + install
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/openssh/build.sh

# 2. authority-linked control (same source/flags, authority libcrypto)
bash docker/openssl-rs-court.sh exec sh -c \
  'CANDIDATE=/work/forensics/authorities/prefix/openssl-3.6.4-production \
   WORK=/court/openssh-auth PREFIX=/court/openssh-auth/install \
   sh /work/courts/phase17/downstream/openssh/build.sh'

# 3. live handshake + crypto matrix + ssh-keygen + agent
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/openssh/probe.sh

# 4. RSA/ECDSA key-format round-trip, candidate vs authority vs upstream test keys
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/openssh/keyformat_probe.sh

# 5. OpenSSH's own unit tests, per binary
bash docker/openssl-rs-court.sh exec sh -c \
  'SRC=/court/openssh-auth/openssh-10.5p1 TMO=120 \
   sh /work/courts/phase17/downstream/openssh/regress_unit.sh'   # control: 12 pass, 1 env fail
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/openssh/regress_unit.sh  # candidate: 8 pass, 4 fail

# 6. minimal defect reproducer
bash docker/openssl-rs-court.sh exec sh -c \
  'D=/court/openssh/openssh-10.5p1/regress/unittests/sshsig/testdata; \
   CK=/court/openssh/openssh-10.5p1/ssh-keygen; \
   $CK -y -f $D/rsa > /tmp/k.pub; echo "x $(cat /tmp/k.pub)" > /tmp/as; \
   $CK -Y verify -f /tmp/as -n unittest -I x -s $D/rsa.sig < $D/signed-data'

# 7. regress file-based / t-exec subset
bash docker/openssl-rs-court.sh exec sh -c \
  'cd /court/openssh/openssh-10.5p1 && make file-tests'
bash docker/openssl-rs-court.sh exec sh -c \
  'cd /court/openssh/openssh-10.5p1 && make t-exec LTESTS="sshcfgparse cfgparse dhgex rekey try-ciphers"'
```

Overrides: `CANDIDATE`, `WORK`, `PREFIX`, `PORT`, `SRC`, `TMO`.

## Toolchain

The existing `openssl-rs-court:1` image suffices (gcc 12.2.0, GNU make 4.3,
zlib headers, perl). The portable release tarball ships a generated `configure`,
and the portable top-level Makefile drives `tests`/`unit` under GNU make, so no
autotools or bsdmake is needed. No extra Dockerfile is required.
