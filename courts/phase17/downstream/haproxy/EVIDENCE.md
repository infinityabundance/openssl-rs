# Phase 17 downstream — unmodified HAProxy 3.0.29 against the candidate shell

Status: **build/link PROVEN; HAProxy's own config check passes, but the candidate cannot run a TLS
listener: the candidate-linked HAProxy 3.0.29 crashes with SIGSEGV on a TLS handshake, and never
completes one even when it survives.** The authority-linked control (same source, same flags,
authority `libssl`/`libcrypto`) terminates TLS 1.3 cleanly for every probe. **The SIGSEGV root
cause is pinpointed to a single missing candidate API arm.** This is a proof slice; nothing is
wired into `forensics/tools/phase17_courts.py`.

## What was built

- Candidate distribution surface: `artifacts/phase2/install/{include,lib}` (libssl.so.3 /
  libcrypto.so.3 / `.a` pair; `openssl` CLI statically linked).
- Unmodified upstream: **HAProxy 3.0.29**, `https://www.haproxy.org/download/3.0/src/haproxy-3.0.29.tar.gz`
  sha256 `225dbddbab9eb0abc0ff3db39ded1e07f20028105a36f4c36fc2f85bf86835d1` (the digest published by
  haproxy.org; the release tarball carries its own generated version metadata — no autotools step).
- Control: the same HAProxy source and flags, linked against the admitted authority's real
  `libssl.so.3`/`libcrypto.so.3` (`forensics/authorities/prefix/openssl-3.6.4-production`).

## Build command (verbatim)

```
make -j"$(nproc)" TARGET=linux-glibc USE_OPENSSL=1 USE_ZLIB=1 \
    SSL_INC=/work/artifacts/phase2/install/include \
    SSL_LIB=/work/artifacts/phase2/install/lib \
    LDFLAGS="-Wl,-rpath,/work/artifacts/phase2/install/lib"
```

`SSL_INC`/`SSL_LIB` are HAProxy's own switches for a non-system OpenSSL prefix (Makefile lines
~609–632): they become `-I<$CAND>/include` and `-L<$CAND>/lib -lssl -lcrypto`, a **shared** link.
`LDFLAGS` is passed on the final link (Makefile line ~1041) and bakes the rpath. **No HAProxy
source is modified.** The image has no PCRE2 headers, so the build is left PCRE-less and HAProxy
falls back to the libc POSIX regex (`src/regex.c` `#else … regexec()`); regex ACLs are irrelevant
to TLS. No extra Dockerfile is needed — the existing `openssl-rs-court:1` image suffices.

## Link evidence (candidate build, PASS)

```
haproxy -vv:
  OPTIONS = USE_OPENSSL=1 USE_ZLIB=1
  Feature list : ... +OPENSSL ... -PCRE -PCRE2 ... +THREAD +ZLIB
  Built with OpenSSL version : OpenSSL 3.6.4 25 Aug 2026
  Running on OpenSSL version : OpenSSL 3.6.4 25 Aug 2026
ldd haproxy:
  libssl.so.3    => /work/artifacts/phase2/install/lib/libssl.so.3
  libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
readelf -d:
  NEEDED  libssl.so.3, libcrypto.so.3
  RUNPATH /work/artifacts/phase2/install/lib
```

The candidate and the authority both call themselves `OpenSSL 3.6.4 25 Aug 2026`, so the version
string does **not** identify the library — the `ldd` paths and the `RUNPATH` do.

## Live proxy probe — candidate vs authority control

HAProxy terminates TLS 1.3 on `127.0.0.1:$PORT` (`bind … ssl crt … ssl-min-ver TLSv1.3
ssl-max-ver TLSv1.3`) and proxies to a plain-HTTP `python3 -m http.server`. Cert is
authority-signed, `subjectAltName = IP:127.0.0.1`. Candidate ports 18445/18081, control
18446/18082 (`proxy_probe.sh` preflights both ports so a leftover server can never impersonate
HAProxy).

| probe                                            | candidate-linked HAProxy | authority control |
|--------------------------------------------------|--------------------------|-------------------|
| `haproxy -c -f` config check                     | ok                       | ok                |
| `haproxy -c` on a broken config                  | rejected (exit 1)        | rejected (exit 1) |
| readiness: verified HTTPS fetch → 200            | **never (server dead)**  | 200 in 0.5 s      |
| HAProxy process after first handshake            | **SIGSEGV, exit 139**    | alive             |
| (a1) authority `s_client` TLSv1.3 / Verification | **none**                 | TLSv1.3 / OK      |
| (a2) authority `s_client -quiet` HTTP response   | **none**                 | `HTTP/1.0 200 OK` |
| (b) candidate curl http/verify/exit              | **000 / 1 / 35**         | 200 / 0 / 0       |
| (b2) candidate curl, unrelated CA                | rejects (exit 60)        | rejects (exit 60) |
| (c1) stats socket, backend `s1`                  | n/a (server dead)        | `UP` `L7OK`       |
| (c2) 16 concurrent verified fetches              | **0/16**                 | **16/16**, 1 s    |

## Defect — candidate-linked HAProxy 3.0.29 SIGSEGVs on the first TLS handshake

Reproduced 2/3 (the third run survives but still fails the handshake); the probe's readiness loop
hits it on the first attempt. Client sees `curl exit 35` / `error:0A000126:SSL routines::reason(294)`
(unexpected EOF). Backtrace from the LD_PRELOAD handler (`segv_trace.c`, HAProxy source untouched):

```
haproxy(ssl_sock_switchctx_err_cbk+0x1d)          <- faulting frame
libssl.so.3(+0x371e1a)   /work/artifacts/phase2/install/lib/libssl.so.3
libssl.so.3(+0x25b402)
libssl.so.3(+0x25d1a0)
haproxy(ssl_sock_io_cb+0x8fd)
haproxy(run_tasks_from_lists+0x1ac) ... haproxy(main+0x1fd1)
```

`objdump` pins the exact instruction: `ssl_sock_switchctx_err_cbk+0x1d` is
`mov 0xf8(%rbx),%eax` — a dereference of the callback's third argument (`priv`), which is **NULL**.

HAProxy's contract (`src/ssl_sock.c`):

```
SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);          // arg = NULL
SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk); // cb(ssl, al, priv)
SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);                       // priv = bind_conf
```

and the callback (`src/ssl_sock.c:2184`) dereferences `priv`:

```c
int ssl_sock_switchctx_err_cbk(SSL *ssl, int *al, void *priv) {
    struct bind_conf *s = priv;
    if (SSL_get_servername(ssl, ...) || (s->options & BC_O_GENERATE_CERTS)) …   /* s == NULL */
```

**Root cause (candidate side).** The candidate's `SSL_CTX_set_tlsext_servername_arg` is the macro
`SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, arg)` (`tls1.h`), but the candidate's
`SSL_CTX_ctrl` (`src/ssl/ssl_lib.rs`) has **no arm for `SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG` (54)** —
it defines/handles only `…_SERVERNAME_CB` (53). Command 54 therefore falls through, returns 0, and
never stores `ctx.servername_arg`, which stays NULL. When the handshake later invokes the callback,
`final_server_name` (`src/ssl/statem/statem_srvr.rs`) passes `(*ctx).servername_arg` = NULL, and
HAProxy dereferences it.

**Minimal isolation** (`sni_arg_probe.c` / `sni_arg_probe.sh`): a same-library server/client
socketpair, `SSL_CTX_set_tlsext_servername_arg(ctx, MAGIC)` then one handshake —

```
candidate:  server: handshake=ok callback_fired=1 arg_matches=0   (libssl+libcrypto both candidate)
authority:  server: handshake=ok callback_fired=1 arg_matches=1
```

The callback fires but receives a pointer other than the one set — exactly the missing ctrl arm.

## Second defect — no TLS handshake completes even when HAProxy survives

With the authority `s_client` as client, the candidate HAProxy does **not** crash but never
completes a handshake either: the server logs
`SSL handshake failure (error:0A0C0001:SSL routines::reason(1))` and the client reports
`error:0A000126:unexpected eof while reading`. 0/3 handshakes succeeded; 2/3 additionally crashed.
(The candidate client `curl` also fails at 35/000.) The control completes TLSv1.3 with
`Verification: OK` for both clients. This is a second, distinct candidate surface (HAProxy is the
first downstream consumer to drive `SSL_CTX_set_client_hello_cb`), reported here as observed.

## HAProxy's own regression tests — not tractable

Not runnable in this court, for two independent reasons. (1) `reg-tests/` (34 suites) is driven by
`vtest` (VTest2, a Varnish-derived harness that is **not** shipped in the HAProxy tarball and is
absent from the image); HAProxy's `make reg-tests` only prints how to point `VTEST_PROGRAM` at an
externally built `vtest`. (2) Even with `vtest`, essentially every TLS reg-test starts a HAProxy
`ssl` listener, which the candidate cannot serve (it crashes or aborts the handshake, above), so the
TLS suites could not pass regardless. The live proxy demonstration plus `haproxy -c` are the
functional evidence instead.

## Reproducible commands

```sh
# from the repository root, court container up (bash docker/openssl-rs-court.sh up)

# 0. candidate-linked curl must already exist (courts/phase17/downstream/curl/build.sh)
# 1. build the candidate HAProxy
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/haproxy/build.sh

# 2. build the authority-linked control (same source/flags, different libssl)
bash docker/openssl-rs-court.sh exec sh -c \
  'CANDIDATE=/work/forensics/authorities/prefix/openssl-3.6.4-production \
   WORK=/court/haproxy-auth sh /work/courts/phase17/downstream/haproxy/build.sh'

# 3. live probe, candidate (ports 18445/18081) — reports the SIGSEGV and exits 3
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/haproxy/proxy_probe.sh

# 4. live probe, control (ports 18446/18082) — full PASS
bash docker/openssl-rs-court.sh exec sh -c \
  'WORK=/court/haproxy-auth HAPROXY=/court/haproxy-auth/haproxy-3.0.29/haproxy \
   PORT=18446 BACKEND_PORT=18082 sh /work/courts/phase17/downstream/haproxy/proxy_probe.sh'

# 5. crash backtrace (LD_PRELOAD handler; reuses step 3's config)
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/haproxy/crash_trace.sh

# 6. minimal isolation of the servername-callback argument
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/haproxy/sni_arg_probe.sh
```

Overrides: `CANDIDATE`, `AUTHORITY`, `WORK`, `PORT`, `BACKEND_PORT`, `CURL`, `HAPROXY`.

## Caveats

- `haproxy -vv` records the candidate only through `USE_OPENSSL=1` and the OpenSSL version string;
  because the authority is also 3.6.4, the path proof is `ldd` + `RUNPATH`, not `-vv`.
- HAProxy is built without PCRE/PCRE2 (headers absent), using the libc regex fallback; noted in
  `haproxy -vv` as `-PCRE -PCRE2` and `Built without PCRE or PCRE2 support`. TLS is unaffected.
- The court container is long-lived and other slices leave servers behind; `proxy_probe.sh` refuses
  to run if its ports are occupied (a squatter previously answered in HAProxy's place during
  bring-up and produced a bogus 200 — the preflight prevents that class of error).
- `crash_trace.sh` uses a fatal-signal backtrace handler because the image ships no gdb and core
  dumps are piped to a `systemd-coredump` that is not present in the container.
