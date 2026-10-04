# Phase 17 downstream — unmodified nginx as a TLS 1.3 server against the candidate shell

Status: **build/link PROVEN; a real TLS 1.3 server WORKS for both the authority's `s_client`
and the candidate-linked curl — but nginx surfaces five concrete candidate defects.** This is a
proof slice; nothing is wired into `forensics/tools/phase17_courts.py`.

## What was built

- Candidate distribution surface: `artifacts/phase2/install/{include,lib}` (libssl.so.3 /
  libcrypto.so.3 / `openssl` CLI statically linked).
- Unmodified upstream: **nginx 1.26.3**, `https://nginx.org/download/nginx-1.26.3.tar.gz`
  sha256 `69ee2b237744036e61d24b836668aad3040dda461fe6f570f1787eab570c75aa`.
- Control: the same nginx source and flags, linked against the admitted authority's
  `libssl.so.3`/`libcrypto.so.3` (`forensics/authorities/prefix/openssl-3.6.4-production`).

## Build command

```
./configure --prefix=... --sbin-path=... --conf-path=... \
    --with-http_ssl_module \
    --without-http_rewrite_module --without-http_gzip_module \
    --with-cc-opt="-I$CANDIDATE/include" \
    --with-ld-opt="-L$CANDIDATE/lib -Wl,-rpath,$CANDIDATE/lib"
```

`--with-openssl=<path>` (as the task suggested) is **not** the way to link a prebuilt prefix:
it points nginx at an OpenSSL *source tree*, which nginx builds into `<path>/.openssl/` and
statically embeds (`auto/lib/openssl/conf`, the `OPENSSL != NONE` branch). The candidate install
prefix has no `./config`, so that path cannot work. Linking the candidate's shared
`libssl.so.3`/`libcrypto.so.3` is done with `--with-cc-opt`/`--with-ld-opt` and no
`--with-openssl`, which takes nginx's `else` branch (probe with `-lssl -lcrypto` plus the flags).
The court image has no PCRE headers (only the pcre2 runtime), so `--without-http_rewrite_module`
is required; `--without-http_gzip_module` drops zlib so the only shared objects are the
candidate's + libc.

## Link evidence (candidate build, PASS)

```
nginx version: nginx/1.26.3
built with OpenSSL 3.6.4 25 Aug 2026
configure arguments: ... --with-cc-opt=-I/work/artifacts/phase2/install/include
  --with-ld-opt='-L/work/artifacts/phase2/install/lib -Wl,-rpath,/work/artifacts/phase2/install/lib'
ldd objs/nginx:
  libssl.so.3    => /work/artifacts/phase2/install/lib/libssl.so.3
  libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
```

## Live TLS 1.3 probe — candidate vs authority control

Same script, same cert (authority-signed, `subjectAltName = IP:127.0.0.1`), TLS 1.3 only.

| probe                                                | candidate-linked nginx | authority-linked control |
|------------------------------------------------------|------------------------|--------------------------|
| (a1) `s_client` Protocol / Verification              | `TLSv1.3` / `OK`       | `TLSv1.3` / `OK`         |
| (a2) `s_client -quiet` HTTP response / exit          | `HTTP/1.1 200 OK`, **124** | `HTTP/1.1 200 OK`, **0** |
| (b) candidate curl `http_code` / verify / exit       | `200` / `0` / `0`      | `200` / `0` / `0`        |
| (c1) keep-alive, two requests                        | `num_connects` 1 then 0| same                     |
| (c2) session resumption (`-sess_out`/`-sess_in`)     | **NO ticket**          | **yes, `Reused, TLSv1.3`** |
| (c3) `nginx -t`                                      | ok                     | ok                       |
| (c3) reload workers 2 -> 3                           | 2 -> **4** (old worker stuck) | 2 -> 3 promptly    |
| (c4) 16 concurrent verified fetches                  | **14/16**, 2 handshake timeouts, 5s | **16/16**, 0 timeouts, 0s |
| error.log SNI / ticket warnings                      | 5 / 5                  | 0 / 0                    |
| error.log `SSL_read() failed ... reason(294)`        | **18**                 | 0                        |

## Defects found (all candidate-specific — the control is clean)

1. **SNI disabled.** `SSL_CTX_set_tlsext_servername_callback()` returns **0** (authority: 1), so
   nginx logs "linked ... to an OpenSSL library which has no tlsext support" and disables SNI.
   Evidence: nginx warning + `tlsext_probe` (candidate `0`, authority `1`).
2. **Session tickets disabled.** `SSL_CTX_set_tlsext_ticket_key_cb()` returns **0** (authority: 1);
   nginx disables tickets, so no TLS 1.3 session resumption (`-sess_out` produces nothing, vs the
   control's 1758-byte session that resumes as `Reused, TLSv1.3`). Same two sources.
3. **Server does not tear the connection down after `Connection: close`.** `s_client -quiet`
   receives the full `HTTP/1.1 200 OK` then **hangs until its 6s timeout (rc 124)**; the
   authority-linked control returns rc 0 for the identical client/request.
4. **`SSL_OP_IGNORE_UNEXPECTED_EOF` is not honoured.** nginx sets this option so an ungraceful
   client close is a clean EOF (control: 0 errors). The candidate instead raises
   `SSL_read() failed (SSL: error:0A000126:SSL routines::reason(294))` on every such close
   (18 in this run). reason 294 = `SSL_R_UNEXPECTED_EOF_WHILE_READING`, and the candidate also
   leaves it unmapped in the reason string ("reason(294)"), unlike the authority.
5. **Intermittent server-side handshake stall under concurrency.** 14/16 concurrent handshakes
   completed; 2 stalled and were killed by nginx's `client_header_timeout`
   (`client timed out (110) while SSL handshaking`), so curl reported `(35) Connection reset by
   peer`. The control completed 16/16 in 0s. The stall also delays graceful shutdown: after a
   reload the old worker lingers in "worker process is shutting down" (candidate reload 2->4,
   control 2->3), exiting only when the master is finally stopped.

## Reproducible commands

```sh
# 0. candidate-linked curl must already exist (courts/phase17/downstream/curl/build.sh)

# 1. build the candidate nginx
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/nginx/build.sh

# 2. build the authority-linked control nginx (same source/flags, different libssl)
bash docker/openssl-rs-court.sh exec sh -c \
  'CANDIDATE=/work/forensics/authorities/prefix/openssl-3.6.4-production \
   WORK=/court/nginx-auth INSTALL=/court/nginx-auth/install \
   sh /work/courts/phase17/downstream/nginx/build.sh'

# 3. run the probe against the candidate nginx (port 9443)
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/nginx/serve_probe.sh

# 4. run the same probe against the control (port 9444)
bash docker/openssl-rs-court.sh exec sh -c \
  'WORK=/court/nginx-auth PORT=9444 NGINX=/court/nginx-auth/nginx-1.26.3/objs/nginx \
   sh /work/courts/phase17/downstream/nginx/serve_probe.sh'

# 5. isolate the tlsext setter return values (candidate 0 / authority 1)
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/nginx/tlsext_probe.sh
```

Overrides: `CANDIDATE`, `AUTHORITY`, `WORK`, `INSTALL`, `PORT`, `CURL`, `NGINX`, `WORKERS`.
The probe starts nginx with `daemon off` and cleans up on exit; it also SIGKILLs leftover nginx
(matched on `/proc/PID/comm`, since nginx workers are non-dumpable and their `exe` link reads
empty) so reruns are clean.

## Toolchain

The existing `openssl-rs-court:1` image suffices (gcc 12.2.0, GNU make 4.3, zlib headers,
binutils); nginx 1.26.3's release tarball ships a generated `configure`, so no autotools are
needed. No extra Dockerfile is required for this slice.
