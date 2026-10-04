# Phase 17 downstream — unmodified curl against the candidate shell

Status: **build/link PROVEN; live TLS fetch FAILS inside the candidate**, with the exact stop
point isolated. This is a proof slice; nothing is wired into `forensics/tools/phase17_courts.py`.

## What was built

- Candidate distribution surface: `artifacts/phase2/install/{include,lib}` (libssl.so.3 /
  libcrypto.so.3 / libcrypto.a / libssl.a, `openssl` CLI is statically linked).
- Unmodified upstream: **curl 8.22.0**, `https://curl.se/download/curl-8.22.0.tar.gz`
  sha256 `d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1` (release tarball,
  which already ships a generated `configure` — no autotools needed).
- Hostile server for the live test: the admitted authority's `openssl s_server`
  (`forensics/authorities/prefix/openssl-3.6.4-production/bin/openssl`), real upstream 3.6.4.

## Toolchain found in `openssl-rs-court:1`

gcc 12.2.0, GNU make 4.3, perl 5.36, pkg-config 1.8.1, zlib headers, binutils. **No**
autotools, libtool, cmake, `openssl` CLI (deliberately removed), `stunnel`/`nghttpd`.
The existing court image is therefore sufficient for the build and the live fetch; **no extra
Dockerfile is required for this slice.**

## Reproducible commands

```sh
# from the repository root, court container up:
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/curl/build.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/curl/live_tls_probe.sh
```

`build.sh` fetches the pinned tarball, checks its sha256, configures with
`--with-openssl=$CANDIDATE --disable-shared …`, builds, then prints `curl -V` and `ldd`.

## Build result (PASS)

```
build.sh: sha256 ok for curl-8.22.0.tar.gz
configure: OpenSSL with QUIC APIv2
  SSL: enabled (OpenSSL)        # curl version: 8.22.0
curl 8.22.0 (x86_64-pc-linux-gnu) libcurl/8.22.0 OpenSSL/3.6.4 zlib/1.2.13
ldd:
  libssl.so.3    => /work/artifacts/phase2/install/lib/libssl.so.3
  libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
RUNPATH: /work/artifacts/phase2/install/lib
```

`curl -V` reports `OpenSSL/3.6.4`; `ldd` resolves both shared objects from the candidate install.

## Live TLS 1.3 fetch (FAIL)

Against the authority's `s_server` with a CA-signed server cert carrying
`subjectAltName = IP:127.0.0.1`:

```
*   Trying 127.0.0.1:8443...
* closing connection #0
curl: (35) SSL connect error
http_code=000
```

The server logs `SSL routines::unexpected eof while reading`. The candidate-linked curl aborts
in `Curl_ossl_ctx_init` before the handshake.

## Root cause (isolated, candidate-side)

`LD_PRELOAD` interposition of the candidate's libssl shows curl stops immediately after:

```
SSL_CTX_new -> 0x…
SSL_CTX_ctrl cmd=16  larg=0   -> 1      # SSL_CTRL_SET_MSG_CALLBACK_ARG
SSL_CTX_ctrl cmd=123 larg=771 -> 0      # SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION
```

curl's `ossl_set_ssl_version_min_max()` (lib/vtls/openssl.c) is:

```c
if(!SSL_CTX_set_min_proto_version(ctx, ossl_ssl_version_min) ||
   !SSL_CTX_set_max_proto_version(ctx, ossl_ssl_version_max))
    return CURLE_SSL_CONNECT_ERROR;   /* no failf() -> generic "(35) SSL connect error" */
```

The candidate's `SSL_CTX_ctrl` returns **0 for `SSL_CTRL_SET_MIN_PROTO_VERSION` (123) and
`SSL_CTRL_SET_MAX_PROTO_VERSION` (124)** and its `SSL_CTX_get_min_proto_version` stays 0;
the authority returns 1 and reads back 771 (TLS1_2). No `src/**/*.rs` implements these arms.
Because curl treats a 0 return as fatal, no unmodified curl can start a TLS connection against
the candidate — regardless of TLS version or ALPN (`--no-alpn`, `--tlsv1.2` all fail identically).

Control experiments that isolate the defect to the candidate:

1. The **same** `src/curl` binary, run with `LD_LIBRARY_PATH=<authority>/lib`, completes a full
   TLS 1.3 handshake and returns `http_code=200` from the same server.
2. A minimal candidate-linked client (`client_probe.c`) that ignores the ctrl return value
   completes a real TLS 1.3 handshake against the authority server (the server logs the full
   handshake state sequence), so the crypto/handshake path itself works.
3. `ctrl_probe.c` prints the return divergence directly (authority 1/771 vs candidate 0/0).

Diagnostics in this directory: `client_probe.c` (socket TLS client), `bio_probe.c`
(`SSL_set_fd` vs `SSL_set0_rbio/wbio`), `ctrl_probe.c` (ctrl return divergence),
`trace_preload.c` (`LD_PRELOAD` tracer). They are evidence tooling, not courts.

## curl test suite (not run)

- `make -C tests` fails: `tests/certs/genserv.pl` requires an `openssl` CLI, which the court
  image deliberately removes.
- The TLS subset additionally needs `stunnel` (absent), and TLS tests are the only ones that
  exercise libssl; plain-HTTP tests exercise only libc/network code.
- Most importantly, every TLS test would fail for the same `SSL_CTX_set_min_proto_version`
  reason as the live fetch. A full-suite run would duplicate, not extend, the finding.

The live fetch is therefore the demonstration, with its negative result explained above.

## To make the court green (next slice, not done here)

Implement `SSL_CTRL_SET_MIN_PROTO_VERSION` / `SSL_CTRL_SET_MAX_PROTO_VERSION` in the candidate's
`SSL_CTX_ctrl` (returning 1 and storing/reading the bound, matching OpenSSL 3.6.4). Once that
lands, `live_tls_probe.sh` should exit 0 and a bounded curl test subset becomes meaningful.
