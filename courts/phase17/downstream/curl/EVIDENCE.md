# Phase 17 downstream — unmodified curl against the candidate shell

Status: **build/link PROVEN; the live TLS 1.3 fetch SUCCEEDS and certificate verification is
enforced** (an unrelated CA is rejected). This is a proof slice; nothing is wired into
`forensics/tools/phase17_courts.py`.

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

## Live TLS 1.3 fetch (PASS)

Against the authority's `s_server` with a CA-signed server cert carrying
`subjectAltName = IP:127.0.0.1`, the candidate-linked curl completes the fetch:

```
*   subjectAltName: "127.0.0.1" matches cert's IP address!
* OpenSSL verify result: 0
* SSL certificate verified via OpenSSL.
< HTTP/1.0 200 ok
http_code=200
ssl_verify_result=0
curl_exit=0
```

## Negative verification arm (PASS)

The same server, fetched with an **unrelated CA** the certificate is not signed by, is rejected:

```
=== live HTTPS fetch, UNRELATED CA (must FAIL verification) ===
neg_http_code=000
neg_ssl_verify_result=20
curl_negative_exit=60
curl: (60) SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)
```

`ssl_verify_result=20` is `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, so the positive arm's
`verify result: 0` is genuine verification, not a skipped check. Both arms are driven by
`live_tls_probe.sh`, which fails if the positive fetch fails *or* the negative fetch succeeds.

## History

The earlier slices that this file recorded — `SSL_CTX_set_min/max_proto_version` returning 0,
and then the missing certificate-verification path — are fixed at git `91eb5398` and the current
Phase 17 client-verification slice respectively; the live fetch now succeeds end to end.
