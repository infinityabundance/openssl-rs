# Phase 17 downstream — unmodified CPython against the candidate shell

Status: **build/link PROVEN; `ssl.OPENSSL_VERSION` and `_hashlib` PROVEN; the TLS 1.3 handshake,
certificate verification, the partial-read path and `cipher()` are all PROVEN.** The three
candidate defects this slice originally exposed are fixed; a fourth (a stack-buffer overflow on
an application write larger than one record) was found while investigating the `test_socketserver`
segfault and is fixed too.

## Pinned upstream

- **CPython 3.12.15**, `https://www.python.org/ftp/python/3.12.15/Python-3.12.15.tar.xz`
  sha256 `c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a`
  (python.org publishes no `.sha256` sidecar for this release — only `.spdx.json`/`.sigstore` —
  so the pin is the hash of the downloaded artifact; the build script re-checks it).
- Candidate distribution surface: `artifacts/phase2/install/{include,lib}` (the same shell
  curl was built against).
- Authority server: `forensics/authorities/prefix/openssl-3.6.4-production/bin/openssl`.

The existing `openssl-rs-court:1` image is sufficient: gcc 12.2.0, GNU make 4.3, perl 5.36,
pkg-config 1.8.1, zlib headers. **No extra Dockerfile is required.**

## Reproducible command sequence

```sh
# from the repository root, court container up:
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/python/build.sh
bash docker/openssl-rs-court.sh exec \
  /court/python/Python-3.12.15/python /work/courts/phase17/downstream/python/probe.py
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/python/live_tls_probe.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/python/run_test_ssl.sh
```

`build.sh` fetches the tarball, checks the sha256, then configures with
`--with-openssl=$CANDIDATE --with-openssl-rpath=auto --without-ensurepip` and
`CPPFLAGS=-I$CANDIDATE/include`, `LDFLAGS=-L$CANDIDATE/lib -Wl,-rpath,$CANDIDATE/lib`, builds
in-tree (no install step), and prints `python -VV`, `ldd python` and `ldd _ssl*.so`.

## Build / link result (PASS)

```
Python 3.12.15 (main, Oct  4 2026, 13:17:57) [GCC 12.2.0]
  libssl.so.3    => /work/artifacts/phase2/install/lib/libssl.so.3
  libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
```

## (a) `ssl` / `_hashlib` probe (PASS)

`probe.py` proves `ssl.OPENSSL_VERSION` is `OpenSSL 3.6.4`, `HAS_TLSv1_3`, the `TLSVersion`
members, `create_default_context()`, both `PROTOCOL_TLS_*` constructors and the `_hashlib`
surface (sha256/sha1/md5/sha3/blake2b, hmac, pbkdf2, scrypt).

## (b) Live TLS 1.3 client against the authority's `s_server` (PASS)

```
negotiated_version = 'TLSv1.3'
cipher             = 'TLS_AES_256_GCM_SHA384'   # was None (defect 3)
cert_present       = True
cert_subject       = {'commonName': '127.0.0.1'}
DATA (16 KiB buffer) = ok, 5036 bytes, status 'HTTP/1.0 200 ok'
VERIFY_NEGATIVE = ok, rejected (verify_code=20)  # was accepted (defect 1)
recv(1024) = ok                                  # was TimeoutError (defect 2)
recv(4096) = ok
```

The three defects and their fixes:

1. **Certificate verification** — `tls_process_server_certificate` now calls the new
   `ssl_verify_cert_chain` (`src/ssl/ssl_cert.rs`, from `ssl/ssl_cert.c:427-553`) after parsing
   the chain, honouring `SSL_VERIFY_PEER`/`SSL_VERIFY_NONE`, building the chain and verifying it
   against `ctx->cert_store` with the connection's `X509_VERIFY_PARAM` (so the hostname/IP check
   runs), setting `SSL_get_verify_result` and `verified_chain`, and on failure raising
   `SSL_R_CERTIFICATE_VERIFY_FAILED` with the `ssl_x509err2alert` alert
   (`statem_lib.c:1823-1832`). An unrelated CA is now rejected with `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY`
   (20); an empty trust store with `CERT_REQUIRED` fails the same way.
2. **Partial reads** — `ssl_read_internal` (`src/ssl/ssl_lib.rs`) decrypts a whole record into a
   connection buffer (`rx_buf`/`rx_off`/`rx_len`, the reduction of the authority's
   `s->rlayer.tlsrecs[i].data`/`off`, `rec_layer_s3.c:778-823`) and returns
   `min(requested, available)`, keeping the tail for the next call. `recv(1024)` on a 5036-byte
   record no longer stalls.
3. **`SSL_get_current_cipher`** — returns the negotiated `SSL_CIPHER` from `pending_cipher`
   (`s3.tmp.new_cipher`) when there is no session; `SSL_CIPHER_get_name`/`_get_protocol_id` then
   answer, so `Socket.cipher()` is `('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)`.

## (c) The `test_socketserver` segfault (candidate, fixed)

`test_socketserver` served a 230 377-byte file and the candidate server process **segfaulted**.
With no gdb in the image, an `LD_PRELOAD` `SIGSEGV` handler (`segv_trace.c`) captured a wild
write at the very top of the main thread's stack and a return address inside
`openssl_rs::ssl::tls13_enc::tls13_encrypt_record`. Root cause:
`ssl3_write_bytes` (`src/ssl/record/rec_layer_s3.rs`) passed the caller's entire `len` to
`tls13_encrypt_record`, whose local `inner = [0u8; TLS13_HS_BUF_LEN + 1]` (16385 bytes) was
overwritten by a response larger than one record. Fixed by fragmenting every `SSL_write` into
`SSL3_RT_MAX_PLAIN_LENGTH` (16384)-byte records through `ssl3_write_one_record`, as the
authority's `tls_write_records_default` does. `test_socketserver` now passes:
`client: read 230377 bytes ... ok`.

## (d) CPython's own `test_ssl` (bounded)

`bounded_test_ssl.py` runs each of the 179 unique test-method groups as its own 20 s regrtest
invocation, 4-way parallel. Counts over all **187** cases:

```
                before   after
passed   :        119  ->  120
failed   :         26  ->   14
errors   :         10  ->    9
skipped  :         15  ->   15
timed out:         16  ->   29
unknown  :          1  ->    0   (test_socketserver segfault)
```

The crash is gone (`unknown` 1 → 0, and `test_socketserver` passes). The shift from `failed` to
`timed out` is expected and is a *server-side* gap exposed by the now-correct client: tests such
as `test_check_hostname`, `test_connect_fail`, `test_ssl_cert_verify_error` and
`test_wrong_cert_tls12` used to fail fast because the client wrongly *accepted* the certificate;
now the client correctly raises `SSLCertVerificationError` and stops sending, but the test's
**candidate-side server thread** does not notice the abort (no alert/EOF handling on
`SSL_accept`) and blocks, so the test times out instead of reporting the expected failure.
Isolated stand-alone: a candidate server with the correct CA completes the handshake, while a
client with an unrelated CA raises `SSLCertVerificationError` and the candidate server thread
stays alive. That server-side abort handling is not one of this slice's three defects.

## What did not work / caveats

- The full unbounded `test_ssl` run still hangs on the server-side gap above; the bounded harness
  is a proof-slice tool under 20 s timeouts, so counts are approximate but each observation was
  reproduced standalone.
- `segv_trace.c` is diagnostic tooling (like the curl directory's `trace_preload.c`), not a court.

## To make this court green (next slices, not done here)

1. Handle a peer fatal alert / EOF on the server-side read path so `SSL_accept` returns instead
   of blocking (turns the new timeouts back into the tests' expected failures/passes).
2. Remaining non-verification failures are unrelated missing surface: ALPN selection
   (`test_alpn_protocols`), `SSL_CTX_set1_groups`/`SSL_CTX_set_tmp_dh`
   (`test_ecdh_curve`/`test_set_ecdh_curve`/`test_load_dh_params`), `SSL_unwrap`
   (`test_unwrap`), SNI callbacks, keylog, PHA and session resumption.
