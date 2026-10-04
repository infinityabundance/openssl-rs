# Phase 17 downstream — unmodified CPython against the candidate shell

Status: **build/link PROVEN; `ssl.OPENSSL_VERSION` and `_hashlib` PROVEN; the TLS handshake
works and data is received with a ≥ record-sized buffer, but the candidate enforces NO
certificate verification and its `SSL_read_ex` cannot return a partial record.** This is a
proof slice; nothing is wired into `forensics/tools/phase17_courts.py`.

## Pinned upstream

- **CPython 3.12.15**, `https://www.python.org/ftp/python/3.12.15/Python-3.12.15.tar.xz`
  sha256 `c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a`
  (python.org publishes no `.sha256` sidecar for this release — only `.spdx.json`/`.sigstore` —
  so the pin is the hash of the downloaded artifact; the build script re-checks it).
- Candidate distribution surface: `artifacts/phase2/install/{include,lib}` (the same shell
  curl was built against; git `e7b50d10`).
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
build.sh: sha256 ok for Python-3.12.15.tar.xz
checking whether OpenSSL provides required ssl module APIs... yes
checking whether OpenSSL provides required hashlib module APIs... yes
checking for stdlib extension module _ssl... yes
Python 3.12.15 (main, Oct  4 2026, 13:17:57) [GCC 12.2.0]
_ssl = .../build/lib.linux-x86_64-3.12/_ssl.cpython-312-x86_64-linux-gnu.so
  libssl.so.3    => /work/artifacts/phase2/install/lib/libssl.so.3
  libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
```

The interpreter itself does not link libssl (as expected); the `_ssl` extension does, and its
RUNPATH resolves both from the candidate. `import ssl` therefore loads the candidate.

## (a) `ssl` / `_hashlib` probe (PASS)

`probe.py` output, abridged:

```
ssl.OPENSSL_VERSION: OpenSSL 3.6.4 25 Aug 2026
ssl.OPENSSL_VERSION_INFO: (3, 6, 0, 4, 0)
ssl.HAS_TLSv1_3: True
ssl.TLSVersion members: ['MINIMUM_SUPPORTED','SSLv3','TLSv1','TLSv1_1','TLSv1_2','TLSv1_3','MAXIMUM_SUPPORTED']
ssl.create_default_context(): OK  (protocol=16, verify_mode=2, check_hostname=True, min=771 max=-1)
SSLContext(PROTOCOL_TLS_CLIENT): min=771 max=-1
SSLContext(PROTOCOL_TLS_SERVER): min=771 max=-1
after set min/max: min=771 max=772
hashlib.sha256(b'abc'): ba7816bf...f20015ad
hmac.new(key,msg,sha256): 2d93cbc1...b8c628
pbkdf2_hmac(sha256): 0a382535...c5567e
scrypt(n=16,r=1,p=1): 086be1ce...afecb7
```

`SSL_CTX_set_min/max_proto_version` (the ctrl curl once tripped on, fixed at git `91eb5398`)
now returns success and reads back correctly, so `create_default_context()` and both
`PROTOCOL_TLS_*` constructors succeed.

## (b) Live TLS 1.3 client against the authority's `s_server` (MIXED)

`live_tls_probe.sh` starts the authority's `openssl s_server -tls1_3 -www` with a CA and a
server cert carrying `subjectAltName = IP:127.0.0.1`, then runs the candidate-linked
`tls_client.py`. Result:

```
negotiated_version = 'TLSv1.3'
cipher             = None  (candidate SSL_get_current_cipher returns NULL)
cert_present       = True
cert_subject       = {'commonName': '127.0.0.1'}
DATA (16 KiB buffer) = ok, 5036 bytes, status 'HTTP/1.0 200 ok'
VERIFY_NEGATIVE = FAIL: server cert accepted though signed by an unrelated CA
recv(1024) = TimeoutError: SSL_read_ex stalls when buffer < record size
recv(4096) = TimeoutError: SSL_read_ex stalls when buffer < record size
```

The handshake, the peer-certificate parse and the transport all work; **three candidate
defects** are exposed:

1. **Certificate verification is not enforced.** With `PROTOCOL_TLS_CLIENT`
   (`verify_mode=CERT_REQUIRED`, `check_hostname=True`) an unrelated CA is accepted, and an
   *empty* trust store still connects. Root cause in the candidate: `tls_process_server_certificate`
   (`src/ssl/statem/statem_clnt.rs:1283-1302`) stores the presented chain and copies it into
   `verified_chain` **without ever calling `ssl_verify_cert_chain`/`X509_verify_cert`** — it
   trusts anything the peer sends. This is a security defect; curl's positive-only `--cacert`
   probe did not catch it.
2. **`SSL_read_ex` cannot return a partial record.** It delivers plaintext only when the
   caller's buffer is ≥ the TLS record size (5036 bytes here); a smaller buffer stalls until
   timeout. curl passes because its receive buffer is 16 KiB; CPython's `SSLSocket.recv()`
   defaults are 1024/8192, so a real Python consumer hangs on a normal HTTPS response.
3. **`SSL_get_current_cipher` returns NULL** after a TLS 1.3 handshake (`Socket.cipher()` is
   `None`).

## (c) CPython's own `test_ssl` (bounded)

The plain `./python -m test -v -u all,-network test_ssl` run **hangs** on defect (2)
(`test_bio_handshake` never returns). `run_test_ssl.sh` therefore uses
`bounded_test_ssl.py`: it runs each of the 179 unique test-method groups as its own
`./python -m test -v -u all,-network -m <name> test_ssl` under a 20 s `timeout`, 4-way
parallel, so hangs are recorded as timeouts. Counts over all **187** cases:

```
passed   : 119
failed   :  26
errors   :  10
skipped  :  15
timed out:  16
unknown  :   1   (test_socketserver segfaulted)
```

Exact failures (representative, from `bounded_logs/*.log`):

- `test_ssl_cert_verify_error` — `AssertionError: Expected connection failure`
  (test_ssl.py:3389): an untrusted-cert connection succeeded.
- `test_wrong_cert_tls13` — `AssertionError: SSLError not raised` (test_ssl.py:3323):
  expected `TLSV1_ALERT_UNKNOWN_CA`.
- `test_check_hostname` — `AssertionError: SSLCertVerificationError not raised`
  (test_ssl.py:3121): hostname mismatch accepted.
- `test_tls1_3` — `TypeError: 'NoneType' object is not subscriptable` (test_ssl.py:3964):
  `s.cipher()[0]` where `cipher()` is `None` (defect 3).
- `test_alpn_protocols` — `AssertionError: None != 'foo'` — ALPN selection not surfaced.
- `test_ecdh_curve`, `test_load_dh_params` — `ssl.SSLError: unknown error` — missing
  `SSL_CTX_set1_groups`/`SSL_CTX_set_tmp_dh` surface.
- `test_unwrap` — `ssl.SSLSyscallError: Some I/O error occurred`.
- `test_socketserver` — **Segmentation fault** (core dumped); recorded as `unknown`.
- 16 timeouts, all local handshake/read tests (`test_bio_handshake`, `test_session`,
  `test_bio_read_write_data`, `test_dual_rsa_ecc`, `test_msg_callback_tls12`, …),
  consistent with defect (2).

Of the 26 failures, the majority (`test_check_hostname*`, `test_ssl_cert_verify_error`,
`test_wrong_cert_tls13`, `test_internal_chain_*`, `test_pha_*`, `test_connect_*_fail`,
`test_get_server_certificate_fail`, `test_crl_check`) are direct consequences of defect (1);
`test_wrong_cert_tls12` and the other handshake tests are in the 16 timeouts.

## What did not work / caveats

- The full unbounded `test_ssl` run hangs (see above); the bounded harness is a proof-slice
  tool, not a court harness, and 4-way parallelism could in principle perturb port-bound
  tests. Counts are therefore approximate but every listed failure was reproduced standalone.
- The `ssl_verify_result = 0` goal is **not** met: the candidate performs no verification, so
  "verified" cannot be claimed. The `s_server` did receive the request and send a 5036-byte
  response (verified with `-msg`), so this is a client-side verification gap, not a transport
  failure.
- `_hashlib` (sha256/sha1/md5/sha3/blake2b, hmac, pbkdf2, scrypt) all pass, so the EVP
  surface is exercised through a real consumer without failure.

## To make this court green (next slices, not done here)

1. Call `X509_verify_cert` (chain + hostname) in `tls_process_server_certificate` /
   `tls_post_process_server_certificate` and fail the handshake on error.
2. Buffer the unread tail of a record in `ssl_read_internal` so `SSL_read_ex` can satisfy a
   read smaller than the record.
3. Return the negotiated cipher from `SSL_get_current_cipher` for TLS 1.3.
