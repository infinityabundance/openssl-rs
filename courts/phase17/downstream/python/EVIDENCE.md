# Phase 17 downstream -- unmodified python against the candidate shell

Status: **build/link/start/functional all PROVEN** (PASS). This file is generated from `courts/phase17/downstream/python/result.json` by `forensics/tools/gen_downstream_evidence.py`; edit the record (or re-run the driver), never this file.

## Pinned upstream

- **python 3.12.15**, `https://www.python.org/ftp/python/3.12.15/Python-3.12.15.tar.xz`
  sha256 `c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a` (parsed from `build.sh`).
- Candidate identity: `0.0.24` (the `RT-DOWNSTREAM-CORPUS` freshness key).
- Authority: `openssl-rt-3.6.4-r2`.

## Measured result

| field | result | detail |
|---|---|---|
| build | PASS | CPython 3.12.15, _ssl/hashlib built with OpenSSL 3.6.4 |
| link | PASS | _ssl*.so libssl -> /work/artifacts/phase2/install/lib/libssl.so.3 |
| start | PASS | the interpreter starts and its ssl/hashlib surface answers |
| functional | PASS | live TLS 1.3 with an unrelated CA rejected, plus CPython's own bounded test_ssl: 172 passed, 0 failed, 0 errors |
| concurrency | 16/16 | parallel operations completed |

Functional evidence (harness lines):

- `live_tls_probe.sh: OK`
- `test_ssl passed=172 failed=0 errors=0`

## Known residuals

None measured.

## Historical failures

| exposed at | defect | fixed by |
|---|---|---|
| `4aa82846` | CPython's _ssl accepted a server certificate signed by an unrelated CA: the candidate had no certificate-verification path, and the post-handshake read stalled when the caller's buffer was smaller than the record | e7b50d10 (ssl: expose the peer certificate/chain and fix the post-handshake read path) |
| `fb701d66` | CPython's own test_ssl stood at 153 passing methods while TLS 1.2 session creation/ALPN/SNI/alerts and the server-side gaps remained | 27b3e300 (ssl: TLS1.2 session creation, tickets and resumption -- CPython test_ssl all-green) |

## How to reproduce

```sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/python/build.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh
```

`run_all.sh` runs this program's harness, rewrites `result.json` from the transcript, re-aggregates `forensics/atlas/downstream-corpus.json` and regenerates this file.
