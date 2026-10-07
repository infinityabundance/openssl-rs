# Phase 17 downstream -- unmodified nginx against the candidate shell

Status: **build/link/start/functional all PROVEN** (PASS). This file is generated from `courts/phase17/downstream/nginx/result.json` by `forensics/tools/gen_downstream_evidence.py`; edit the record (or re-run the driver), never this file.

## Pinned upstream

- **nginx 1.26.3**, `https://nginx.org/download/nginx-1.26.3.tar.gz`
  sha256 `69ee2b237744036e61d24b836668aad3040dda461fe6f570f1787eab570c75aa` (parsed from `build.sh`).
- Candidate identity: `0.0.27` (the `RT-DOWNSTREAM-CORPUS` freshness key).
- Authority: `openssl-rt-3.6.4-r2`.

## Measured result

| field | result | detail |
|---|---|---|
| build | PASS | nginx/1.26.3, built with OpenSSL 3.6.4 |
| link | PASS | libssl.so.3 -> /work/artifacts/phase2/install/lib/libssl.so.3 |
| start | PASS | the TLS listener starts and answers an authority s_client |
| functional | PASS | TLS 1.3 termination for the authority s_client and the candidate curl, 16/16 concurrent verified fetches, reload 2->3 workers, post-handshake NewSessionTicket + TLS 1.3 resumption |
| concurrency | 16/16 | parallel operations completed |

Functional evidence (harness lines):

- `A_tls13_handshake=1`
- `B_http_code=200`
- `C_concurrent_200s=16/16`
- `D_tls13_resumed=1`

## Known residuals

None measured.

## Historical failures

| exposed at | defect | fixed by |
|---|---|---|
| `6448fa4c` | nginx 1.26.3 exposed five candidate defects: SNI disabled (tlsext servername callback returned 0), TLS session tickets disabled, no close_notify teardown after Connection: close, SSL_OP_IGNORE_UNEXPECTED_EOF not honoured, and an intermittent server-side handshake stall under concurrency | 3e1c5313 (ssl: fix the nginx-exposed defects: SNI, ticket cb, close_notify, EOF option, record resync) |

## How to reproduce

```sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/nginx/build.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh
```

`run_all.sh` runs this program's harness, rewrites `result.json` from the transcript, re-aggregates `forensics/atlas/downstream-corpus.json` and regenerates this file.
