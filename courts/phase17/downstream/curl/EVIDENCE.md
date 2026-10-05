# Phase 17 downstream -- unmodified curl against the candidate shell

Status: **build/link/start/functional all PROVEN** (PASS). This file is generated from `courts/phase17/downstream/curl/result.json` by `forensics/tools/gen_downstream_evidence.py`; edit the record (or re-run the driver), never this file.

## Pinned upstream

- **curl 8.22.0**, `https://curl.se/download/curl-8.22.0.tar.gz`
  sha256 `d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1` (parsed from `build.sh`).
- Candidate identity: `0.0.21` (the `RT-DOWNSTREAM-CORPUS` freshness key).
- Authority: `openssl-rt-3.6.4-r2`.

## Measured result

| field | result | detail |
|---|---|---|
| build | PASS | curl 8.22.0 (x86_64-pc-linux-gnu) libcurl/8.22.0 OpenSSL/3.6.4 zlib/1.2.13
Release-Date: 2026-09-02
Protocols: file ftp ftps http https ipfs ipns ws wss
Features: alt-svc HSTS HTTPS-proxy IPv6 Largefile libz SSL threadsafe UnixSockets |
| link | PASS | libssl.so.3 -> /work/artifacts/phase2/install/lib/libssl.so.3 |
| start | PASS | the candidate-linked curl runs and reports -V |
| functional | PASS | TLS 1.3 verified fetch of the authority s_server (HTTP 200) with an unrelated CA rejected |
| concurrency | 16/16 | parallel operations completed |

Functional evidence (harness lines):

- `live_tls_probe.sh: OK`
- `http_code=200`
- `curl_negative_exit=60`

## Known residuals

None measured.

## Historical failures

| exposed at | defect | fixed by |
|---|---|---|
| `91eb5398` | the candidate's SSL_CTX_set_min_proto_version/SSL_CTX_set_max_proto_version returned 0, so curl's TLS setup failed before a request was sent | 91eb5398 (ssl: implement SSL_CTX_ctrl/SSL_ctrl SET_MIN/MAX_PROTO_VERSION) |
| `e7b50d10` | curl fetched HTTPS without verifying the chain: the peer certificate/chain was not exposed and the post-handshake read path stalled | e7b50d10 (ssl: expose the peer certificate/chain and fix the post-handshake read path) |

## How to reproduce

```sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/curl/build.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh
```

`run_all.sh` runs this program's harness, rewrites `result.json` from the transcript, re-aggregates `forensics/atlas/downstream-corpus.json` and regenerates this file.
