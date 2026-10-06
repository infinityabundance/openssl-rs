# Phase 17 downstream -- unmodified haproxy against the candidate shell

Status: **build/link/start/functional all PROVEN** (PASS). This file is generated from `courts/phase17/downstream/haproxy/result.json` by `forensics/tools/gen_downstream_evidence.py`; edit the record (or re-run the driver), never this file.

## Pinned upstream

- **haproxy 3.0.29**, `https://www.haproxy.org/download/3.0/src/haproxy-3.0.29.tar.gz`
  sha256 `225dbddbab9eb0abc0ff3db39ded1e07f20028105a36f4c36fc2f85bf86835d1` (parsed from `build.sh`).
- Candidate identity: `0.0.25` (the `RT-DOWNSTREAM-CORPUS` freshness key).
- Authority: `openssl-rt-3.6.4-r2`.

## Measured result

| field | result | detail |
|---|---|---|
| build | PASS | HAProxy 3.0.29, built with the candidate OpenSSL 3.6.4 |
| link | PASS | libssl.so.3 -> /work/artifacts/phase2/install/lib/libssl.so.3 |
| start | PASS | the frontend binds and reaches readiness |
| functional | PASS | TLS 1.3 termination in front of a plain-HTTP backend for the authority s_client and the candidate curl; backend UP/L7OK; broken config rejected |
| concurrency | 16/16 | parallel operations completed |

Functional evidence (harness lines):

- `A_tls13_handshake=1`
- `B_http_code=200`
- `B_neg_exit=60`
- `B_broken_cfg_exit=1`
- `C_concurrent_200s=16/16`

## Known residuals

None measured.

## Historical failures

| exposed at | defect | fixed by |
|---|---|---|
| `6b65e05b` | candidate-linked HAProxy 3.0.29 SIGSEGV'd on the first TLS handshake: SSL_CTX_set_tlsext_servername_arg (SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG=54) had no SSL_CTX_ctrl arm, so the servername callback's priv argument stayed NULL and ssl_sock_switchctx_err_cbk dereferenced it | a742f27d (ssl: fix the HAProxy crash and handshake: SNI arg ctrl, client_hello_cb, ERR constant) |

## How to reproduce

```sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/haproxy/build.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh
```

`run_all.sh` runs this program's harness, rewrites `result.json` from the transcript, re-aggregates `forensics/atlas/downstream-corpus.json` and regenerates this file.
