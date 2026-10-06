# Phase 14 — TLS / DTLS (`libssl`): seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. The stratum's export ledger is empty of open rows —
`forensics/phase14-obligations.json:9` reads `open_in_this_stratum: 0` — the stratum ships no
provider registration row (§1), every earlier stratum is `complete`, and the FRF/Gemel chain entry
§8 records has landed, so `forensics/phase-state.json` reports phase 14 **`complete`** with an empty
blocking reason. That derived state is the phase-exit predicate, and D529 records that the ledger's
own `complete` is *not* it (`docs/DECISIONS.md`). `seal_sha256` is derived too: this document is
named in `forensics/tools/atlas_common.py`'s `SEAL_DOCS` table, which
`forensics/tools/render_seal_census.py` and `phase_state.py` read, so the line is recomputed
whenever this document changes and is not restated here. Reaching `complete` means the stratum has
reached the state a seal *records* (D421); it is **not** a parity claim, and this document is where
what the derivation does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This seal
cites that document rather than restating its arithmetic, because a number typed here is a number
that can drift from the evidence it summarises (D97), and the census's own header says so. The one
table this document *does* carry — §3's court list — is copied from `artifacts/phase14/COURTS.json`,
and it says so.

**This seal records a candidate-transcription claim, and it is neither a security claim nor a
parity claim.** Its evidence shows that the candidate distribution defines the names this stratum
owns and that the behaviours its eleven courts exercise match the pinned authority's over fixed
fixtures, observation for observation. It does **not** show that the crate's TLS/DTLS engine, its
record layer or its certificate plumbing are safe against a hostile input — no court here is a
security or fuzz gate — and it does **not** show that the crate completes a handshake the authority
would. `docs/PARITY_MODEL.md` is the authority on what the labels mean: `implemented` means a
symbol with that name is defined, and a passing bounded court is a differential result over the
behaviours that court exercises. `PARITY_VERIFIED` is not claimed for any symbol here, and
`forensics/STATUS.md`'s non-claims are the generated projection's. The `libssl` namespace is no
longer scaffolded — the stratum's own units define its 600 atlas-owned exports — but a defined
symbol is not a completed handshake, and `docs/SEAL-CENSUS.md` and `forensics/STATUS.md` record the
live implemented surface.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json:39`), named as the
  authority by `artifacts/phase14/COURTS.json:2`
- Court results: `artifacts/phase14/COURTS.json` — eleven courts, `all_pass` true
  (`artifacts/phase14/COURTS.json:4`), zero residuals; the per-court table is §3. Ten are
  **differential** courts and one (`RT-PHASE14-REF`) is the reference basis; this stratum
  registers no correctness `CT-*` court, and §3 states why.
- Obligation ledger: `forensics/phase14-obligations.json` — `open_in_this_stratum` 0
  (`forensics/phase14-obligations.json:9`), `deferred_to_later_phase` 0
  (`forensics/phase14-obligations.json:7`), `received_by_handoff` 0
  (`forensics/phase14-obligations.json:11`); the working-set rule it enforces is the ledger's own.
- Court coverage: `forensics/atlas/court-coverage.json` — phase 14's block, its counts
  `implemented` 600, `directly_courted` 600 (500 `called`, 100 `referenced`), 0 indirect, 0
  non-observable, 0 `unmatched`; the weaker meaning of `directly_courted` is stated in §3 and in §1
  below (D199).
- Derived state: `forensics/phase-state.json`, phase 14; it owns **no provider row**, so its
  `provider_rows` reads `null` rather than a count (§1).
- FRF receipts and claim: **present, and the chain's objects are on disk.** `.frf` carries ten
  receipts for the ten declarable courts
  (`receipt-run-openssl-rs-rt-{ssl-object,ssl-methods,ssl-ciph,record,statem,ssl-bio,dtls,ssl-init,session-cert,ssl-ext}-*`),
  twenty adjudicated challenge records (both operators on every court) and the
  `sensitivity-backed` claim
  `10b828f3a6728477715d82f06a9ea6a206e54380b4db1965c3fdb00604887955`, binding
  `openssl-rt-3.6.4-r2` to `openssl-rs 0.0.26` with zero blockers and all ten premises carrying
  stdout and exit. §8 states what that is.
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s head
  change is Phase 14's `C101` and its `current:` is `checkpoint.23b2564b0f48b12146b8b842338cd365879e9bf550a43e33f6d348d61ee7595e`
  (`K55`), whose summary names Phase 14 and the FRF chain. §8 states what that is.
- Deciding record: `docs/DECISIONS.md` — **D524** (the FRF requirement is read from the court
  inventory) is the predicate this stratum's chain engages through
  `artifacts/phase14/COURTS.json`, and **D529** is this seal, with `docs/PHASE-14-SUBPHASES.md` for
  the subphase plan this seal closes. §10 is where the corrections this seal records are summarised.

## 1. What this phase owns, and how that was decided

Phase 14 is **the TLS/DTLS stratum: the whole of `libssl`**. `forensics/atlas/symbol-ownership.json`
assigns it every export declared in `ssl.h`, `tls1.h`, `srtp.h` and `sslerr_legacy.h` — the
`SSL_CTX`/`SSL` object model, the `TLS_*`/`DTLS_*` method and version tables, the record layer, the
handshake state machine, the BIO pair, the session and certificate plumbing and the DTLS and QUIC
bridges (`docs/PHASE-14-SUBPHASES.md:3-23`). It is deliberately **not** the cryptography the record
layer and the ciphersuites call (`AES_encrypt`, `SHA256_Update`, `EVP_EncryptInit_ex` are Phases 7
and 8's, and `libssl.so.3` has a `DT_NEEDED` on `libcrypto.so.3` — the two are separate
namespaces), **not** the X.509 object graph the certificate plumbing carries (Phase 11's), and
**not** the `openssl s_client`/`s_server` commands (Phase 16's).

**The working set is derived, not chosen.** `forensics/atlas/symbol-ownership.json` assigns it 600
exports over **four headers** — `ssl.h` 582, `tls1.h` 13, `srtp.h` 4, `sslerr_legacy.h` 1 — and no
earlier stratum's ledger records an `owning_phase == 14` hand-off, so `received_by_handoff` reads
**0** (`forensics/phase14-obligations.json:11`). This is the **first stratum whose working set *is*
its atlas-owned universe**: the census's per-stratum row records `atlas-owned` 600, `ledger owned`
600, `implemented` 600, `deferred` 0, `open` 0.

**Unlike every earlier activation, this stratum inherited nothing already implemented.** libssl is
the candidate distribution's second namespace, present at activation only as the Phase 2 ABI
scaffold (`artifacts/phase2/shell/libssl.shell.rs`), which aborts when called, so
`forensics/atlas/implemented-surface.json` recorded `implemented: 0` for libssl and the ledger's
`open_in_this_stratum` opened at **600**, its whole working set, not a subset
(`docs/PHASE-14-SUBPHASES.md:48-53`). That split moved as the stratum landed its own units, so the
ledger's `counts` is the live record and §1 of the plan is the activation measurement.

**The 600 symbols are defined by 29 authority translation units** under `ssl/` (23),
`ssl/statem/` (2), `ssl/record/` (1), `ssl/quic/` (2) and `ssl/rio/` (1)
(`forensics/atlas/export-defining-units.json`); `ssl_lib.c` alone carries 342 of the 600 and the
stratum partitions them over its subphases by defining unit, not by theme
(`docs/PHASE-14-SUBPHASES.md:67-76`). The landed crate modules are `src/ssl/`'s 36 units:
`ssl_lib.rs`, `ssl_cert.rs`, `ssl_ciph.rs` and its generated `ssl_ciph_table.rs`, `ssl_conf.rs`,
`methods.rs`, `s3_lib.rs`, `statem/{statem,statem_lib,extensions_cust}.rs`,
`record/rec_layer_s3.rs`, `rio/poll_immediate.rs`, `bio_ssl.rs`, `d1_lib.rs`, `d1_srtp.rs`,
`ssl_init.rs`, `ssl_err_legacy.rs`, `quic/{quic_tls_api,quic_impl}.rs`, `ssl_sess.rs`,
`ssl_asn1.rs`, `ssl_txt.rs`, `ssl_cert_comp.rs`, `ssl_rsa.rs`, `ssl_rsa_legacy.rs`,
`ssl_stat.rs`, `ssl_mcnf.rs`, `tls_depr.rs`, `t1_trce.rs`, `t1_lib.rs`, `tls_srp.rs`.

**This stratum publishes no provider registration row, and the census records the zero.** Reading
`forensics/atlas/provider-algorithms.json` for `owning_phase == 14` yields nothing: libssl is not a
provider and this stratum's subphases activate none, so the ledger's `provider_rows_owned` is `0`
and `phase_state.py`'s provider-row rule and `provider_court_coverage.py` have nothing to hold
against this stratum — the mirror of Phases 12 and 13.

**The plane, and which one this stratum's evidence is.** D201's commitment — every
*primitive-bearing* subphase carries a differential `RT-*` court *and* a correctness `CT-*` court —
is scoped to primitive-bearing work, and this stratum emits no primitive: it has **ten behavioural
differential courts and one reference-basis court, and no `CT-*` court**. The reference basis is
`RT-PHASE14-REF`, the court the plan's §4.3 precondition requires: it takes the address of each of
the stratum's 600 atlas-owned exports and prints whether each is non-NULL, so a symbol covered only
by it is a proof of *reference* and not that any arm of it was driven (`artifacts/phase14/COURTS.json:6`).
§3 is where the two readings are tabulated.

## 2. What has been built

**14.0, the plan and the census.** `docs/PHASE-14-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase14-obligations.json` and its generator, the runner
`forensics/tools/phase14_courts.py`, and the reference-basis probe
`courts/phase14/rt_coverage_ref_probe.c` — all landed together, because §4.3 of the plan makes the
runner and the reference probe a precondition rather than a later slice
(`docs/PHASE-14-SUBPHASES.md:221-240`).

**14.1, the `SSL_CTX`/`SSL` object model.** `src/ssl/ssl_lib.rs`: the context and connection
allocation, reference counts, ex-data, the option/flag/mode/verify accessors and the
`SSL_CTX_ctrl`/`SSL_ctrl` dispatch, the callback setters, the `SSL_set_bio` plumbing and the
read/write/handshake entry guards, in two slices, plus `TLS_method` pulled forward from 14.2. The
remainder — eighteen rows closed after 14.3/14.4/14.5/14.7 landed, and 14.7b's last sixteen — is
part of the same unit. `RT-SSL-OBJECT` (362 observations) drives the lifecycle and refcounts, the
accessor/control/callback surface, the DANE setters and read-backs, the four
`SSL_bytes_to_cipher_list` forms, `SSL_get1_supported_ciphers`, `SSL_dup` and `SSL_set_SSL_CTX`.
The whole-archive link divergence is §5.

**14.2, the method and version tables.** `src/ssl/methods.rs` and `src/ssl/s3_lib.rs`: the 21
`TLS_*`/`DTLS_*`/`TLSv1_*` constructors and the protocol-version accessors they install. Every
constructor returns its own static table and `SSL_new` installs the any-version maximum of both
families. `RT-SSL-METHODS` (304 observations) compares the version the accessors report, the
`min`/`max` bounds a constructor installs and the `SSL_CTX_set_min_proto_version` refusals. The two
group-name accessors are reduced, recorded in `src/ssl/s3_lib.rs` (§5).

**14.3, the cipher and configuration surface.** `src/ssl/ssl_ciph.rs` (the three built-in
ciphersuite tables, transcribed by `forensics/tools/gen_phase14_cipher_tables.py` into the
generated `src/ssl/ssl_ciph_table.rs`, the `SSL_CIPHER_*` readers, the `OSSL_default_*` lists, the
`SSL_COMP_*` surface and the rule engine) and `src/ssl/ssl_conf.rs` (the `SSL_CONF_CTX` lifecycle
and the full command table). `RT-SSL-CIPH` (156 observations) drives the parsed `SSL_CIPHER_*`
sequence and every return code over fixed strings.

**14.4, the record layer.** `src/ssl/record/rec_layer_s3.rs` and `src/ssl/rio/poll_immediate.rs`:
the two default read-buffer length setters, the two record-state string readers (answering the
authority's `"RH"`/`"read header"`), and the non-QUIC `SSL_poll` readout with its three refusal
arms. `RT-RECORD` (38 observations) drives them with a zero timeout so nothing blocks.

**14.5, the handshake state machine, and 14.5b, the engine.** `src/ssl/statem/statem.rs`'s four
state readers (reading the three words `SSL_new` installs to the authority's post-`SSL_new`
values), `src/ssl/statem/extensions_cust.rs`'s custom-extension registration surface and
`src/ssl/t1_lib.rs`'s max-fragment-length and signature-algorithm accessors. 14.5b added the
`statem.c` control surface and the fresh-connection `state_machine` driver, `s3_lib.rs`'s
renegotiation helpers and `rec_layer_s3.rs`'s two pending readers, over which the thirteen
`ssl_lib.c` handshake entry points landed. `RT-STATEM` (68 observations) drives the state readers
and the extension table. **The message layer is unlanded, so no flight is built or parsed and no
court reads one** (§5).

**14.6, the BIO pair.** `src/ssl/bio_ssl.rs`: the `"ssl"` `BIO_METHOD` and its seven callbacks, the
`BIO_SSL` record, the four constructors and the session-copy/shutdown controls. `RT-SSL-BIO` (50
observations) drives the method, the constructors' NULL-context refusals, the `BIO_C_SSL_MODE` and
renegotiation controls and `BIO_ssl_shutdown`.

**14.7, the session and certificate plumbing, in four slices.** `src/ssl/ssl_sess.rs` (the session
object, cache and accessors), `ssl_asn1.rs` (the `SSL_SESSION_ASN1` template and the DER codec),
`ssl_txt.rs` (the printers), `ssl_cert_comp.rs` (the compression unit, whose exports answer the
`OPENSSL_NO_COMP_ALG` arm — §5), `ssl_cert.rs` (the CA-list and subject plumbing),
`ssl_rsa.rs`/`ssl_rsa_legacy.rs` (the certificate and private-key loaders). `RT-SESSION-CERT`
(208 observations) drives the session DER/PEM round trip, the CA-list surface, the loaders over a
fixed RSA pair, the compression refusals and the printers byte for byte.

**14.7b, the DANE/RPK surface and the last blocked rows.** `src/ssl/ssl_lib.rs` gains the twelve
DANE/RPK exports and their internals, `ssl_cert_dup`/`dup_ca_names`, `SSL_dup`/`SSL_set_SSL_CTX`,
`ossl_bytes_to_cipher_list` and `SSL_get1_supported_ciphers`; `src/ssl/s3_lib.rs` gains
`ssl3_ctrl`'s hostname arm; `src/ssl/t1_lib.rs` gains `ssl_set_client_disabled`/`ssl_cipher_disabled`;
`src/ssl/statem/statem_lib.rs` lands the `ssl_version_cmp`/`ssl_method_error` trio;
`src/ssl/statem/extensions_cust.rs` gains the custom-extension copies. With it the stratum reaches
**600 of 600 implemented and 0 open**. `RT-SSL-OBJECT` extends with the DANE setters and the four
cipher-list forms.

**14.8, the DTLS layer.** `src/ssl/d1_lib.rs` (`DTLSv1_listen`'s parser, version gate and refusal
arms, `DTLS_get_data_mtu`, `DTLS_set_timer_cb` and the internal `DTLS1_STATE` block) and
`src/ssl/d1_srtp.rs` (the twelve-profile table and parser, the two setters and the two readers).
`RT-DTLS` (42 observations) drives the refusal arms over a fixed in-memory datagram BIO and the
SRTP profile surface.

**14.9, the TLS extension, SRP and diagnostic glue.** `src/ssl/tls_srp.rs` (the SRP credential and
callback surface), `ssl_stat.rs` (the alert and state string readers), `ssl_mcnf.rs` (the config
glue), `tls_depr.rs` (the deprecated temporary-DH callback setters) and `t1_trce.rs` (`SSL_trace`,
the whole decoder). `RT-SSL-EXT` (77 observations) drives the SRP surface, the config refusals and
`SSL_trace` over a fixed memory BIO for a record header, an alert, a change-cipher-spec, an inner
content type and three handshake messages, compared byte for byte.

**14.10, the init, error and QUIC bridge.** `src/ssl/ssl_init.rs` (`OPENSSL_init_ssl`'s option
folding and one base `RUN_ONCE`), `src/ssl/ssl_err_legacy.rs` (`ERR_load_SSL_strings`), and
`src/ssl/quic/`'s three QUIC TLS accessors and `SSL_inject_net_dgram`. `RT-SSL-INIT` (26
observations) drives `OPENSSL_init_ssl` over fixed option words and the QUIC accessors'
setter/refusal arms over an incomplete `OSSL_DISPATCH` table. The QUIC success arms are Phase 15's
(§5).

**14.11, the received hand-offs.** Nothing: no earlier stratum defers a symbol to Phase 14, so
`RT-HANDOFF` remains in `pending_courts` with `14.11 (the received hand-offs)` and no court is
registered for it (`artifacts/phase14/COURTS.json`, `pending_courts`). The row exists because the
plan's contract is to name every one of the four situations, and here the measured answer is zero.

**The books that moved with the code.** Phase 14's own ledger reads `implemented` 600 of `owned`
600 with `deferred` 0 and `open` 0 (`forensics/phase14-obligations.json:5-12`), and the census
records the `libssl`/total implemented surface (`docs/SEAL-CENSUS.md`). It received no hand-off and
passed none on (`received_by_handoff` 0).

## 3. The evidence

Copied from `artifacts/phase14/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. Eleven courts are differential; the stratum registers no
correctness `CT-*` court, so no row here carries a `vectors_checked` count.

| court | plane | observations | probe |
|---|---|---|---|
| `RT-PHASE14-REF` | differential (reference basis) | 600 | `courts/phase14/rt_coverage_ref_probe.c` |
| `RT-SSL-OBJECT` | differential | 362 | `courts/phase14/rt_ssl_object_probe.c` |
| `RT-SSL-METHODS` | differential | 304 | `courts/phase14/rt_ssl_methods_probe.c` |
| `RT-SSL-CIPH` | differential | 156 | `courts/phase14/rt_ssl_ciph_probe.c` |
| `RT-RECORD` | differential | 38 | `courts/phase14/rt_record_probe.c` |
| `RT-STATEM` | differential | 68 | `courts/phase14/rt_statem_probe.c` |
| `RT-SSL-BIO` | differential | 50 | `courts/phase14/rt_ssl_bio_probe.c` |
| `RT-DTLS` | differential | 42 | `courts/phase14/rt_dtls_probe.c` |
| `RT-SSL-INIT` | differential | 26 | `courts/phase14/rt_ssl_init_probe.c` |
| `RT-SESSION-CERT` | differential | 208 | `courts/phase14/rt_session_cert_probe.c` |
| `RT-SSL-EXT` | differential | 77 | `courts/phase14/rt_ssl_ext_probe.c` |

Every row carries `residual_count: 0` and `verdict: "pass"` (`artifacts/phase14/COURTS.json`), and
the summary reads `pass` 11 of `total` 11 with `pending_courts` naming only `RT-HANDOFF`
(`artifacts/phase14/COURTS.json`, `pending_courts`). The totals over the eleven transcript courts
are `docs/SEAL-CENSUS.md`'s (**1931** authority observations), and the per-court rows there are the
same computation.

**`RT-PHASE14-REF` is not a behavioural court, and its meaning is the weaker one.** Its probe takes
the address of each of the stratum's 600 atlas-owned exports into a `volatile` table and prints
whether each is non-NULL, so a symbol covered only by it means the candidate distribution defines
the name — which the link proves — and **not** that any arm of it was driven
(`artifacts/phase14/COURTS.json:6`, `courts/phase14/rt_coverage_ref_probe.c`). The court coverage
atlas records those at basis `referenced`, never `called` (D199). Ten courts are behavioural:
`RT-SSL-OBJECT` drives the object model and its accessors, `RT-SSL-METHODS` the method tables,
`RT-SSL-CIPH` the cipher and config parsers, `RT-RECORD` the record-layer surface, `RT-STATEM` the
state and extension surface, `RT-SSL-BIO` the BIO pair, `RT-DTLS` the datagram layer,
`RT-SSL-INIT` the init and QUIC bridge, `RT-SESSION-CERT` the session and certificate plumbing, and
`RT-SSL-EXT` the SRP, diagnostic and config glue (`courts/phase14/*_probe.c`,
`docs/PHASE-14-SUBPHASES.md:266-467`).

**Why there is no correctness plane, stated rather than left to inference.** D201's commitment is
scoped to primitive-bearing subphases, and this stratum emits no primitive: every subphase builds
an object model, a parser, a wiring surface or a protocol state reader over Phases 7 and 8's
primitives, and a `CT-*` court is a vector-driven construction check with no authority transcript
to diff (D13, D201). The stratum's evidence is therefore **differential only**, which is a
measurement and not an omission, and every arm that could not be driven is named `pending.` or left
undriven rather than counted as passing (§5).

**The court coverage join is clean, and its meaning is the weaker one.**
`docs/SEAL-CENSUS.md` reads phase 14 as 600 implemented, 600 `directly_courted` (500 of them
`called` and 100 `referenced`), 0 indirect, 0 non-observable, 0 unmatched; the block is
`forensics/atlas/court-coverage.json`. `directly_courted` means *referenced by a staged candidate
probe that ran and produced a transcript*, a proof of **reference** rather than that every arm of
the symbol was driven — the same reading Phases 8 through 13's seals adopt. The referenced 100 are
the atlas-owned names the behavioural courts do not call, each still reached by `RT-PHASE14-REF`'s
address-taking probe; the called 500 are the names a behavioural probe actually invokes.

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
evidence found real defects, in the candidate and in the instrument.

**The differential courts held the transcription to the authority's own returns.** `RT-SSL-OBJECT`
and `RT-SSL-METHODS` established that the context's observable defaults and every constructor's
version bounds are the authority's, that a constructor's refusal arms return the authority's `0`,
and that the lifecycle's refcount effect on `SSL_free`/`SSL_CTX_free` matches. `RT-SSL-CIPH`
established that the cipher-list parser the crate builds from the same provider fetches the
authority runs produces the authority's preference order. `RT-SESSION-CERT` established that the
session DER/PEM round trip and the certificate/private-key loaders agree over fixed fixtures, and
that `SSL_SESSION_print`/`_fp`/`_keylog` match byte for byte.

**A lower-unit state divergence is named rather than compared.** `SSL_get_state` reports the three
state words `SSL_new` installs, but the message layer is unlanded, so `SSL_do_handshake` cannot
build or parse a flight and the sequence §3.5 of the plan describes stops at the fresh-connection
boundary; `RT-STATEM` drives the readers and the extension table, not a transition sequence, and
records the reduction in `src/ssl/mod.rs` (§5).

**The reference basis is what made the coverage join green at activation, and its meaning is the
weaker one.** 14.0 landed `RT-PHASE14-REF` so that the atlas's phase-14 row could bind every
atlas-owned name from the day the stratum began; since not one of the 600 was implemented at
activation, the basis it records is `referenced`, and the behavioural courts move names to `called`
as they land. The 100 that remain `referenced` are the honest residue.

**The whole-archive link and the error/conf duplications are recorded, not compared.** §5 states
the divergence the WIP link (`d181e440`) preserves; no court here reads the error queue or a
`CONF` module loaded through libcrypto, so the duplicated state cannot leak into a comparison — the
convention Phases 9 through 13 established.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an unset field, or crashes, the court does not
call it and the divergence is recorded. **No divergence obligation names Phase 14 as its
`current_owner`.** `forensics/divergence-obligations.json` reads 10 rows and **0 blocking** at seal
time; no live obligation outran this stratum's evidence, so `phase_state.py` derives `complete`.
The boundaries this stratum actually met are recorded in the places below.

- **The whole-archive link gives libssl its own `ERR` and `CONF` state.** `build_phase2.sh` links
  the crate archive into `libssl.so.3` with `--whole-archive` and `libcrypto.so.3` links its own
  copy of the same archive, so the *state* is duplicated: a libssl `ERR_raise` writes the archive
  copy inside `libssl.so.3` while a consumer's `ERR_peek_error` resolves to `libcrypto.so.3`, and a
  command set loaded through libcrypto's `CONF_modules_load_file` is not visible to libssl's
  `SSL_CTX_config` (`src/ssl/mod.rs:180-189`, `src/ssl/ssl_ciph.rs:30-32`,
  `src/ssl/mod.rs:513-519`). The raises are the authority's coordinates and are kept; the
  divergence is the link. No court compares an error-observing arm, and `RT-SSL-EXT` compares
  `SSL_CTX_config`'s refusal arms, which read the same empty store on both sides, naming the
  success arm `pending`.
- **The message layer is unlanded, so the state machine emits no flight.**
  `statem_lib.c`/`statem_clnt.c`/`statem_srvr.c`, the `extensions*.c` units, the key schedule and
  the record protection are not landed, so `SSL_do_handshake` cannot build or parse a flight and
  no court reads one (`src/ssl/mod.rs:362-364`, `docs/PHASE-14-SUBPHASES.md:342-364`).
  `RT-STATEM`'s sequence stops at the fresh-connection boundary; `SSL_dup`'s session arms and the
  `CRYPTO_UP_REF` "not quiescent" return need a handshake and are unreachable
  (`src/ssl/mod.rs:586-590`).
- **The security callback and the signature mask are reduced.** `ssl_security` answers 1 for the
  version check (14.1's recorded reduction), so `ssl_get_min_max_version` reads `SSL3_VERSION`
  where the authority rejects SSLv3 at security level 2 and reads `TLS1_VERSION`; the cipher filter
  is unaffected and the court drives only the filtered list. `ssl_set_sig_mask` walks the crate's
  own `sigalg_lookup_tbl` rather than `tls12_get_psigalgs`, and for the admitted default table it
  clears the same families, so no arm observes the difference (`src/ssl/mod.rs:566-585`).
- **`ssl_cert_comp.c`'s `OPENSSL_NO_COMP_ALG` arm is the admitted build's.** The admitted authority
  defines `OPENSSL_NO_COMP_ALG`, so every compression export answers the `#else return 0;` arm;
  `src/ssl/ssl_cert_comp.rs` transcribes that arm, and `ssl_cert_dup`'s `comp_cert[]` loop is the
  guard-off body (`src/ssl/mod.rs:436-442,492,579-582`). `RT-SESSION-CERT` drives the refusals.
- **The DANE context methods guard a NULL argument; the authority does not.**
  `SSL_CTX_dane_*` check NULL where the authority dereferences — the same reduction `s3_lib.rs`
  records for `SSL_CTX_set_tlsext_ticket_key_evp_cb` — so the court names that arm rather than
  driving it (`src/ssl/mod.rs:583-585`).
- **The QUIC success arms are Phase 15's.** The three QUIC TLS accessors' success arms are
  unreachable because the object they would drive (`ossl_quic_tls_new` and friends) is Phase 15's,
  and `SSL_inject_net_dgram`'s demux half is likewise; `RT-SSL-INIT` drives the setter/refusal arms
  over an incomplete `OSSL_DISPATCH` table (`src/ssl/mod.rs:394-404`).
- **`DTLSv1_listen` is reduced past the cookie stage, and two DTLS accessors add NULL guards.** The
  listener needs `WPACKET` and the record layer, the `IS_QUIC_METHOD` and handshake-negotiated arms
  are unreachable, and `DTLS_get_data_mtu`/`DTLS_set_timer_cb` add `d1 == NULL` guards the
  authority does not carry (`src/ssl/mod.rs:400-403`).
- **`SSL_trace`'s key-exchange arm answers `UNKNOWN`.** `ssl_get_keyex` reads a cipher that is NULL
  before a handshake, so the court never hands `SSL_trace` a
  `ClientKeyExchange`/`ServerKeyExchange` (`src/ssl/mod.rs:520-523`).
- **The `pending.` set and the undriven arms are the register's machine form.** The boundaries above
  are recorded in the probes, in the plan's §3 and §5, and in D529;
  `forensics/divergence-obligations.json`'s 10 rows and 0 blocking are why no live obligation outran
  this stratum's evidence.

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with that
   name is defined. `docs/PARITY_MODEL.md` states what each label means; no symbol here is
   `PARITY_VERIFIED`, and `forensics/STATUS.md` carries the current non-claims. The `PARITY_MODEL.md`
   labels this stratum's evidence reaches are at most `IMPLEMENTED`, plus a bounded `SEMANTIC_PASS`
   over the behaviours its courts exercise — never `PARITY_VERIFIED`.
2. **This is a candidate-transcription claim, and it is not a security claim.** The evidence shows
   the names are defined and the courts' fixtures match; it does **not** show the crate's TLS/DTLS
   engine, record layer or certificate plumbing are safe against a hostile input, and no court here
   is a fuzz or security gate. `docs/SECURITY_DIVERGENCE_POLICY.md` records the boundaries; a
   boundary not exercised is recorded, not a safety guarantee.
3. **No completed-handshake claim.** No arm of any court drives a handshake to completion: the
   message layer is unlanded (§5), so the state readers report the fresh-connection state and the
   record layer frames no negotiated record. A transcription that returns the same state string as
   the authority has not been shown to complete a handshake the authority would.
4. **`libssl` is no longer scaffolded, which is not the same as parity.** The Phase 2 ABI scaffold's
   `libssl` exports are superseded by this stratum's own definitions, so the namespace is
   implemented; `docs/SEAL-CENSUS.md` and `forensics/STATUS.md` record the live surface. A defined
   symbol is a name, not a working TLS stack.
5. **This stratum ships no provider registration row, and claims none.** libssl is not a provider
   and this stratum activates none; `provider_rows_owned: 0` is a measurement, not an omission, and
   §1 states why.
6. **The whole-archive link's duplicated `ERR`/`CONF` state is a boundary, not a pass.** A libssl
   `ERR` raise is invisible to the distribution's error queue and a libcrypto-loaded `CONF` module
   is invisible to libssl's `SSL_CTX_config`; no court observes either, and §5 records them
   (`src/ssl/mod.rs:180-189,513-519`).
7. **A passing court is a differential result over the behaviours its probe exercises, and
   implemented-and-courted is not "is a drop-in replacement".** A symbol recorded `directly_courted`
   is *referenced by a staged candidate probe that ran* — 500 of the stratum's are `called` and 100
   are `referenced` (`docs/SEAL-CENSUS.md`) — and `RT-PHASE14-REF` in particular proves only that
   the candidate distribution defines the atlas-owned names. Nothing here claims stderr
   equivalence, full CLI compatibility, build-profile independence beyond the admitted one, or
   drop-in substitution.
8. **The FRF and Gemel evidence is established, and §8 records what it is.** `docs/RELEASE_GATES.md`
   §2 items 6, 8 and 10 are met by the chain entry §8 records: ten receipts, twenty adjudicated
   challenge records, the `sensitivity-backed` claim
   `10b828f3a6728477715d82f06a9ea6a206e54380b4db1965c3fdb00604887955` with zero blockers, and the
   Gemel checkpoint `K55` whose summary names Phase 14 and the FRF chain. Phase 14's
   derived state is `complete`.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process (`docs/PHASE-14-SUBPHASES.md:250-257`) — a subphase lands its code, its court and
its regenerated artefacts in **one commit**; every export carries a court edge on the commit that
lands it (D236); every provider row it publishes is named by a court (D245, which this stratum has
nothing to hold against it) — and its §4.3 precondition (the reference-basis probe and the runner
land **with** the ledger). Every clause below is checked against a generated artefact rather than
asserted.

| criterion | evidence |
|---|---|
| every export is implemented or handed on with the dependency named | `forensics/phase14-obligations.json`: `open_in_this_stratum` 0 (`:9`) and `deferred_to_later_phase` 0 (`:7`); the generator fails closed, so `implemented + deferred + open == owned` |
| every implemented export is observed by a court | `forensics/atlas/court-coverage.json` phase-14 block; `unmatched` 0, enforced for `complete` by `forensics/tools/phase_state.py` |
| the reference basis covers the atlas-owned exports | `RT-PHASE14-REF` (`courts/phase14/rt_coverage_ref_probe.c`), registered with the ledger and runner (`docs/PHASE-14-SUBPHASES.md:221-240`); D199/D236 |
| no authority fault is reproduced | §5, and the boundaries recorded in the probes and D529 |
| no blocking divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking; none names Phase 14 |
| `ABI-PROTOTYPE`, `ABI-SYMBOL` and `ABI-DYNAMIC` stay clean | `forensics/atlas/ownership-audit.json`: `problems` empty, `implemented_by_two_strata` empty |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 |
| the dispatch court clean | `forensics/atlas/dispatch-court.json`: `problems` 0 |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` empty |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` empty |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json`'s rule line |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |

**`docs/RELEASE_GATES.md` §2's ten items, each checked rather than assumed.** The first column is
the authority's own list (`docs/RELEASE_GATES.md:54-63`); the second says what this stratum's
evidence for it is, and, where an item is **not met**, says so plainly rather than leaving the row
empty.

| # | item | this stratum's evidence |
|---|---|---|
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json:39` pins `openssl-3.6.4-production`; `artifacts/phase14/COURTS.json:2` names it |
| 2 | obligation inventory | `forensics/phase14-obligations.json` (`:5-12`); this stratum owns no provider row |
| 3 | court manifests | `artifacts/phase14/COURTS.json` |
| 4 | raw captures | **met.** The eleven staged `artifacts/phase14/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (each row's `staged_binaries`), and `.frf/captures/` carries the FRF venue's captures for the ten declarable courts, produced by §8's chain |
| 5 | residual set | **met in the court venue.** Every court's `residual_count` is 0 and its `residuals` list empty, `summary` reads `pass` 11 of 11 and `pending_courts` names only `RT-HANDOFF` |
| 6 | mutation / sensitivity evidence | **met.** `.frf/challenges/` carries twenty adjudicated Phase-14 records — both declared axes (`stdout-first-line`, `exit-class`) on each of the ten declarable courts, every one `saw_defect` and `specificity_clean` |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-14 FRF residual exists to carry one |
| 8 | FRF receipts | **met.** `.frf/receipts/` carries one receipt per declarable court (`receipt-run-openssl-rs-rt-{ssl-object,ssl-methods,ssl-ciph,record,statem,ssl-bio,dtls,ssl-init,session-cert,ssl-ext}-*`), each with an empty `residuals` list |
| 9 | generated parity projection | `forensics/STATUS.md`, rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s head change is Phase 14's `C101` and its `current:` is `K55`, whose summary names Phase 14 and the FRF chain |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and item 7 is not applicable
rather than wanting, because `--resolution-run` is required only for a `fixed` disposition and none
attaches to a Phase-14 FRF residual.** Items 6, 8 and 10 retired when §8's chain landed, and
`phase_state.py` now derives `complete` with an empty blocking reason.

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and this section records what it is.**

- **Ten declarations are on disk.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table gained a
  Phase-14 block — `("rt-ssl-object", 14, …)` through `("rt-ssl-ext", 14, …)` — and
  `gen_frf_courts.py` wrote the declarations under
  `forensics/frf/courts/openssl-rs-rt-{ssl-object,ssl-methods,ssl-ciph,record,statem,ssl-bio,dtls,ssl-init,session-cert,ssl-ext}`.
  `gen_frf_courts.py --check` reads `ok: 250 file(s) match the table (125 courts)`, and
  `forensics/frf/README.md` counts **125 runtime courts** — the Phase-14 ten among them, which
  moves the manifest count `docs/RELEASE_GATES.md`'s alternative names with it
  (D200/D413/D424/D475). **`RT-PHASE14-REF` is not declared**, because its probe takes addresses
  and diffs no transcript, so it is a reference basis with nothing to stage and cannot carry a
  declaration (D199).
- **The chain's objects are on disk.** `.frf/receipts/` carries ten Phase-14 receipts, one per
  declarable court
  (`receipt-run-openssl-rs-rt-{ssl-object,ssl-methods,ssl-ciph,record,statem,ssl-bio,dtls,ssl-init,session-cert,ssl-ext}-*`),
  each with an empty `residuals` list. `.frf/challenges/` carries twenty adjudicated challenge
  records — both declared axes (`stdout-first-line` and `exit-class`) on each of the ten courts,
  every one `saw_defect` and `specificity_clean` — which is what makes the claim
  `sensitivity-backed` rather than merely green (D13). `.frf/claims/` carries the compiled claim
  `10b828f3a6728477715d82f06a9ea6a206e54380b4db1965c3fdb00604887955`, compiled at
  `--policy sensitivity-backed` over the ten receipts, binding authority `openssl-rt-3.6.4-r2` to
  candidate `openssl-rs 0.0.26` (`identity_hash e4f60d8b…`) with zero blockers and all ten premises
  asserting both `stdout` and `exit`.
  **The identity is the current 0.0.26 release.** The chain was cut into the store the 0.0.26
  release regenerated from clean — FRF run identities are content-addressed on the declaration,
  which carries the candidate version — so this claim records the candidate the tree is
  (`gen_frf_courts.CANDIDATE_VERSION`), which is what the fix-4 identity clause requires.
- **The Gemel change and checkpoint are this stratum's.** The change `C101` names Phase 14 and
  the FRF chain, and the checkpoint `K55`
  (`checkpoint.23b2564b0f48b12146b8b842338cd365879e9bf550a43e33f6d348d61ee7595e`) closes it; the projection `forensics/GEMEL_TRAJECTORY.md`
  carries both, and the checkpoint's summary names Phase 14 and the FRF chain. Items 6, 8 and 10 of
  §7 retired with that entry, exactly as they did for Phase 9's `C94`, Phase 10's `C95`, Phase 11's
  `C97`, Phase 12's `C98` and Phase 13's `C99`.

**The declarations are produced by `gen_frf_courts.py`; the receipts, challenges, claim and
checkpoint were produced by running the chain in the FRF tooling container, never on the host.**
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
This section records the objects that are on disk.

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase14-obligations.json`'s
`deferred` list is empty and its `deferred_by_phase` reads `{}`; every export this stratum owns is
implemented, and it received no hand-off to pass on (`received_by_handoff` 0). The three `quic.h`
exports that sit in libssl's DSO (`OSSL_QUIC_client_method`, `OSSL_QUIC_client_thread_method` and
`OSSL_QUIC_server_method`) belong to **Phase 15** by their declaring header and were never this
stratum's (`docs/PHASE-14-SUBPHASES.md:18-46`).

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF/Gemel chain entry has landed.** §8's subject is now the objects on disk: the ten
  declarations, ten receipts, twenty adjudicated challenges, the claim
  `10b828f3a6728477715d82f06a9ea6a206e54380b4db1965c3fdb00604887955` and the checkpoint
  `K55`. This stratum registers no `CT-*` court, so the entry covers the ten behavioural
  differential courts and nothing is recorded as not declarable; `RT-PHASE14-REF` is the reference
  basis and is not declarable. Items 6, 8 and 10 of §7 retired with it, and `phase_state.py`
  derives `complete`.
- **The message layer is deferred to Phase 15, and this seal names it rather than claiming past it.**
  `statem_lib.c`/`statem_clnt.c`/`statem_srvr.c`, the `extensions*.c` units, the key schedule and
  the record protection are unlanded (§5), so no flight is built or parsed and no handshake
  completes. `ssl/statem/statem_lib.c` is reached (14.7b landed its version-helper trio), but
  `statem_clnt.c` and `statem_srvr.c` are not, and 14.12 records both as
  `deferred_to_later_stratum` in `forensics/prerequisites.json`, owned by **Phase 15**
  (QUIC/ECH), whose engine drives the TLS handshake through the message layer and is the first
  later stratum in `phase_state.py`'s `REQUIRES` DAG to consume it (D132, D529).
- **Phase 15 begins on a landed libssl substrate.** The `SSL_CTX`/`SSL` object model, the method,
  cipher, record, state, BIO, DTLS, session, certificate, SRTP, init and QUIC-bridge surfaces are
  now Phase 14's (`src/ssl/`), and the QUIC success arms this stratum left unreachable are the
  Phase 15 object they would drive.
- **`forensics/phase14-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and coverage figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections this seal makes to the plan's own account, and the corrections
the evidence forced rather than the ones a reviewer might have preferred.

1. **The stratum's export ledger reaches zero open before the stratum is complete, and D529 writes
   the distinction down.** `phase14_obligations.py`'s `complete` is the ledger-level emptiness
   check, not the phase-exit predicate; the stratum is not complete until 14.12's seal and the
   FRF/Gemel chain (D529). This seal is that 14.12 document, and §7's item 6/8/10 rows are the
   predicate's remaining input.
2. **The plan's table did not anticipate 14.5b, and §2 records it as a slice row rather than a
   partition row.** Measurement after 14.9 found 14.1's remainder bottlenecked on a single unlanded
   substrate — the state-machine and record-layer *engine* — so thirteen `ssl_lib.c` handshake entry
   points could not be landed without starting a handshake no arm could complete. 14.5b is that
   slice; its thirteen names are `ssl_lib.c` rows 14.1 already owns, so the activation partition is
   unchanged (`docs/PHASE-14-SUBPHASES.md:110-114,342-364`).
3. **The plan's table did not name 14.7b either, and it closes the partition.** After 14.9 the
   remainder was sixteen `ssl_lib.c` rows, each waiting on one named helper rather than an invented
   body; 14.7b lands all sixteen and the stratum reaches 600 of 600 implemented with 0 open
   (`docs/PHASE-14-SUBPHASES.md:116-120,432-453`).
4. **`received_by_handoff` is 0, and this is the first stratum whose working set is exactly its
   atlas-owned universe.** No earlier stratum's ledger records an `owning_phase == 14` hand-off, and
   the plan's §4.1 measures it rather than asserting it (`docs/PHASE-14-SUBPHASES.md:40-46,208-213`).
   The three `quic.h` names in libssl's DSO are Phase 15's and are not this stratum's.
5. **The whole-archive link's duplicated `ERR`/`CONF` state is a recorded divergence, not a hidden
   one.** `libssl.so.3` and `libcrypto.so.3` each link a copy of the crate archive, so libssl's
   `ERR` raises and `CONF` store are its own; no court observes either, and §5 records the link and
   the arms it closes (`src/ssl/mod.rs:180-189,513-519`).
6. **The QUIC success arms are Phase 15's, and the court drives the refusal arms.** The three QUIC
   TLS accessors cannot reach their success arms because the object they would drive is Phase 15's,
   so `RT-SSL-INIT` drives the setter/refusal arms over an incomplete `OSSL_DISPATCH` table
   (`src/ssl/mod.rs:394-404`).
7. **The FRF/Gemel chain entry landed, and §7 and §8 record it.** The seal's §8 records the ten
   declarations, ten receipts, twenty adjudicated challenges, the `sensitivity-backed` claim
   `10b828f3a6728477715d82f06a9ea6a206e54380b4db1965c3fdb00604887955` and the Gemel change
   `C101` / checkpoint `K55`, so items 6, 8 and 10 retired and `phase_state.py`
   derives `complete`. `seal_sha256` is recomputed from the document's new bytes.
8. **The Phase-14 slices left four generator drifts, and 14.12 regenerates and reconciles them.**
   The later subphases landed crate and tool changes without re-running the whole pipeline, so
   four artefacts drifted from their generators and only surfaced when 14.12 derived the stratum
   `complete`: (a) 14.1/14.7 added a second `pub type PemPasswordCb` in `src/ssl/ssl_lib.rs`, which
   defeated `prototype_court.py`'s unique-alias resolution and produced 89 type mismatches the
   committed `prototype-court.json` did not record -- 14.12 re-exports the one definition from
   `src/evp/pem_bridge.rs`; (b) 14's libssl callback typedefs (`VerifyCb`, `KeylogCb`, `TmpDhCb`
   and their siblings) were 40 aliases no link resolved, so `dispatch_court.py` refused them --
   14.12 exempts the family as not-a-provider-dispatch; (c) the crate models the authority macro
   `dtls_ver_ordinal` as a `const fn`, which `prerequisite_gate.py`'s definition scanner mis-read
   as a definition of `fn`, reporting an `undefined_prerequisite` -- 14.12 fixes the scanner's
   regex; and (d) `plan_reconciliation.py` reported the plan's 14.5b row as naming
   `ssl/statem/statem_clnt.c` and `ssl/statem/statem_srvr.c` while nothing reached them --
   14.12 records both as `deferred_to_later_stratum` to Phase 15. Every artefact re-derives green
   (`evidence_determinism.py --keep`, 34 artefacts).
