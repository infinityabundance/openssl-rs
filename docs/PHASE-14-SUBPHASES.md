# Phase 14 — TLS / DTLS (`libssl`), as subphases

## 0. What this stratum is, and what it is not

Phase 14 is the TLS/DTLS stratum: the whole of `libssl`. Its name in `docs/RELEASE_GATES.md` §1 is
"TLS / DTLS (`libssl`)", and `forensics/atlas/symbol-ownership.json` gives it every export declared
in `ssl.h`, `tls1.h`, `srtp.h` and `sslerr_legacy.h`. It owns the `SSL_CTX`/`SSL` object model, the
`TLS_*`/`DTLS_*` method and version tables, the record layer, the handshake state machine, the BIO
pair, the session and certificate plumbing and the DTLS and QUIC bridges.

It is **not** the cryptography the record layer and the ciphersuites call: `AES_encrypt`,
`SHA256_Update`, `EVP_EncryptInit_ex` and every primitive behind them are Phases 7 and 8's, and
`libssl` reaches them as a caller -- `libssl.so.3` has a `DT_NEEDED` on `libcrypto.so.3` and the
two are separate distribution namespaces. Nor is it the X.509 object graph the certificate plumbing
carries, which is Phase 11's, nor `libcrypto`'s provider framework, nor the `openssl s_client` /
`s_server` commands, which are Phase 16's.

**Why this stratum is being planned while Phase 13 has sealed.** `forensics/tools/phase_state.py`'s
`REQUIRES` derives `requires(14) == (13,)`, and Phase 13 is `complete`. **Unlike every earlier
activation, this stratum inherits nothing**: libssl is the candidate distribution's second
namespace, `forensics/atlas/implemented-surface.json` records `implemented: 0` for it, and every one
of its 600 atlas-owned exports is open. The whole working set is the stratum's own work, which is
the scope this document measures.

## 1. The measurement this plan rests on

Every number below is read from `forensics/atlas/`, not typed, and
`forensics/phase14-obligations.json` is authoritative for the present.

**Phase 14's atlas-owned universe is 600 exports, all `libssl`, over four headers.** Reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 14`:

| header | exports | what it declares |
|---|---|---|
| `ssl.h` | 582 | the `SSL_CTX`/`SSL` object model, the accessor and control surface, the method/version constructors, the cipher and `SSL_CONF_*` parsers, the session and certificate plumbing, the BIO pair, the custom-extension and DTLS and QUIC bridges |
| `tls1.h` | 13 | the TLS protocol constants' accessors and the signature-algorithm and max-fragment-length surface |
| `srtp.h` | 4 | the DTLS-SRTP profile accessors |
| `sslerr_legacy.h` | 1 | `ERR_load_SSL_strings`, the legacy error-string loader |

**It receives no hand-off.** Every row of every `forensics/phase*-obligations.json` whose
`owning_phase` is 14 is discovered rather than listed, and there are none: libssl is a
self-contained namespace, every symbol earlier strata defer goes to another stratum, and
`received_by_handoff` reads **0**. This is the first stratum whose working set *is* its atlas-owned
universe; the three `quic.h` exports that sit in `libssl`'s DSO (`OSSL_QUIC_client_method`,
`OSSL_QUIC_client_thread_method` and `OSSL_QUIC_server_method`) belong to **Phase 15** by their
declaring header and are not this stratum's.

That is a working set of **600 exports**. **At activation, none of them was already implemented**
and `forensics/atlas/implemented-surface.json` is where that is read from: the 603 `libssl` exports
the authority defines are present in the candidate only as the Phase 2 ABI scaffold
(`artifacts/phase2/shell/libssl.shell.rs`), which aborts when called, so `implemented: 0` and
`open_in_this_stratum` opened at **600**, not a subset. **That split moves as this stratum lands its
own units: the ledger's `counts` is the live record and this section is the activation measurement.**

**Open, by declaring header** (`forensics/phase14-obligations.json`'s `open` rows, counted from
their own `declaring_header`):

| header | open |
|---|---|
| `ssl.h` | 582 |
| `tls1.h` | 13 |
| `srtp.h` | 4 |
| `sslerr_legacy.h` | 1 |

Every row is the atlas projection; there is no hand-off row to separate out.

**The 600 symbols are defined by 29 authority translation units**
(`forensics/atlas/export-defining-units.json`), under `ssl/` (23 units), `ssl/statem/` (2),
`ssl/record/` (1), `ssl/quic/` (2) and `ssl/rio/` (1). **All 29 still have open symbols**, and they
are the whole of §2's work: `ssl_lib.c` (342 open), `ssl_sess.c` (65), `ssl_ciph.c` (25),
`methods.c` (21), `ssl_cert.c` (20), `tls_srp.c` (19), `ssl_rsa.c` (19), `ssl_conf.c` (11),
`t1_lib.c` (9), `ssl_cert_comp.c` (8), `bio_ssl.c`/`ssl_rsa_legacy.c`/`ssl_stat.c` (6 each),
`extensions_cust.c` (5), `rec_layer_s3.c`/`d1_srtp.c`/`statem.c` (4 each), `d1_lib.c`/`ssl_mcnf.c`/
`tls_depr.c`/`s3_lib.c`/`ssl_txt.c`/`quic_tls_api.c`/`ssl_asn1.c` (3 each), and the seven one- or
two-symbol remainder (`ssl_err_legacy.c`, `ssl_init.c`, `quic_impl.c`, `poll_immediate.c`,
`t1_trce.c`).

**Phase 14 publishes no provider registration row.** Reading
`forensics/atlas/provider-algorithms.json` for `owning_phase == 14` yields nothing: libssl is not a
provider and this stratum's subphases activate none. The ledger's `provider_rows_owned` is therefore
`0` and `phase_state.py`'s provider-row rule and `provider_court_coverage.py` have nothing to hold
against this stratum -- the mirror of Phases 12 and 13.

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 14.0 | **The plan and the census** | `docs/PHASE-14-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase14-obligations.json`) and its generator land with it. **The runner and the reference-basis probe land with it too, and §4.3 is why they cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and `RT-PHASE14-REF` is the stratum's only court until 14.1 lands a unit, so a later subphase cannot satisfy the runner without leaving the pipeline red in between. | 13 | — |
| 14.1 | **The `SSL_CTX`/`SSL` object model** | `ssl_lib.c` (342 open). The `SSL_CTX` and `SSL` allocation, reference counts, ex-data, the accessor and control surface (`SSL_CTX_ctrl`/`SSL_ctrl` and the option/flag/mode/verify accessors), the callback setters, the BIO/`SSL_set_bio` plumbing and the error/read/write entry points. **342 open rows over 1 unit.** **Slice 1 landed (checked against the ledger): 164 of the 342 `ssl_lib.c` rows — the object model and its accessor/control/callback/BIO surface — plus `TLS_method` pulled forward from 14.2 as the one constructor 14.1's court needs; 178 `ssl_lib.c` rows and 20 `methods.c` rows remain open.** | 14.0 | `RT-SSL-OBJECT` |
| 14.2 | **The method and version tables** | `methods.c` (21), `s3_lib.c` (3). The `TLS_*`/`DTLS_*`/`TLSv1_*` constructor table and the protocol-version accessors it installs (`SSL_get0_group_name`, `SSL_group_to_name`, the ticket-key callback). **24 open rows over 2 units.** **Landed (checked against the ledger): the 23 rows still open at activation — the 20 `methods.c` constructors plus `s3_lib.c`'s three — with `TLS_method` already pulled forward into 14.1, so all 21 `methods.c` constructors are present.** | 14.1 | `RT-SSL-METHODS` |
| 14.3 | **The cipher and configuration surface** | `ssl_ciph.c` (25), `ssl_conf.c` (11). The cipher and ciphersuite tables and their `SSL_CIPHER_*` readers, the `OSSL_default_*` lists, and the `SSL_CONF_CTX_*`/`SSL_CONF_cmd*` command parser the `openssl` config reader drives. **36 open rows over 2 units.** **Landed (checked against the ledger): all 36 rows, plus the five `ssl_lib.c` cipher-list accessors the plan already names 14.3's — `SSL_CTX_set_cipher_list`, `SSL_set_cipher_list`, `SSL_CTX_get_ciphers`, `SSL_get_ciphers` and `SSL_get_cipher_list` — pulled forward because the court drives them.** | 14.1 | `RT-SSL-CIPH` |
| 14.4 | **The record layer** | `rec_layer_s3.c` (4), `poll_immediate.c` (1). The default read-buffer length accessors, the record-state string readers and the non-blocking `SSL_poll`. **5 open rows over 2 units.** **Landed (checked against the ledger): all 5 rows — `rec_layer_s3.c`'s four (`SSL_CTX_set_default_read_buffer_len`, `SSL_set_default_read_buffer_len`, `SSL_rstate_string`, `SSL_rstate_string_long`) and `poll_immediate.c`'s one (`SSL_poll`). The stratum stood at 360 of the 600 atlas-owned exports implemented, with 240 open.** | 14.1 | `RT-RECORD` |
| 14.5 | **The handshake state machine** | `statem.c` (4), `extensions_cust.c` (5), `t1_lib.c` (9). The state readers (`SSL_get_state`, `SSL_in_before`, `SSL_in_init`, `SSL_is_init_finished`), the custom-extension registration surface and the signature-algorithm and max-fragment-length surface. **18 open rows over 3 units.** **Landed (checked against the ledger): all 18 rows — `statem.c`'s four, `extensions_cust.c`'s five and `t1_lib.c`'s nine. The stratum now stands at 378 of the 600 atlas-owned exports implemented, with 222 open.** | 14.1 | `RT-STATEM` |
| 14.6 | **The BIO pair and buffers** | `bio_ssl.c` (6). `BIO_f_ssl`/`BIO_new_ssl`/`BIO_new_ssl_connect`/`BIO_new_buffer_ssl_connect` and the session-copy/shutdown BIO controls. **6 open rows over 1 unit.** | 14.1 | `RT-SSL-BIO` |
| 14.7 | **The session and certificate plumbing** | `ssl_sess.c` (65), `ssl_cert.c` (20), `ssl_rsa.c` (19), `ssl_rsa_legacy.c` (6), `ssl_cert_comp.c` (8), `ssl_asn1.c` (3), `ssl_txt.c` (3). The session cache and PEM/DER session codec, the CA-list and certificate/private-key loaders (including the deprecated `use_RSAPrivateKey` spellings), certificate compression and the session printers. **124 open rows over 7 units** — the largest subphase. | 14.1 | `RT-SESSION-CERT` |
| 14.8 | **The DTLS layer** | `d1_lib.c` (3), `d1_srtp.c` (4). `DTLSv1_listen`, the DTLS data-MTU and timer callbacks, and the DTLS-SRTP profile surface. **7 open rows over 2 units.** | 14.2 | `RT-DTLS` |
| 14.9 | **The TLS extension, SRP and diagnostic glue** | `tls_srp.c` (19), `ssl_stat.c` (6), `ssl_mcnf.c` (3), `tls_depr.c` (3), `t1_trce.c` (1). The SRP credential and callback surface, the alert/state string readers, the `SSL_CTX_config`/`SSL_add_ssl_module` config glue, the deprecated DH-callback setters and `SSL_trace`. **32 open rows over 5 units.** | 14.1, 14.3 | `RT-SSL-EXT` |
| 14.10 | **The init, error and QUIC bridge** | `ssl_init.c` (1), `ssl_err_legacy.c` (1), `quic_tls_api.c` (3), `quic_impl.c` (1). `OPENSSL_init_ssl`, the legacy error-string loader, and the QUIC TLS accessors (`SSL_set_quic_tls_cbs`/`_transport_params`/`_early_data_enabled`, `SSL_inject_net_dgram`). **6 open rows over 4 units.** | 14.1 | `RT-SSL-INIT` |
| 14.11 | **The received hand-offs** | nothing: no earlier stratum defers a symbol to Phase 14 (§1). The row exists because the plan's contract is to name every one of the four situations, and here the measured answer is zero. **0 open rows.** | 14.0 | `RT-HANDOFF` |
| 14.12 | **The seal** | nothing in the crate — evidence: `docs/PHASE-14-TLS-SEAL.md` | 14.0–14.11 | — |

The ten rows above the empty hand-off row and the seal partition the 600 open exports exactly, by
defining unit: 342 + 24 + 36 + 5 + 18 + 6 + 124 + 7 + 32 + 6 = 600 (the activation partition, which
moves as subphases land), and the 29 open units each appear in exactly one row. The partition is
derived from `forensics/atlas/export-defining-units.json` joined to the ledger's `open` list, not
typed.

**2.1 The order, and the dependency it rests on.** 14.1 first because every other subphase binds to
an `SSL_CTX` or `SSL` object it allocates: the method constructors return into it, the cipher and
config parsers write it, the record layer's buffers hang off it, the state readers observe it, the
BIO pair wraps it, the session and certificate plumbing loads into it, and the SRP, config, init
and QUIC glue all read or write it. 14.2 before 14.8 because `DTLSv1_listen` drives a method the
constructor table installs, and 14.3 before 14.9 because the config glue's `SSL_CONF_cmd` dispatch
is the cipher parser's table. 14.4 and 14.5 are the record and state halves of the same engine and
depend only on the object model. 14.6 is independent of the cipher chain -- the BIO pair wraps an
`SSL` object, not a method. The unit-level call graph inside `ssl_lib.c` (which helper each open
entry needs, and in what order) is measured at each slice, the way D442 and D444 were; a slice that
discovers its unit is somewhere else records that rather than forcing the row (§5).

## 3. What each subphase must honour

**3.1 An `SSL_CTX` is a factory and an `SSL` is a connection, and the refcount is observable.**
`SSL_CTX_new`/`SSL_CTX_free` and `SSL_new`/`SSL_free`/`SSL_up_ref` are lifecycles, and the
`SSL_CTX_ctrl`/`SSL_ctrl` command dispatch and the option/flag/mode accessors are an observable
state machine. The differential court builds a context from a fixed method, allocates a connection
from it, and compares the observed `SSL_version`, `SSL_get_state`, the refcount's effect on
`SSL_free` and `SSL_CTX_free`, and the refusal arms (a NULL method, a NULL context) by their return
values, read from the authority's own returns rather than typed.

**3.2 A method is a version, and the constructor table is the observable.** `TLS_method`,
`TLS_client_method`, `DTLS_method` and the pinned `TLSv1_2_*`/`DTLSv1_2_*` constructors return a
method whose version the accessors report. The court compares `SSL_get_version`/`SSL_version`, the
`min`/`max` protocol bounds a constructor installs, and the `SSL_CTX_set_min_proto_version` refusal
for a version the method does not support, each named by its return and the `SSL_R_*` coordinate the
authority raises.

**3.3 The cipher list is a parser, and its accept/refuse boundary is the contract.** `SSL_CTX_set_cipher_list`,
`SSL_CTX_set_ciphersuites` and `SSL_CONF_cmd` parse a fixed string into a `STACK_OF(SSL_CIPHER)`.
The court drives the fixed list, a token the default provider does not publish, an empty string, a
bad `SSL_CONF` command name and its value type, and compares the parsed `SSL_CIPHER_get_name`/
`_get_id`/`_get_protocol_id` sequence and every return code, because a parser that accepts a
ciphersuite the authority refuses is a different library.

**3.4 The record layer is framing and a read state, and both are observable.** `SSL_rstate_string`/
`_long` report the record read state, `SSL_CTX_set_default_read_buffer_len` fixes the buffer the
record layer allocates, and `SSL_poll` reports readiness. The court drives the default length and
the state string over a fixed connection and compares what the authority's own accessors answer; it
does not drive `SSL_poll` over a real socket and leaves the network arm `pending` rather than
compared.

**3.5 The handshake state machine is a transition sequence, and `SSL_get_state` names it.** The
observable is the sequence the state readers report as a fixed in-process handshake is driven -- an
`SSL_in_before` context, an `SSL_do_handshake` started against an in-memory BIO pair, and the
`SSL_in_init`/`SSL_is_init_finished` pair at each step. The court prints the sequence and the state
string at each step rather than only the final answer, because a probe that reads only the last
state measures half of it.

**3.6 The BIO pair is a filter, and the bytes through it are the observable.** `BIO_new_ssl`
attaches an `SSL` object to a BIO; the court writes a fixed record into the pair and compares what
`BIO_read` returns, `BIO_ssl_copy_session_id`'s effect on the session and `BIO_ssl_shutdown`'s
return. It uses in-memory BIOs only, so no socket and no wall clock move an answer.

**3.7 The session and certificate plumbing is a codec and a loader.** `PEM_read_SSL_SESSION`,
`PEM_write_SSL_SESSION` and the `i2d_SSL_SESSION`/`d2i_SSL_SESSION` pair are one session codec, and
the court writes a fixed in-process session out and re-reads it, comparing the observer bytes and
the decoded identifier -- never a key byte. The certificate loaders
(`SSL_CTX_use_certificate*`, `SSL_CTX_use_PrivateKey*`, the CA-list setters) are driven over a fixed
fixture and compared by their return and the `SSL_CTX_get0_certificate` identity, and the deprecated
`use_RSAPrivateKey` spellings are driven through the same path.

**3.8 DTLS is the datagram method, and its own entry points are the observable.** `DTLSv1_listen`
over a fixed in-memory datagram BIO, the `DTLS_get_data_mtu`/`DTLS_set_timer_cb` accessors, and the
`SSL_CTX_set_tlsext_use_srtp`/`SSL_get_srtp_profiles`/`SSL_get_selected_srtp_profile` profile
surface. The court compares the listener's return and the profile stack the authority builds, and
uses no real datagram socket.

**3.9 The extension, SRP, config and init glue is dispatch and a return code.** `SSL_CTX_add_custom_ext`,
`SSL_CTX_has_client_custom_ext` and `SSL_extension_supported` are a registration table; the court
compares the code a subsequent lookup reports. `SSL_CTX_set_srp_*` and `SRP_Calc_A_param` are the SRP
surface, compared by their returned `SRP_*` codes over a fixed verifier. `SSL_CTX_config` and
`SSL_add_ssl_module` are driven over a fixed `CONF`, and `OPENSSL_init_ssl`/`ERR_load_SSL_strings`
by their return and the absence of a duplicate load. The QUIC TLS accessors are driven over a fixed
in-process callback table and compared by their return.

**3.10 Nothing here is a parity claim about the meaning of a completed handshake.** A transcription
that returns the same state string as the authority has not been shown to complete a handshake the
authority would, and §3.5's sequence is only as good as the fixed BIO pair the court supplies. The
measured surface is the one above, and a name that cannot be driven is named `pending` rather than
counted as passing — the contract Phase 8's `PENDING_CORRECTNESS_COURTS` and every later activation
established.

## 4. Measured corrections, and the precondition

**4.1 The working set is exactly the atlas projection, and the empty hand-off set is a
measurement.** Phase 14 owns the whole of `libssl`, a namespace no earlier stratum writes into: the
atlas's `owner_phase == 14` rows are 600, and no `forensics/phase*-obligations.json` records an
`owning_phase == 14` deferred row. The ledger discovers the edges rather than listing them, so
`received_by_handoff: 0` is what the discovery found. The three `libssl` exports the atlas assigns
elsewhere are `quic.h`'s, and Phase 15 owns them.

**4.2 This stratum ships no provider row, and the plan says why.** Reading
`forensics/atlas/provider-algorithms.json` for `owning_phase == 14` yields nothing: libssl is not a
provider and this stratum activates none, so `phase_state.py`'s provider-row rule and
`provider_court_coverage.py` have nothing to hold against it and `forensics/phase14-obligations.json`
carries `provider_rows_owned: 0`. This is the mirror of Phase 12's and Phase 13's `0`.

**4.3 The precondition this plan places on 14.0, and it is not optional.** `run_courts.py` refuses a
stratum that is not `not-started` and has no runner: "phase 14 (in-progress) is not `not-started`
and has no runner". Phase 13 satisfied this by landing `forensics/tools/phase13_courts.py` in the
same commit; this stratum lands `forensics/tools/phase14_courts.py`, whose only runnable court until
14.1 is the reference basis. **The reference basis is a new shape, and the plan states it rather
than implying the earlier one:** `RT-PHASE14-REF`
(`courts/phase14/rt_coverage_ref_probe.c`) takes the address of each of the stratum's 600
atlas-owned exports and prints whether each is non-NULL. Unlike every earlier reference basis, the
set it covers is **entirely unimplemented** at activation -- `implemented-surface.json` records `0`
implemented `libssl` symbols -- so the candidate proves the names exist through the Phase 2 ABI
scaffold and the atlas's phase-14 row binds no `referenced` name yet. The probe references; it does
not call, which is what keeps the scaffolds (they abort on call) from firing. It is registered in
`court-coverage-rows.json`'s `reference_probes` as `RT-PHASE14-REF` is, and the atlas records a
symbol covered only by it at basis `referenced`, never `called`.

So the activation order is: the ledger, the plan, the runner and the reference probe land
**together**, or `forensics/tools/pipeline.sh` fails at `run_courts.py` and the tree carries an
activation whose runner is refused. This document states the precondition; the runner is
`forensics/tools/phase14_courts.py` and the probe is `courts/phase14/rt_coverage_ref_probe.c`, and
both are `courts/`-side work rather than this plan's files.

**4.4 "TLS / DTLS (`libssl`)" here is the protocol engine, not the cryptography or the commands.**
The `EVP` and primitive calls the record layer and the ciphersuites reach are Phases 7 and 8's, the
`X509` objects the certificate plumbing carries are Phase 11's, and the `openssl s_client` and
`s_server` commands that consume `SSL_CTX` are Phase 16's. Measured,
`forensics/atlas/symbol-ownership.json` assigns the whole of `ssl.h`, `tls1.h`, `srtp.h` and
`sslerr_legacy.h` to phase 14 and leaves the three `quic.h` names to phase 15, so the two readings
are reconciled by the ownership table rather than by widening it.

## 5. Process

This stratum inherits Phases 8 through 13's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every export carries a court edge in
`forensics/atlas/court-coverage.json` on the commit that lands it (D236); every provider row it
publishes is named by a probe of a court that covers it (D245); and an artefact that a source change
moves is regenerated in the same commit. `docs/DECISIONS.md` is append-only and this document is not
a decision record.

**This plan's own boundaries are the census's, and the census will correct them.** The subphase
table above was written from the defining units in `forensics/atlas/export-defining-units.json` and
the 600-row measurement in §1. D283's equivalent table for Phase 8 was corrected twice by
measurement — by D285, which found most of a slice was another stratum's, and by D287, which found a
prerequisite the slice's name could not show — and Phases 10 through 13 were each corrected inside
their own activation. The same is expected here and is not a defect in this document: the census is
the authority, and a subphase that discovers its unit is somewhere else records that rather than
forcing the row.

**Landed exports (checked against the ledger):**

Subphase 14.1 landed the stratum's first slice: **165** of the 600 atlas-owned exports moved into
the ledger's implemented set — the `ssl_lib.c` object model (the context and connection allocation, reference
counts and ex-data, the option/flag/mode/verify accessors and the `SSL_CTX_ctrl`/`SSL_ctrl`
dispatch, the callback setters, the `SSL_set_bio` plumbing, the version and state readers and the
read/write/handshake entry guards) plus **`TLS_method`**, the one `methods.c` constructor 14.1's court
builds its context with. Slice 2 then landed the verify, transparency, ALPN and connection-accessor
surface (126 more rows). The pulled-forward constructor is a measured correction to section 2's
ordering and is recorded in `src/ssl/mod.rs`, which also records the slice symbol by symbol and the
divergences the slices carry: the context constructor allocates without the cipher/group/sigalg
loaders, the connection constructor does not run the method's init and reset hooks, the control
surface's fall-through is not the method's own control dispatcher, and the candidate DSO duplicates
the crate's error state. Its court is `RT-SSL-OBJECT` (`courts/phase14/rt_ssl_object_probe.c`),
registered in `forensics/tools/phase14_courts.py`.

Subphase 14.2 landed the method and version tables: the 23 rows open at its activation — the whole
of `methods.c` less `TLS_method` (already pulled forward into 14.1), plus `s3_lib.c`'s three,
`SSL_get0_group_name`, `SSL_group_to_name` and `SSL_CTX_set_tlsext_ticket_key_evp_cb`. Every
`TLS_*`/`DTLS_*`/`TLSv1_*` constructor now returns its own static table (`TLS_method`,
`TLS_server_method`, `TLS_client_method`, `DTLS_method`, `DTLS_server_method`, `DTLS_client_method`,
the pinned `TLSv1_2_*`, `TLSv1_1_*`, `TLSv1_*`, `DTLSv1_2_*` and `DTLSv1_*` and their server/client
spellings), and `SSL_new` installs the any-version maximum of both families (`TLS_MAX_VERSION_INTERNAL`
for `TLS_ANY_VERSION`, `DTLS_MAX_VERSION_INTERNAL` for `DTLS_ANY_VERSION`). The ticket-key callback
is stored on the context and the two group-name accessors are reduced to the authority's unknown-id
answers because the context group table `ssl_load_groups` builds is 14.5's; both reductions are
recorded in `src/ssl/s3_lib.rs`. Its court is `RT-SSL-METHODS`
(`courts/phase14/rt_ssl_methods_probe.c`), registered in `forensics/tools/phase14_courts.py`.

Subphase 14.3 landed the cipher and configuration surface: the whole of `ssl_ciph.c` (the 25 rows
open at its activation) and `ssl_conf.c` (11), plus the five `ssl_lib.c` cipher-list accessors the
plan already named 14.3's. `src/ssl/ssl_ciph.rs` carries the three built-in ciphersuite tables
(`tls13_ciphers`, `ssl3_ciphers` and `ssl3_scsvs`, transcribed by
`forensics/tools/gen_phase14_cipher_tables.py` into the generated `src/ssl/ssl_ciph_table.rs`
alongside the four mask-to-NID tables and the alias table), the `SSL_CIPHER_*` readers, the
`OSSL_default_*` lists, the `SSL_CTX_set_ciphersuites`/`SSL_set_ciphersuites` setters, the
`SSL_COMP_*` compression surface, and the rule engine (`ssl_load_ciphers`, `ssl_create_cipher_list`
and its collect/apply/sort/process helpers) that `src/ssl/ssl_lib.rs`'s five accessors drive.
`src/ssl/ssl_conf.rs` carries the `SSL_CONF_CTX` lifecycle and flag accessors, the full command
table, and the `SSL_CONF_cmd`/`SSL_CONF_cmd_value_type`/`SSL_CONF_cmd_argv` dispatch. The disabled
masks are computed from the same provider fetches the authority runs, so the default preference
list the parser builds is the authority's; the certificate- and group-loading `SSL_CONF` commands
stay recognised but unwired until 14.5/14.7. Its court is `RT-SSL-CIPH`
(`courts/phase14/rt_ssl_ciph_probe.c`), registered in `forensics/tools/phase14_courts.py`. The
stratum now stands at 355 of the 600 atlas-owned exports implemented, with 245 open.

Subphase 14.4 landed the record layer: the 5 rows open at its activation — `rec_layer_s3.c`'s four
and `poll_immediate.c`'s one. `src/ssl/record/rec_layer_s3.rs` carries the two default read-buffer
length setters (`SSL_CTX_set_default_read_buffer_len`, `SSL_set_default_read_buffer_len`) and the two
record-state string readers (`SSL_rstate_string`/`_long`), which read a `rlayer.rstate` scalar a fresh
connection sets to `SSL_ST_READ_HEADER` so they answer the authority's `"RH"`/`"read header"`.
`src/ssl/rio/poll_immediate.rs` carries the non-QUIC `SSL_poll` readout and its three refusal arms.
Both files record their divergences: the record-read method object is not modelled (only the state
value the switch reads), the buffer-length setters have no public reader on either side, and
`SSL_poll`'s QUIC and blocking paths are unreachable for objects this crate builds. Its court is
`RT-RECORD` (`courts/phase14/rt_record_probe.c`), registered in `forensics/tools/phase14_courts.py`.
The stratum stood at 360 of the 600 atlas-owned exports implemented, with 240 open.

Subphase 14.5 landed the handshake state machine: the 18 rows open at its activation — `statem.c`'s
four, `extensions_cust.c`'s five and `t1_lib.c`'s nine. `src/ssl/statem/statem.rs` carries the four
state readers, reading the three state words `SSL_new` installs to the authority's post-`SSL_new`
values (`TLS_ST_BEFORE`, `MSG_FLOW_UNINITED`, `in_init = 1`). `src/ssl/statem/extensions_cust.rs`
carries the custom-extension registration surface (the type switch, the accept/refuse ladder and the
role-aware lookup), which required a `custext` record list on `Cert`. `src/ssl/t1_lib.rs` carries the
MFL accessors, the four signature-algorithm readers, `SSL_check_chain`'s refusal arms and the
provider-probing `SSL_get1_builtin_sigalgs`, whose table it transcribes. Each file records its
divergences: the sigalg lookup cache is not loaded (14.1's recorded `SSL_CTX_new_ex` reduction),
`SSL_check_chain` lands only its refusal arms, the old-style custom-extension callbacks are stored
without the authority's wrapper allocation, and the GOST rows of the sigalg table are omitted because
the admitted authority's default provider publishes neither their digests nor their key types. Its
court is `RT-STATEM` (`courts/phase14/rt_statem_probe.c`), registered in
`forensics/tools/phase14_courts.py`. The stratum now stands at 378 of the 600 atlas-owned exports
implemented, with 222 open.

**Open exports (checked against the ledger):**

The remaining 222 exports are the object model's deeper surface and the strata that depend on it:
47 `ssl_lib.c` rows (14.1's own session/certificate plumbing, DANE, the CT surface, the client-hello
readers and the QUIC stream accessors), 65 `ssl_sess.c` rows and the rest distributed across
subphases 14.6 to 14.10 as section 2 partitions them — `bio_ssl.c` (6), `ssl_cert.c` (20),
`ssl_rsa.c` (19), `ssl_rsa_legacy.c` (6), `ssl_cert_comp.c` (8), `ssl_asn1.c` (3), `ssl_txt.c` (3),
`d1_lib.c` (3), `d1_srtp.c` (4), `tls_srp.c` (19), `ssl_stat.c` (6), `ssl_mcnf.c` (3), `tls_depr.c`
(3), `t1_trce.c` (1), `ssl_init.c` (1), `ssl_err_legacy.c` (1) and the four `quic/` rows.
Representative names are `BIO_new_ssl`, `PEM_read_SSL_SESSION`, `SSL_CTX_use_certificate`,
`DTLSv1_listen`, `SSL_CTX_config`, `OPENSSL_init_ssl` and `SSL_trace`.
