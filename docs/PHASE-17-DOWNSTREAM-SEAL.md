# Phase 17 — the downstream replacement court: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. The stratum's obligation ledger is empty of open rows —
`forensics/phase17-obligations.json` reads `open_in_this_stratum: 0` — every earlier stratum is
`complete`, and the FRF/Gemel chain entry §8 records has landed, so `forensics/phase-state.json`
reports phase 17 **`complete`** with an empty blocking reason. That derived state is the
phase-exit predicate, and D529 records that a ledger's own `complete` is *not* it
(`docs/DECISIONS.md`). `seal_sha256` is derived too: this document is named in
`forensics/tools/atlas_common.py`'s `SEAL_DOCS` table at `17`, which
`forensics/tools/render_seal_census.py` and `phase_state.py` read, so the line is recomputed
whenever this document changes and is not restated here. Reaching `complete` means the stratum has
reached the state a seal *records* (D421); it is **not** a parity claim, and this document is where
what the derivation does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This seal
cites that document rather than restating its arithmetic, because a number typed here is a number
that can drift from the evidence it summarises (D97). The one table this document *does* carry —
§3's court list — is copied from `artifacts/phase17/COURTS.json`, and it says so.

**This seal records a candidate-transcription claim, and it is neither a security claim nor a
parity claim.** Its evidence shows that the behaviours the stratum's six courts exercise match the
pinned authority's over fixed fixtures, observation for observation, on the five differential
courts, and that the machine-owned downstream corpus this stratum seals on is internally consistent
with the current candidate. It does **not** show that the crate's CLI is a drop-in replacement for
the `openssl` program, that its reduced TLS 1.3 engine interoperates with every peer or matches the
authority's wire bytes, that the cross-DSO shared state is safe under concurrency, or that any of it
is safe against a hostile input. `docs/PARITY_MODEL.md` is the authority on what the labels mean: a
passing bounded court is a differential result over the behaviours that court exercises.
`PARITY_VERIFIED` is not claimed for any symbol here — indeed this stratum owns none — and
`forensics/STATUS.md`'s non-claims are the generated projection's.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json`), named as the
  authority by `artifacts/phase17/COURTS.json`.
- Court results: `artifacts/phase17/COURTS.json` — six courts, `all_pass` true, zero residuals; the
  per-court table is §3. Five are **differential** and declare an FRF court
  (`RT-CLI-BODIES`, `RT-TLS13-INTEROP`, `RT-TLS13-INTEROP-MATRIX`, `RT-CROSS-DSO-STATE`,
  `RT-DOWNSTREAM-CONSUMER`); the sixth, `RT-DOWNSTREAM-CORPUS`, is a **data-validation** court whose
  own row is marked `frf_declarable: false`, and §1 and §3 state why.
- Obligation ledger: `forensics/phase17-obligations.json` — `owned` 5, `implemented` 5,
  `deferred_to_later_phase` 0, `open_in_this_stratum` 0; its unit is `downstream replacement
  contract`, a non-export unit, and its `atlas_owned` count is 0. `contract_units` 5,
  `provider_rows_owned` 0, `provider_rows_open` 0, `unit_deferrals_received` 0, and the 52
  `apps/<name>.c` unit deferrals D530 hands forward are all discharged (`unit_deferrals` empty).
- Court coverage: `forensics/atlas/court-coverage.json` records **no phase-17 row**, and that is the
  join's own definition rather than an omission: `court_coverage.py` skips a ledger whose unit is in
  `atlas_common.NON_EXPORT_UNITS` (the same rule Phase 16's `cli-config contract` and Phase 22's
  `compatibility plane` meet), so a stratum with no export universe can have no row and no unmatched
  export. §1 and §3 state the reading; `docs/DECISIONS.md` D485 records the marker.
- Derived state: `forensics/phase-state.json`, phase 17, `complete` with empty blocking. It owns
  **no exported symbol**, so its `atlas_owned` count is 0 and it registers no provider row.
- FRF receipts and claim: **present, and the chain's objects are on disk.** `.frf` carries five
  receipts, one per declarable court; ten adjudicated challenge records (both operators on every
  court); and the `sensitivity-backed` claim
  `d04cd5bbd876008366b72548b95260650f18dbc27088ee0ecc3b5f618d587450`, binding
  `openssl-rt-3.6.4-r2` to `openssl-rs 0.0.25` (`identity_hash e4f60d8b`) with zero blockers. Two of
  the five premises are narrowed to the exit class, and §8 states what that is.
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s
  `current:` is the checkpoint `K61`
  (`checkpoint.8269810786499a3fd45b482760e5de1761e06b4637922ccbeb8a2174e047ecd7`), whose summary
  names Phase 17 and the FRF chain; the change that closes it is
  `C108` (`change.0fa422966a3429aad18f93626b862d7e52992298f6f69f6cec38aa77d3650efc`). §8 states
  what that is.
- Deciding record: `docs/DECISIONS.md` — **D530** fixed the 52 command bodies and the two entrance
  criteria this stratum is held to, **D529** is the Phase-16 seal whose chain this one mirrors,
  **D485** is the non-export-unit marker, **D525** hands the legacy provider rows past this
  stratum, and `docs/PHASE-17-SUBPHASES.md` is the subphase plan this seal closes. §10 summarises
  the corrections this seal records.

## 1. What this phase owns, and how that was decided

Phase 17 is **the downstream replacement court stratum**, and like Phase 16 it owns **no exported
symbol**. Reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 17` yields nothing
(`docs/PHASE-17-SUBPHASES.md:30-32`), because the declaring-header rule assigns no installed header
to this stratum; its ledger's `atlas_owned` count is therefore `0` and the ledger fails closed if
that ever stops being true rather than counting a symbol through a non-export unit
(`forensics/tools/phase17_obligations.py`).

**The working set is its rows, not its exports.** `forensics/phase17-obligations.json`'s `rule`
names two kinds of row, every one read from an atlas this stratum does not type:

* **the 52 `apps/<name>.c` CLI command bodies.** `forensics/prerequisites.json`'s `units` block
  records 52 command translation units as `deferred_to_later_stratum` with `owner_phase: 17` — the
  bodies Phase 16.4 landed a dispatcher for but not the bodies, handed forward by D530. Each is an
  executable translation unit no symbol atlas carries, which is why the vehicle is a `units` row
  rather than a `deferrals` row. All 52 are discharged: the ledger's `unit_deferrals` is empty once
  the plane records each body's row instead as the `reached_by_a_named_construct` record
  `plan_reconciliation.py` requires, and the ledger fails closed unless the plane still records all
  52.
* **the downstream replacement contract** proper: the `openssl` CLI command bodies over
  `libcrypto`/`libssl`, a real TLS 1.3 interoperability handshake, the cross-DSO shared state the
  candidate's whole-crate archives create, and a real downstream consumer whose authority surface
  the prerequisite plane and this stratum's own courts measure.

**The contract is five units**, each derived from a surface that measures it:
`command-bodies` (the 52 unit deferrals above), `tls13-interop` (the `RT-TLS13-INTEROP` and
`RT-TLS13-INTEROP-MATRIX` courts), `cross-dso-state` (the `RT-CROSS-DSO-STATE` court),
`downstream-consumer` (the `RT-DOWNSTREAM-CONSUMER` court) and `downstream-corpus` (the
`RT-DOWNSTREAM-CORPUS` court). The ledger's `contract_units` reads 5 and all five are
`implemented`.

**The ledger's unit is not an exported symbol.** `forensics/phase17-obligations.json` publishes
`unit: "downstream replacement contract"`, its `implemented`/`open` export lists are empty *by
measurement*, and its working set is counted in `open_in_this_stratum`. `atlas_common.NON_EXPORT_UNITS`
names the unit, so the two tools that partition the export universe (`court_coverage.py`,
`ownership_audit.py`) skip this ledger rather than reconcile a symbol set that does not exist.

**The plane, and which one this stratum's evidence is.** D201's commitment — every
*primitive-bearing* subphase carries a differential `RT-*` court *and* a correctness `CT-*` court —
is scoped to primitive-bearing work. This stratum emits no primitive: a command body is a *program
over* the libraries, and a TLS 1.3 handshake is a flight of the state machine, not a set of exports.
Its evidence is therefore **differential only** — five `RT-*` courts and no `CT-*` court — which is
a measurement and not an omission. There is **no reference basis** here either: every differential
court diffs a real transcript and stages an authority/candidate probe pair, so all five are
declarable and nothing is left to an address-taking `RT-*-REF` (contrast Phases 13, 14 and 15).

**It begins on nothing of its own, and ends owning everything it began with.** No module of this
stratum had landed at activation (`docs/PHASE-17-SUBPHASES.md:59-63`): the 52 command bodies reached
`src/apps/openssl.rs`'s `not_landed` boundary, and no interop, cross-DSO or downstream-consumer court
existed, so `open_in_this_stratum` opened at the whole working set and moved to zero as 17.1 through
17.4a landed their rows and units. The ledger's `counts` is the live record; §1's activation
measurement is the plan's.

**This stratum is a non-export unit, and the export-partitioning tools say so by the document's own
field.** `forensics/phase17-obligations.json` publishes `unit: "downstream replacement contract"`,
which `atlas_common.NON_EXPORT_UNITS` contains, so `court_coverage.py` and `ownership_audit.py` skip
the ledger rather than reconcile a symbol set that does not exist — exactly as they skip Phase 16's
`cli-config contract` and Phase 22's `compatibility plane` (D485).

## 2. What has been built

**17.0, the plan and the ledger.** `docs/PHASE-17-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase17-obligations.json` and its generator, and the runner
`forensics/tools/phase17_courts.py` with the empty registry it writes. The runner could not be
deferred (`docs/PHASE-17-SUBPHASES.md` §4.2): `run_courts.py` refuses a stratum that is not
`not-started` and has no runner, and this stratum's obligations are not exports, so its first
runnable court is a later subphase's. It landed with `PENDING_COURTS` naming the planned courts,
which 17.1 through 17.4a emptied.

**17.1, the 52 CLI command bodies.** `src/apps/openssl.rs`'s dispatcher and the generated
`src/apps/tables.rs` `OPTIONS[]` table, and the 52 `apps/<name>.c` bodies landed in ordered slices
behind them: 17.1a `errstr`; 17.1b `info`, `prime`, `skeyutl`, `configutl`, `pkeyparam`, `nseq`;
17.1c `crl2pkcs7`, `ciphers`, `sess_id`, `kdf`, `mac`, `spkac`, `genrsa`, `dsaparam`; 17.1d
`asn1parse`, `ecparam`, `rsa`, `dsa`, `ec`, `pkey`, `pkcs8`, `verify`, `crl`, `rsautl`; 17.1e
`gendsa`, `rand`, `rehash`, `engine`, `storeutl`, `dhparam`, `genpkey`, `passwd`, `pkeyutl`, `enc`;
17.1f `dgst`, `pkcs7`, `ocsp`, `ts`, `speed`, `fipsinstall`, `srp`; 17.1g `x509`, `req`, `smime`,
`cms`, `pkcs12`, `ca`, `s_client`, `s_server`, `s_time`, `cmp`. `RT-CLI-BODIES` (805 observations
over 198 argv cases) runs the authority's own `openssl` and the candidate distribution shell's over
a fixed argv through the shell probe `courts/phase17/rt_cli_bodies_probe.sh`.

**17.2, the TLS 1.3 interoperability handshake.** 17.2a the client's first flight
(`tls_construct_client_hello` over a reduced plaintext record write); 17.2b the server's first
flight (`tls_process_client_hello`, `tls_construct_server_hello`, the `extensions_srvr` framework
and the reduced group/key-share infrastructure); 17.2c the rest of the flight — the reduced TLS 1.3
key schedule (`src/ssl/tls13_enc.rs`), the client's read path and the server's encrypted flight.
`RT-TLS13-INTEROP` (69 observations) drives each side's own client and server over memory BIOs to
`TLS_ST_OK` and exchanges a 15-byte application record each way. The interoperability court proper
is `RT-TLS13-INTEROP-MATRIX` (154 observations): the peer `courts/phase17/rt_tls13_matrix_peer.c` is
compiled twice and the driver `courts/phase17/rt_tls13_matrix_driver.c` forks one peer per side over
an `AF_UNIX` socketpair and drives the four cells `auth-auth`/`cand-auth`/`auth-cand`/`cand-cand`.

**17.3, the cross-DSO shared-state court.** `RT-CROSS-DSO-STATE` (18 observations) measures the
shared-state contract the candidate's whole-crate archives break, in both directions: a
libssl-raised error read through libcrypto's `ERR` queue, and a `CONF` command set through
libcrypto read through libssl's `SSL_CTX_config`. Its measurement verdict is `pass` and its
compatibility verdict is `PASS`, and §4 records the divergence it began on.

**17.4, the downstream consumer.** `RT-DOWNSTREAM-CONSUMER` (59 observations): a real consumer
linked only against the shipped install prefix (`artifacts/phase2/install/`) with the out-of-tree
link shape, exercising an EVP digest, an X.509 PEM parse, a libcrypto `ERR` round-trip and a TLS 1.3
handshake over memory BIOs.

**17.4a, the machine-owned downstream corpus.** Six real downstream programs
(`courts/phase17/downstream/`) are built against the candidate distribution shell and exercised by
`run_all.sh`, each with a measured `result.json` aggregated into
`forensics/atlas/downstream-corpus.json`; `RT-DOWNSTREAM-CORPUS` (6 observations) validates the
recorded corpus and its freshness. §5 records the corpus and §7 records that the seal depends on it.

**17.5, the seal.** This document, the FRF/Gemel chain §8 records, and the registry rows the chain
requires.

**The books that moved with the code.** Phase 17's own ledger reads `owned` 5, `implemented` 5,
`deferred_to_later_phase` 0 and `open_in_this_stratum` 0, with `contract_units` 5 and no provider
row. The working set is the 52 unit deferrals and the five contract units; the split moved as the
subphases landed their rows, so this note does not restate counts the ledger is the live record of.

## 3. The evidence

Copied from `artifacts/phase17/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. The five differential courts are transcript comparisons; the sixth
is a data-validation court, so its row carries no `probe` pair and its own `frf_declarable` is
false.

| court | plane | observations | instrument |
|---|---|---|---|
| `RT-CLI-BODIES` | differential | 805 | `courts/phase17/rt_cli_bodies_probe.sh` (shell probe) |
| `RT-TLS13-INTEROP` | differential | 69 | `courts/phase17/rt_tls13_interop_probe.c` |
| `RT-TLS13-INTEROP-MATRIX` | differential | 154 | `courts/phase17/rt_tls13_matrix_peer.c` + `rt_tls13_matrix_driver.c` |
| `RT-CROSS-DSO-STATE` | differential | 18 | `courts/phase17/rt_cross_dso_state_probe.c` |
| `RT-DOWNSTREAM-CONSUMER` | differential | 59 | `courts/phase17/rt_downstream_consumer_probe.c` |
| `RT-DOWNSTREAM-CORPUS` | data-validation | 6 | `forensics/atlas/downstream-corpus.json` |

Every differential row carries `residual_count: 0` and `verdict: "pass"`, and the summary reads
`pass` 6 of `total` 6 with `pending_courts` empty. The total over the five transcript courts is
`docs/SEAL-CENSUS.md`'s, and the per-court rows there are the same computation.

**`RT-CLI-BODIES` is a shell probe, and it is declared honestly.** The CLI is an executable, not a
linkable symbol, so `courts/phase17/rt_cli_bodies_probe.sh` is the instrument: it drives one side's
`openssl` over the fixed 198-case argv and prints the same `case.N.*` transcript the court venue
diffs. `forensics/tools/phase17_courts.py` stages it as the
`artifacts/phase17/probes/rt_cli_bodies_probe.{authority,candidate}` shim pair the FRF runtime
harness runs, and `gen_frf_courts.py` declares that `.sh` source as the court's data artifact rather
than a `rt_cli_bodies_probe.c` (`PROBE_SOURCES`), exactly as Phase 16's `rt-cli` is.

**Why there is no correctness plane, stated rather than left to inference.** D201's commitment is
scoped to primitive-bearing subphases, and this stratum emits no primitive: it lands programs over
the libraries and a state-machine flight. A `CT-*` court is a vector-driven construction check with
no authority transcript to diff (D13, D201), so the stratum's evidence is **differential only**,
which is a measurement and not an omission, and every arm that could not be driven is named in the
module or the court rather than counted as passing (§5).

**The court coverage join does not have a phase-17 row, and that is the join's own definition.**
`docs/SEAL-CENSUS.md`'s coverage table lists no phase-17 row for the same reason it lists no
phase-16 or phase-22 row: all three are non-export units, so `court_coverage.py` skips their ledgers
and there is no export to partition. `directly_courted` in this project means *referenced by a staged
candidate probe that ran and produced a transcript* — a proof of **reference** rather than that every
arm of a symbol was driven (D199/D236); with zero exports the join is vacuous here. The provider-row
join (D245) is likewise vacuous: this stratum owns no provider row.

**The data-validation court is not a transcript court, and its row says so.** `RT-DOWNSTREAM-CORPUS`
consumes `forensics/atlas/downstream-corpus.json` (aggregated from the six per-program
`result.json` records) and fails the stratum unless every program is present, every required field
is present, `functional` is true, `candidate` equals the current `Cargo.toml` version and each
corpus record still equals its per-program `result.json`. It is marked `frf_declarable: false`
because it stages no probe pair and diffs no authority transcript (D13); §7 records that the seal
depends on it, and §5 records what it consumes.

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
courts did look. They found real defects in the candidate, and one measurement record that is honest
about what the FRF venue can and cannot drive.

**The cross-DSO court began on a defect and its repair is this stratum's.** `RT-CROSS-DSO-STATE`
landed as a *recorded divergence* (17.3): because the crate links `libcrypto`, `libssl` and
`ossl-modules/legacy.so` as whole-crate archives, each DSO carried its own copy of the crate's
internal globals, so an error raised through the libssl path (`err.ssl.peek=0`) was not observable
through libcrypto's queue and a `CONF` command set through libcrypto (`conf.ctx_config.ret=0`) was
not observable through `SSL_CTX_config`. `src/runtime/dso_shared.rs` now resolves libcrypto's
exported `ERR_get_state`/`conf_ssl_*` owners, so one queue and one store serve both DSOs; the
measurement verdict is `pass` and the compatibility verdict `PASS`, with
`compatibility_residuals: []`.

**The downstream programs found defects, and each is a `historical_failure` the corpus records.** The
corpus is not a post-hoc assertion: every program's `historical_failures` names the commit that
exposed a candidate defect and the commit that fixed it. The corpora exposed, and the candidate
fixed, at least: curl's `SSL_CTX_set_min/max_proto_version` returning 0 (fixed by `91eb5398`) and
curl fetching HTTPS without a verification path (fixed by `e7b50d10`); nginx's five TLS defects
(SNI disabled, ticket callback, missing `close_notify`, `SSL_OP_IGNORE_UNEXPECTED_EOF`, an
intermittent handshake stall; fixed by `3e1c5313`); HAProxy's missing `SSL_CTX_ctrl` SNI arm; Git's
HTTPS transport blocked by the nginx defects; CPython's `_ssl` accepting an unrelated CA and its
`test_ssl` standing at 153 methods before TLS 1.2 session creation landed (fixed by `27b3e300`); and
OpenSSH's RSA/ECDSA signing failing with `initialization error` (fixed by `52b61567`). These are the
stratum's own findings, recorded in `courts/phase17/downstream/<program>/result.json` and generated
into each `EVIDENCE.md`.

**The FRF venue found that the reduced engine's raw transcript differs, and the claim is honest
about it.** Running `RT-TLS13-INTEROP` and `RT-DOWNSTREAM-CONSUMER` in the FRF tooling container
raised one `open` residual each on the harness's first stdout line, which is a digest of the whole
transcript. The cause is not a defect on a claimed surface: the probes print observation lines the
court *records rather than diffs* (§5), so the whole-transcript digest differs while every compared
observation agrees. Disposing the residual would have let the claim assert the first stdout line it
does not have; **leaving it open narrows those two premises to the exit class** and the claim
carries both axes on the other three. The claim
`d04cd5bbd876008366b72548b95260650f18dbc27088ee0ecc3b5f618d587450` compiles with zero blockers.

**The one instrument boundary: the cross-process matrix is measured in the court venue, not by the
single-process FRF harness.** `RT-TLS13-INTEROP-MATRIX` is a *cross-process* court: two
implementations cannot share one process, so its evidence is the driver's four-cell transcript in
the court venue. The FRF runtime harness runs one staged probe per side with no arguments, and the
peer binary takes a role and a connected socket descriptor, so its FRF run exercises the peer's
argument guard on both sides rather than the matrix. The declaration and its sensitivity evidence
are still valid — the court demonstrates axis isolation on both operators — but the interoperability
measurement is the court venue's 154-observation transcript, and this seal records the distinction
rather than counting the FRF run as the matrix.

**No generator drift the stratum's own slices left went unreconciled, and the seal forced none.**
Unlike Phase 14 (D529), whose later slices left four artefacts that only surfaced when the stratum
was derived `complete`, this stratum's slices are one plan, one ledger, one runner and six courts,
and deriving `complete` surfaced no reconciliation the slices had not already made. §10 records the
one correction this seal does make.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an unset field, or builds an object this crate
does not, the court does not call it and the divergence is recorded. **No divergence obligation
names Phase 17 as its `current_owner`.** `forensics/divergence-obligations.json` reads 10 rows and
**0 blocking** at seal time; no live obligation outran this stratum's evidence, so `phase_state.py`
derives `complete`. The boundaries this stratum actually met are recorded in the places below.

1. **The TLS 1.3 flight is reduced, and the on-the-wire bytes are recorded rather than diffed.**
   The candidate's engine builds a smaller `ClientHello` than the authority's full stack: its
   extension set is partial (no `renegotiation_info`/`ec_point_formats`/`signature_algorithms` and
   no hybrid `X25519MLKEM768` key share, so it sends a 38-byte `X25519` share where the authority
   sends 1258 bytes), and its reduced security callback admits SSL3 through TLS 1.2, so the offered
   `supported_versions` list is longer than the authority's. The court compares the terminal states,
   the carrying rounds and the application-data exchange, and records the byte counts as
   `recorded_divergences` rather than diffing them (`docs/PHASE-17-SUBPHASES.md` §3.4).
2. **The post-handshake `NewSessionTicket` flight is unlanded, so TLS 1.3 resumption is
   unavailable.** `RT-DOWNSTREAM-CONSUMER`'s `tls.flight.1.server.out` is 0 where the authority
   writes the ticket flight; the nginx record's `known_residuals` names the same boundary
   (`s_client -sess_out` saves nothing under TLS 1.3). TLS 1.2 resumption and tickets work. No
   court compares the TLS 1.3 ticket wire.
3. **The TLS 1.2 `NewSessionTicket` is stateful, not the authority's encrypted stateless blob.**
   The authority encrypts an `i2d_SSL_SESSION` under the context ticket key and reconstructs by
   decrypting (`construct_stateless_ticket`/`tls_decrypt_ticket`); this crate mints an opaque
   64-byte ticket and caches the server session under `SHA256(ticket)`, resuming by an
   internal-cache lookup. The client-observable shape is the authority's (`session.id` is
   `SHA256(ticket)`, `has_ticket` true, the lifetime hint is the session timeout), but the ticket
   bytes and `SSL_CTX_sess_number` after a handshake differ. No court compares the TLS 1.2 ticket
   wire (`src/ssl/ssl_sess.rs`).
4. **The cross-DSO shared state was the stratum's fault boundary and is now closed.** §4 records the
   whole-crate duplication and its repair (`src/runtime/dso_shared.rs`); the court's
   `compatibility_residuals` is empty. The candidate still links as whole-crate archives rather than
   the authority's one shared `libcrypto.so.3` via `DT_NEEDED`, and the court measures the *result*
   (one queue, one store) rather than asserting the link shape away.
5. **The CLI command bodies reach recorded divergences rather than diffs.** Forty-seven inputs are
   recorded rather than diffed, each a surface this stratum does not own: the build-dependent
   `info` selectors (seed source, CPU settings, the configured prefix and directories), the
   `BN_print` rendering (`prime`/`rsa`/`dsa -modulus` case and padding), the `ciphers` default-list
   `EVP`-fetch over the legacy provider, `sess_id -text -cert`'s `X509_print basicConstraints`, the
   pointer-bearing `ERR_print_errors` tails (`kdf`, `mac`, `spkac`, `ecparam`), `genrsa -bogus`'s
   `opt_set_unknown_name`, the `rand`/`gendsa`/`genpkey`/`dhparam` generation arms, `passwd`
   without `-salt`, the `engine` listing, and the many `-help`-gated arms (`opt_help` is unlanded).
   Each is named in `forensics/tools/phase17_courts.py`'s `RECORDED_DIVERGENCES`.
6. **The downstream residuals are environment and harness facts, not candidate defects.** OpenSSH's
   `regress/unittests/utf8` aborts on both the candidate and the authority because the court image
   ships only `C`/`C.utf8`/`POSIX` locales; Git's `t5540-http-push-webdav` is skipped because Git is
   built without expat, a plain-HTTP path with no OpenSSL use.
7. **The `pending.` set is empty, and that is a measurement.** Every court the plan names is
   registered in `artifacts/phase17/COURTS.json`, and `PENDING_COURTS` is empty; this stratum owns
   no exported symbol, so nothing is counted as pending rather than dropped (§3).

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable drop-in OpenSSL.** `implemented` in the ledgers means a symbol
   with that name is defined, and this stratum defines none. `docs/PARITY_MODEL.md` states what each
   label means; no symbol here is `PARITY_VERIFIED`, and `forensics/STATUS.md` carries the current
   non-claims. A landed command body or a passing handshake is at most `SEMANTIC_PASS` over the
   behaviours the court exercises — never `PARITY_VERIFIED`.
2. **This is a candidate-transcription claim, and it is not a security claim.** The evidence shows
   the courts' fixtures match; it does **not** show the crate's CLI, TLS engine, cross-DSO state or
   downstream shell is safe against a hostile input, and no court here is a fuzz or security gate.
   `docs/SECURITY_DIVERGENCE_POLICY.md` records the boundaries; a boundary not exercised is
   recorded, not a safety guarantee.
3. **No drop-in CLI claim.** `RT-CLI-BODIES` compares the dispatcher's arms, the 52 landed command
   bodies and the recorded divergence set over a fixed argv. It does not establish byte-identical
   stderr, the many recorded-divergence arms, full CLI compatibility, or that any command whose arm
   is recorded rather than diffed works identically.
4. **No full-interoperability claim beyond the four measured cells.** `RT-TLS13-INTEROP-MATRIX`
   drives `auth-auth`/`cand-auth`/`auth-cand`/`cand-cand` over a fixed client/server pair and a
   fixed certificate, and nothing else. It does not claim interoperability with any other peer,
   version, cipher suite or extension set, and the reduced engine's wire bytes are recorded, not
   matched (§5.1).
5. **No completed-new-handshake claim beyond the measured flight.** `RT-TLS13-INTEROP` drives one
   fixed `ClientHello`-through-`Finished` flight and one application record each way; the
   post-handshake ticket flight is unlanded (§5.2), resumption is not exercised, and no court drives
   a renegotiation, a resumption, an alert path beyond the recorded ones or a second cipher suite.
6. **No concurrency-safety claim for the cross-DSO shared state.** `RT-CROSS-DSO-STATE` measures one
   error queue and one `CONF` store in a single-threaded probe; it does not claim the shared
   resolution is safe under concurrent DSO use, and no court drives it concurrently.
7. **No downstream-correctness claim.** The corpus records each program's `build`/`link`/`start`/
   `functional`/`concurrency` and its `known_residuals`; it does not claim a program is defect-free,
   and the `historical_failures` are the record that earlier candidate builds failed these programs
   before the fixes named there landed.
8. **The FRF and Gemel evidence is established, and §8 records what it is.**
   `docs/RELEASE_GATES.md` §2 items 6, 8 and 10 are met by the chain entry §8 records: five
   receipts, ten adjudicated challenge records, the `sensitivity-backed` claim
   `d04cd5bbd876008366b72548b95260650f18dbc27088ee0ecc3b5f618d587450` with zero blockers, and the
   Gemel checkpoint `K61` whose summary names Phase 17 and the FRF chain. Phase 17's derived state
   is `complete`. Two premises are narrowed to the exit class (§4), and that is recorded rather than
   smoothed.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process — a subphase lands its code, its court and its regenerated artefacts in **one
commit**; every name a subphase lands carries a court edge where it has one; and an artefact a
source change moves is regenerated in the same commit — and its §4.2 precondition (the runner lands
**with** the ledger). Every clause below is checked against a generated artefact rather than
asserted.

| criterion | evidence |
|---|---|
| every row this stratum owns is implemented or handed on with the dependency named | `forensics/phase17-obligations.json`: `open_in_this_stratum` 0, `deferred_to_later_phase` 0, `contract_units` 5 all `implemented`, `unit_deferrals` empty (the 52 bodies discharged) |
| the export-coverage join is vacuous here, and that is the marker's rule | no phase-17 row in `forensics/atlas/court-coverage.json`, because `phase17-obligations.json`'s `unit` is in `atlas_common.NON_EXPORT_UNITS` (D485); `phase_state.py` scopes the rule out for such a ledger |
| no authority fault is reproduced | §5, and the boundaries recorded in the probes and the modules |
| no blocking divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking; none names Phase 17 |
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
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json` pins `openssl-3.6.4-production`; `artifacts/phase17/COURTS.json` names it |
| 2 | obligation inventory | `forensics/phase17-obligations.json`; 5 contract units, 0 provider rows, 0 export rows |
| 3 | court manifests | `artifacts/phase17/COURTS.json` |
| 4 | raw captures | **met.** The five staged `artifacts/phase17/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (each row's `staged_binaries`), and `.frf/captures/` carries the FRF venue's captures for the five declarable courts, produced by §8's chain |
| 5 | residual set | **met in the court venue.** Every differential court's `residual_count` is 0 and its `residuals` list empty, `summary` reads `pass` 6 of 6 and `pending_courts` is empty. In the FRF venue, two premises carry one `open` first-line residual each, narrowed around by the claim and recorded in §4 |
| 6 | mutation / sensitivity evidence | **met.** `.frf/challenges/` carries ten adjudicated Phase-17 records — both declared axes (`stdout-first-line`, `exit-class`) on all five declarable courts, each `saw_defect` and `specificity_clean` |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-17 FRF residual is disposed `fixed` |
| 8 | FRF receipts | **met.** `.frf/receipts/` carries five Phase-17 receipts, one per declarable court |
| 9 | generated parity projection | `forensics/STATUS.md`, rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s `current:` is `K61` (`checkpoint.8269810786499a3fd45b482760e5de1761e06b4637922ccbeb8a2174e047ecd7`), whose summary names Phase 17 and the FRF chain |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and item 7 is not applicable
rather than wanting, because `--resolution-run` is required only for a `fixed` disposition and none
attaches to a Phase-17 FRF residual.** Items 6, 8 and 10 retired when §8's chain landed, and
`phase_state.py` now derives `complete` with an empty blocking reason.

**The seal depends on the machine-owned corpus, and that dependency is mechanical.** 17.4a records
each downstream program's measurement in `result.json`, aggregated into
`forensics/atlas/downstream-corpus.json`. `RT-DOWNSTREAM-CORPUS` is the seal's mechanical
dependency: `phase_state.py` blocks a stratum on any non-`pass` court in
`artifacts/phase17/COURTS.json`, so Phase 17 cannot derive `complete` while a program's `functional`
is false, a required field is missing or the recorded `candidate` is not the current `Cargo.toml`
version. The court validates the recorded corpus rather than re-running the multi-hour builds;
`courts/phase17/downstream/run_all.sh` is the driver that reproduces it, and
`courts/phase17/downstream/README.md` and each `EVIDENCE.md` are generated from the records, so the
prose cannot drift from the measurement.

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and this section records what it is.**

- **Five declarations are on disk.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table gained a
  Phase-17 block — `rt-cli-bodies`, `rt-tls13-interop`, `rt-tls13-interop-matrix`,
  `rt-cross-dso-state` and `rt-downstream-consumer` — and `gen_frf_courts.py` wrote the five
  declarations under `forensics/frf/courts/openssl-rs-rt-<court>`. `gen_frf_courts.py --check`
  reports `ok: 274 file(s) match the table (137 courts)`, and `forensics/frf/README.md` counts
  **137 runtime courts** — the five Phase-17 ones among them, which moves the manifest count
  `docs/RELEASE_GATES.md` names with it. `RT-DOWNSTREAM-CORPUS` is not declared: its
  `artifacts/phase17/COURTS.json` row is `frf_declarable: false`, so no declaration is generated
  for it and its evidence is the court table and the corpus atlas. `rt-cli-bodies`'s data artifact
  is `courts/phase17/rt_cli_bodies_probe.sh` (a shell probe) rather than a `.c` file, and
  `gen_frf_courts.py`'s `PROBE_SOURCES` records that.
- **The chain's objects are on disk.** `.frf/receipts/` carries five Phase-17 receipts, one per
  declarable court. `.frf/challenges/` carries ten adjudicated challenge records — both declared
  axes (`stdout-first-line`, `exit-class`) on all five courts, every one `saw_defect` and
  `specificity_clean` — which is what makes the claim `sensitivity-backed` rather than merely green
  (D13). `.frf/claims/` carries the compiled claim
  `d04cd5bbd876008366b72548b95260650f18dbc27088ee0ecc3b5f618d587450`, compiled at
  `--policy sensitivity-backed` over the five receipts, binding authority `openssl-rt-3.6.4-r2` to
  candidate `openssl-rs 0.0.25` (`identity_hash e4f60d8b`) with zero blockers. **The identity is
  the current 0.0.25 release**: the chain was cut into the store the 0.0.25 release regenerated from
  clean, and the claim records the candidate the tree is (`gen_frf_courts.CANDIDATE_VERSION`), which
  is what the fix-4 identity clause requires. Two premises — `rt-tls13-interop` and
  `rt-downstream-consumer` — are narrowed to the exit class because the reduced engine's raw
  transcript differs on the harness's first-line digest; §4 records why leaving the residual open is
  the honest reading.
- **The Gemel change and checkpoint are this stratum's.** The change `C108`
  (`change.0fa422966a3429aad18f93626b862d7e52992298f6f69f6cec38aa77d3650efc`) names Phase 17, its
  courts, the five contract units, the 52 command bodies, the two entrance criteria and the
  six-program downstream corpus; the checkpoint `K61`
  (`checkpoint.8269810786499a3fd45b482760e5de1761e06b4637922ccbeb8a2174e047ecd7`) closes it. The
  projection `forensics/GEMEL_TRAJECTORY.md` carries both, and the checkpoint's summary names Phase
  17 and the FRF chain. Items 6, 8 and 10 of §7 retired with that entry, exactly as they did for
  Phase 8's `C74`, Phase 9's `C94`, Phase 10's `C95`, Phase 11's `C97`, Phase 12's `C98`, Phase 13's
  `C99`, Phase 14's `C101`, Phase 15's `C103` and Phase 16's `C106`.

**The declarations are produced by `gen_frf_courts.py`; the receipts, challenges, claim and
checkpoint were produced by running the chain in the FRF tooling container, never on the host.**
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
This section records the objects that are on disk.

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase17-obligations.json`'s
`deferred` list is empty and its `deferred_to_later_phase` reads 0; every row this stratum owns is
implemented, and it received the 52 unit deferrals from Phase 16 and discharged all of them. The
reduced handshake, the post-handshake ticket flight and the many recorded-divergence CLI arms are not
rows this stratum's ledger owns — they are named boundaries rather than deferrals (§5) — so nothing
moves forward.

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF/Gemel chain entry has landed.** §8's subject is now the objects on disk: the five
  declarations, five receipts, ten adjudicated challenges, the claim
  `d04cd5bbd876008366b72548b95260650f18dbc27088ee0ecc3b5f618d587450` and the checkpoint `K61`.
  This stratum registers no `CT-*` court, so the entry covers the five behavioural differential
  courts and records `RT-DOWNSTREAM-CORPUS` as not declarable. Items 6, 8 and 10 of §7 retired with
  it, and `phase_state.py` derives `complete`.
- **The machine-owned corpus is the seal's live dependency.** 17.4a's records are data, not
  assertions: a program that stops being functional, a missing required field or a `Cargo.toml`
  version bump that the records do not name turns `RT-DOWNSTREAM-CORPUS` to `fail` and blocks the
  stratum. `courts/phase17/downstream/run_all.sh` is how a later reader reproduces it.
- **`forensics/phase17-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table
  and the head matter's court and row figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections this seal makes to the evidence and the tools, and the
corrections the evidence forced rather than the ones a reviewer might have preferred.

1. **The FRF declaration table learned a second shell-probe court, and the FRF runtime manifest
   count moved with it.** `gen_frf_courts.py`'s `PROBE_SOURCES` gained `rt_cli_bodies_probe` ->
   `rt_cli_bodies_probe.sh`, so `rt-cli-bodies`'s data artifact is the shell probe rather than a
   `.c` file, exactly as Phase 16's `rt-cli` is. `--check` moved from `264 file(s) (132 courts)` to
   `274 file(s) (137 courts)`, and `forensics/frf/README.md` and `docs/RELEASE_GATES.md`'s
   manifest-count sentence were moved with it, because `docs_consistency.py` binds both to the
   registry.
2. **The two reduced-engine premises are correctly narrowed, and the seal records it rather than
   disposing the residuals.** The FRF venue's first stdout line is a digest of the whole transcript,
   so the reduced TLS 1.3 engine raises an `open` first-line residual on `rt-tls13-interop` and
   `rt-downstream-consumer`. Disposing it would have let the claim assert a first stdout line it
   does not have; leaving it open narrows those two premises to the exit class and keeps the claim
   honest. §4 and §8 record the reading.
3. **The cross-process matrix is measured in the court venue, and the seal says so.** The
   single-process FRF runtime harness cannot drive the matrix peer, so its FRF run is a
   presence-and-sensitivity record rather than the interoperability measurement, which is the court
   venue's 154-observation four-cell transcript. §4 records the instrument boundary.
4. **`atlas_common.SEAL_DOCS` gained `17: docs/PHASE-17-DOWNSTREAM-SEAL.md`**, so
   `render_seal_census.py` and `phase_state.py` recompute this document's `seal_sha256`, exactly as
   Phase 16's seal is recorded.
5. **The FRF/Gemel chain entry landed, and §7 and §8 record it.** The seal's §8 records the five
   declarations, five receipts, ten adjudicated challenges, the `sensitivity-backed` claim
   `d04cd5bbd876008366b72548b95260650f18dbc27088ee0ecc3b5f618d587450` and the Gemel change `C108`
   / checkpoint `K61`
   (`checkpoint.8269810786499a3fd45b482760e5de1761e06b4637922ccbeb8a2174e047ecd7`), so items 6, 8
   and 10 retired and `phase_state.py` derives `complete`. `seal_sha256` is recomputed from the
   document's new bytes.
