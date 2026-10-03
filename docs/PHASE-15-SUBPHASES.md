# Phase 15 — QUIC / ECH and modern SSL surface, as subphases

## 0. What this stratum is, and what it is not

Phase 15 is the stratum `docs/RELEASE_GATES.md` §1 names "QUIC / ECH and modern SSL surface". By
`forensics/atlas/symbol-ownership.json`'s declaring-header rule it owns **exactly three exports**,
all `libssl`, all declared in `quic.h`: `OSSL_QUIC_client_method`,
`OSSL_QUIC_client_thread_method` and `OSSL_QUIC_server_method`. They sit in libssl's DSO beside
Phase 14's 600 `ssl.h`/`tls1.h`/`srtp.h`/`sslerr_legacy.h` exports, and Phase 14's plan and seal
name them as this stratum's by their declaring header and land none of them
(`docs/PHASE-14-SUBPHASES.md` §1 and §4.1, `docs/PHASE-14-TLS-SEAL.md` §9).

It is **not** the QUIC implementation object the method table points at, nor the TLS message layer
Phase 14 deferred. The method table's dispatch functions (`ossl_quic_new`, `ossl_quic_accept`,
`ossl_quic_connect` and the rest of `quic_impl.c`) and the message construction and parsing
(`ssl/statem/statem_clnt.c`, `ssl/statem/statem_srvr.c`) are unlanded; the two message-layer units
are recorded as `deferred_to_later_stratum` to this stratum in `forensics/prerequisites.json`, and
the QUIC object is not an export of this stratum's header. Nor is it the ECH extension surface,
which is `ssl.h`'s and so Phase 14's. The three constructors are the whole of this stratum's
export set; a subphase that discovers its unit is somewhere else records that rather than forcing
the row (§4).

## 1. The measurement this plan rests on

Every number below is read from `forensics/atlas/`, not typed, and
`forensics/phase15-obligations.json` is authoritative for the present.

**Phase 15's atlas-owned universe is three exports, all `libssl`, all `quic.h`.** Reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 15`:

| header | exports | what it declares |
|---|---|---|
| `quic.h` | 3 | the three `OSSL_QUIC_*_method` constructors |

**It receives no hand-off.** Every row of every `forensics/phase*-obligations.json` whose
`owning_phase` is 15 is discovered rather than listed, and there are none:
`received_by_handoff` reads **0**. The two authority units `forensics/prerequisites.json` defers to
this stratum (`ssl/statem/statem_clnt.c` and `ssl/statem/statem_srvr.c`) are unit deferrals for the
prerequisite gate, not export hand-offs, and do not move that count.

**It begins on a landed `libssl` substrate.** Phase 14 is `complete`, so
`forensics/atlas/implemented-surface.json` already records its 600 `libssl` exports as
implemented; the three `quic.h` names were the only `libssl` exports that stratum did not own, and
at activation they are present only as the Phase 2 ABI scaffold
(`artifacts/phase2/shell/libssl.shell.rs`), which aborts when called. So the working set is three
and the ledger's `open` count opens at **3** and moves to zero as 15.1 lands them. **That split
moves as this stratum lands its own units: the ledger's `counts` is the live record and this
section is the activation measurement.**

**The three exports are defined by one authority translation unit**,
`ssl/quic/quic_method.c` (`forensics/atlas/export-defining-units.json`), and 15.1 lays it out as
`src/ssl/quic/quic_method.rs`.

**Phase 15 publishes no provider registration row.** Reading
`forensics/atlas/provider-algorithms.json` for `owning_phase == 15` yields nothing: QUIC is not a
provider and this stratum activates none. The ledger's `provider_rows_owned` is therefore `0` and
`phase_state.py`'s provider-row rule and `provider_court_coverage.py` have nothing to hold against
this stratum — the mirror of Phases 12, 13 and 14.

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 15.0 | **The plan and the census** | `docs/PHASE-15-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase15-obligations.json`) and its generator land with it. **The runner and the reference-basis probe land with it too, and §4.2 is why they cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and `RT-PHASE15-REF` is the stratum's only court until 15.1 lands a unit. | 14 | — |
| 15.1 | **The three QUIC method constructors** | `ssl/quic/quic_method.c` (3). `OSSL_QUIC_client_method`, `OSSL_QUIC_client_thread_method` and `OSSL_QUIC_server_method`, each the `IMPLEMENT_quic_meth_func` expansion — a process-lifetime `static const SSL_METHOD` carrying `OSSL_QUIC_ANY_VERSION`, no flags, no mask, `tls1_default_timeout`, the `ssl3_undef_enc_method` enc table and the `q_accept`/`q_connect` role pair. **Landed (checked against the ledger): all three rows, in `src/ssl/quic/quic_method.rs`.** | 15.0 | `RT-QUIC` |
| 15.2 | **The seal** | nothing in the crate — evidence: `docs/PHASE-15-QUIC-ECH-SEAL.md` (at the seal) | 15.0–15.1 | — |

The two rows above the seal and 15.1 partition the three exports exactly, by defining unit: 3 = 3,
and the one open unit appears in exactly one row. The partition is derived from
`forensics/atlas/export-defining-units.json` joined to the ledger's `open` list, not typed.

## 3. What each subphase must honour

**3.1 A method is a version and a dispatch table, and the constructor is the observable.** Each
constructor returns its own process-lifetime static. The court compares the non-NULL return, the
distinctness of the three statics, `SSL_CTX_new`'s acceptance of each, the identity
`SSL_CTX_get_ssl_method` reports back, the method's `tls1_default_timeout` through
`SSL_CTX_get_timeout`, and the version-inflexible protocol-bound arm (`ssl_set_version_bound` is
keyed on the method's `version`, which is `OSSL_QUIC_ANY_VERSION` and therefore neither
`TLS_ANY_VERSION` nor `DTLS_ANY_VERSION`, so `SSL_CONF_cmd(ctx, "MinProtocol", "TLSv1.2")` returns
success and leaves the context's minimum at zero).

**3.2 The QUIC object and the dispatch bodies are not this unit's.** The method table points at
`ossl_quic_new`/`_accept`/`_connect` and the rest of `quic_impl.c`, which this stratum does not
build. `SSL_new` on a QUIC method is therefore **not driven**: the authority builds a
`QUIC_CONNECTION` (and refuses `OSSL_QUIC_server_method`), while a candidate connection from these
methods is an ordinary `SSL` object, so the two would report different `SSL_is_quic` and
`SSL_version`. The divergence is recorded in `src/ssl/quic/quic_method.rs` rather than diffed.

**3.3 Nothing here is a parity claim about a completed QUIC handshake.** No arm of the court
builds or drives a connection; the measured surface is the constructors and the context each
installs. A name that cannot be driven is named `pending` rather than counted as passing.

## 4. Measured corrections, and the precondition

**4.1 The working set is exactly the atlas projection, and the empty hand-off set is a
measurement.** The atlas's `owner_phase == 15` rows are three and no
`forensics/phase*-obligations.json` records an `owning_phase == 15` deferred row, so
`received_by_handoff: 0` is what the discovery found rather than an omission.

**4.2 The precondition this plan places on 15.0, and it is not optional.** `run_courts.py` refuses
a stratum that is not `not-started` and has no runner. This stratum lands
`forensics/tools/phase15_courts.py`, whose only runnable court until 15.1 is the reference basis.
`RT-PHASE15-REF` (`courts/phase15/rt_coverage_ref_probe.c`) takes the address of each of the
stratum's three atlas-owned exports and prints whether each is non-NULL; it references and does not
call, which is what kept the Phase 2 scaffold (it aborts on call) from firing at activation. It is
registered in `court-coverage-rows.json`'s `reference_probes`, and the atlas records a symbol
covered only by it at basis `referenced`, never `called` (docs/DECISIONS.md D199).

So the activation order is: the ledger, the plan, the runner and the reference probe land
**together**, or `forensics/tools/pipeline.sh` fails at `run_courts.py` and the tree carries an
activation whose runner is refused.

**4.3 "QUIC / ECH and modern SSL surface" here is the method constructors, not the object.** The
QUIC object and the message layer are named in §0 and deferred; the three `quic.h` constructors are
the whole of the stratum's export set, and the two readings are reconciled by the ownership table
rather than by widening it.

## 5. Process

This stratum inherits Phases 8 through 14's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every export carries a court edge in
`forensics/atlas/court-coverage.json` on the commit that lands it (D236); and an artefact that a
source change moves is regenerated in the same commit. `docs/DECISIONS.md` is append-only and this
document is not a decision record.

**This plan's own boundaries are the census's, and the census will correct them.** The subphase
table above was written from the defining unit in `forensics/atlas/export-defining-units.json` and
the three-row measurement in §1. A subphase that discovers its unit is elsewhere records that
rather than forcing the row.

**Landed exports (checked against the ledger):**

`OSSL_QUIC_client_method`, `OSSL_QUIC_client_thread_method` and `OSSL_QUIC_server_method`, the
whole of quic.h's export set, landed by 15.1 in src/ssl/quic/quic_method.rs. Each is a
process-lifetime static method table built from the authority's own constants, and the module
records the divergences the reduction carries: the QUIC dispatch functions and the QUIC object are
not built here, so SSL_new on a QUIC method is not driven and the QUIC connection object is a
later stratum's. Its court is RT-QUIC (courts/phase15/rt_quic_probe.c), registered in
forensics/tools/phase15_courts.py.

**Open exports (checked against the ledger):**

None: all three quic.h constructors are implemented, so the ledger's open list is empty.
