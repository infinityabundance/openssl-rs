# Phase 17 — the downstream replacement court, as subphases

## 0. What this stratum is, and what it is not

Phase 17 is the stratum `docs/RELEASE_GATES.md` §1 names "Downstream replacement court". Like
Phase 16 it owns **no exported symbol**: reading `forensics/atlas/symbol-ownership.json` for
`owner_phase == 17` yields nothing, because the declaring-header rule assigns no installed header to
this stratum. Its unit is therefore not a symbol. What it owes is two kinds of *row*:

* **the 52 CLI command bodies.** `forensics/prerequisites.json`'s `units` block records 52
  `apps/<name>.c` translation units as `deferred_to_later_stratum` with `owner_phase: 17` — the
  command bodies Phase 16.4 did not own, handed forward by D530. Each is an executable translation
  unit no symbol atlas carries, which is why the vehicle is a `units` row rather than a `deferrals`
  row (D530).
* **the downstream replacement contract** proper: the `openssl` CLI command bodies over
  `libcrypto`/`libssl`, a real TLS 1.3 interoperability handshake, the cross-DSO shared state the
  candidate's whole-crate archives create, and a real downstream consumer whose authority surface
  the prerequisite plane and this stratum's own courts measure.

It is **not** the algorithms the commands drive, and **not** the library surface they call. A
command body is a program over `libcrypto`/`libssl`, not a namespace of them, and a TLS 1.3
handshake is a flight of the state machine, not a set of exports. A subphase that discovers its unit
is somewhere else records that rather than forcing the row (§4).

## 1. The measurement this plan rests on

Every number below is read from an atlas, not typed, and `forensics/phase17-obligations.json` is
authoritative for the present.

**Phase 17 owns zero exports.** Reading `forensics/atlas/symbol-ownership.json` for `owner_phase ==
17` returns no record: the stratum's `atlas_owned` count is `0`, and the ledger fails closed if that
ever stops being true rather than silently counting a symbol through a non-export unit.

**It receives zero provider registration rows.** Reading `forensics/atlas/provider-algorithms.json`
for `owning_phase == 17` gives no row: this stratum activates no provider, and the census's provider
projection for it is empty. The legacy module Phase 16 owns is not this stratum's.

**It receives 52 unit deferrals and zero symbol deferrals.** Reading `forensics/prerequisites.json`
for `owner_phase == 17`: no `deferrals` row, and exactly 52 `units` rows, every one an `apps/<name>.c`
translation unit with `class: deferred_to_later_stratum` and one shared evidence citation to Phase
16's row 16.4a and section 3.8 (`docs/PHASE-16-SUBPHASES.md`) and the Phase-16 CLI seal. No earlier
stratum's ledger records a hand-off to Phase 17, so its working set is exactly this projection plus
the contract units.

**The downstream replacement contract is four units**, each derived from a surface that measures it:
`command-bodies` (the 52 unit deferrals above), `tls13-interop` (the `RT-TLS13-INTEROP` court,
`courts/phase17/rt_tls13_interop_probe.*`), `cross-dso-state` (the `RT-CROSS-DSO-STATE` court) and
`downstream-consumer` (the `RT-DOWNSTREAM-CONSUMER` court). At activation the runner registers all
four as `pending`, so all four units are open.

**The ledger's unit is not an exported symbol.** `forensics/phase17-obligations.json` publishes
`unit: "downstream replacement contract"`, its `implemented`/`open` export lists are empty *by
measurement*, and its working set is counted in `open_in_this_stratum` over the 52 unit deferrals and
the four contract units. `atlas_common.NON_EXPORT_UNITS` names the unit, so the two tools that
partition the export universe (`court_coverage.py`, `ownership_audit.py`) skip this ledger rather
than reconcile a symbol set that does not exist.

**Phase 17 begins on nothing of its own.** No module of this stratum has landed: the 52 command
bodies reach `src/apps/openssl.rs`'s `not_landed` boundary, and no interop, cross-DSO or
downstream-consumer court exists, so `open_in_this_stratum` opens at the whole working set and moves
only as the subphases below land. **That split moves as the stratum lands its own units: the
ledger's `counts` is the live record and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 17.0 | **The plan and the ledger** | `docs/PHASE-17-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase17-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase17_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 16 | — |
| 17.1 | **The 52 CLI command bodies** | the 52 `apps/<name>.c` command translation units (asn1parse, ca, ciphers, cmp, cms, configutl, crl, crl2pkcs7, dgst, dhparam, dsa, dsaparam, ec, ecparam, enc, engine, errstr, fipsinstall, gendsa, genpkey, genrsa, info, kdf, mac, nseq, ocsp, passwd, pkcs12, pkcs7, pkcs8, pkey, pkeyparam, pkeyutl, prime, rand, rehash, req, rsa, rsautl, s_client, s_server, s_time, sess_id, skeyutl, smime, speed, spkac, srp, storeutl, ts, verify, x509). Each command's body lands behind the `src/apps/openssl.rs` dispatcher and its `src/apps/tables.rs` option table; ordered slices land them in the groups D530 records. | 17.0 | `RT-CLI-BODIES` |
| 17.2 | **The TLS 1.3 interoperability handshake** | the real client/server flight: a `ClientHello` through `Finished` with application data exchanged, over the record layer, the extension units (`ssl/extensions_clnt.c`/`extensions_srvr.c`), the key schedule (`ssl/t1_enc.c`/`tls13_enc.c`) and the 56 message bodies D529 handed forward. The state 16.5's transitions reach is the substrate; this subphase drives the flight they select. | 17.1 | `RT-TLS13-INTEROP` |
| 17.3 | **The cross-DSO shared-state court** | the shared-state contract the candidate's link shape breaks: because the crate links `libcrypto`, `libssl` and `ossl-modules/legacy.so` as whole-crate archives, each DSO carries its own copy of the crate's internal globals, where the admitted authority shares one `libcrypto.so.3` via `DT_NEEDED`. The court raises an error through the libssl path and reads it through the libcrypto path, and does the same for `CONF`, requiring one queue. | 17.2 | `RT-CROSS-DSO-STATE` |
| 17.4 | **The downstream-consumer court** | a real downstream consumer: a program built against the candidate distribution shell the way an out-of-tree package links it, exercising the exported surface and the two entrance criteria above from outside the crate, rather than a probe compiled with the crate. | 17.3 | `RT-DOWNSTREAM-CONSUMER` |
| 17.5 | **The seal** | nothing in the crate — evidence: `docs/PHASE-17-DOWNSTREAM-SEAL.md` (at the seal) | 17.0–17.4 | — |

The rows above the seal partition the working set by source: the 52 unit deferrals are 17.1's, and
the four contract units are 17.1's through 17.4's. The partition is derived from
`forensics/phase17-obligations.json` joined to `forensics/prerequisites.json` and
`artifacts/phase17/COURTS.json`, not typed.

## 3. What each subphase must honour

**3.1 A unit deferral is a promise, and plan reconciliation is the arbiter.** `phase_state.py` and
`plan_reconciliation.py` read each `units` row's own `owner_phase`; a unit whose owner stratum seals
without reaching it is stale, so Phase 17 may not seal with a command body unlanded. The 52 rows are
this stratum's because Phase 16 did not own them, so no subphase may leave a body unlanded behind a
green court.

**3.2 The interop handshake is a real flight, not a symbol count.** 17.2 drives the client and the
server through `ClientHello` to `Finished` and then exchanges application data. A handshake that
stops at the extension or key-schedule boundary is named `pending` rather than counted as passing;
what is compared is the authority's and the candidate's own transcripts, not an inventory of names
(D529).

**3.3 The cross-DSO court records the duplication rather than asserting it away.** The candidate's
whole-crate archive link shape is a *recorded divergence* from the authority's one shared
`libcrypto.so.3`, and the court measures it: an error raised through the libssl path is read through
the libcrypto path (and the same for `CONF`), and the result is a receipt. A court that cannot make
the two DSOs agree records the divergence rather than failing on the architecture.

**3.4 The downstream consumer is a program outside the crate.** 17.4 builds a consumer against the
candidate distribution shell as a downstream package would, rather than linking the crate directly,
because the compatibility frontier is the shipped DSOs' surface and not the crate's internal
modules. It is the stratum's answer to "does a real consumer work?", not a parity claim about any
one symbol.

**3.5 Nothing here is a parity claim about the library.** A landed command body says a command exists
over the libraries, not that its output is the authority's; a passing handshake says the two flights
agree, not that every arm of the state machine matches. A name that cannot be driven is named
`pending` rather than counted as passing.

**3.6 The 52 bodies land in ordered slices behind the dispatcher.** 17.1 lands each body behind
`src/apps/openssl.rs`'s `do_cmd` lookup and the generated `src/apps/tables.rs` `OPTIONS[]` table
Phase 16.4 already landed, so the dispatcher's `not_landed` boundary shrinks slice by slice. The
`openssl` executable the Phase-2 link machinery emits already forwards to the crate; this stratum
gives its commands bodies.

## 4. Measured corrections, and the precondition

**4.1 The working set is not an export projection, and the ledger says so by its unit.** The atlas
gives this stratum zero exports, so `forensics/phase17-obligations.json` cannot be the export
projection Phases 3 through 15 publish. Its unit is `downstream replacement contract`, recorded in
`atlas_common.NON_EXPORT_UNITS` so that the export-partitioning tools skip it, exactly as Phase 16's
`cli-config contract` and Phase 22's `compatibility plane` are (D485). The ledger fails closed if the
ownership atlas ever assigns this stratum an export, because then the non-export unit would be wrong.

**4.2 The precondition this plan places on 17.0, and it is not optional.** `run_courts.py` refuses a
stratum that is not `not-started` and has no runner, so this stratum lands
`forensics/tools/phase17_courts.py` with **no runnable court**: its obligations are not exports, so no
differential probe over a symbol set is its evidence, and its four behavioural courts
(`RT-CLI-BODIES`, `RT-TLS13-INTEROP`, `RT-CROSS-DSO-STATE`, `RT-DOWNSTREAM-CONSUMER`) are named in
`PENDING_COURTS` and land with the subphases that build the things they drive. **The direction of the
`phase17_courts.py` <-> `phase17_obligations.py` edge is the reverse of Phase 16's**: the ledger's
contract-unit states are measured from the courts registry, so the registry is generated first and
`phase17_courts.py` does **not** bind the ledger as an input. A cycle in which each embedded the
other's digest would make neither reproducible. **No court is registered in `gen_frf_courts.py`**:
that registry is the stratum's seal. So the activation order is: the runner and its pending registry,
the ledger, and the plan land **together**, or `run_courts.py` fails and the tree carries an
activation whose runner is refused.

**4.3 "Downstream replacement court" here is the compatibility frontier, not the whole of Phase 22's
whole-program atlas.** Phase 22 measures the authority's whole program; Phase 17 *exercises* the
candidate's as a consumer would. The two are different strata and different planes, and this plan
reconciles them by naming which surface each contract unit is measured against rather than by
widening the ownership table.

## 5. Process

This stratum inherits Phases 8 through 16's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every name a subphase lands carries a court edge
where it has one; and an artefact that a source change moves is regenerated in the same commit.
`docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the prerequisite plane's, and it will correct them.** The subphase
table above was written from the 52 `units` rows in `forensics/prerequisites.json` and the
four-row measurement in §1. A subphase that discovers its unit is elsewhere records that rather than
forcing the row. D530 is the record that fixed the 52 units and the two entrance criteria.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the 52 CLI command unit deferrals and the
four downstream replacement contract units, recorded in the ledger's own blocks rather than as open
exports.
