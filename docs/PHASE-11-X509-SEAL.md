# Phase 11 — X.509 + verification: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. `forensics/phase-state.json:502` reads `complete` for phase 11,
`docs/SEAL-CENSUS.md:365` reads `complete` and `docs/SEAL-CENSUS.md:39` carries the same stratum's
row, `forensics/phase11-obligations.json:9` reads `open_in_this_stratum: 0`, and every earlier
stratum is `complete`, which the rule `forensics/phase-state.json:647` states. `seal_sha256` is
derived too: this document is named in `forensics/tools/atlas_common.py`'s `SEAL_DOCS` table, which
`forensics/tools/render_seal_census.py` and `phase_state.py` read, so the line is recomputed
whenever this document changes and is not restated here. In the tree before this document existed
both `forensics/phase-state.json:501` and `docs/SEAL-CENSUS.md:366` read `null` /
`seal: none written yet (unnamed)`, and the hash the pipeline records when it next runs is the
derived answer, not a figure this seal types. Reaching `complete` means the stratum has reached the
state a seal *records* (D421); it is **not** a parity claim, and this document is where what the
derivation does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This seal
cites that document rather than restating its arithmetic, because a number typed here is a number
that can drift from the evidence it summarises (D97), and the census's own header
(`docs/SEAL-CENSUS.md:6-9`) says so. The one table this document *does* carry — §3's court list —
is copied from `artifacts/phase11/COURTS.json`, and it says so.

**This seal records a candidate-transcription claim, and it is neither a security claim nor a
parity claim.** Its evidence shows that the candidate distribution defines the names this stratum
owns and that the behaviours its nine courts exercise match the pinned authority's over fixed
fixtures, observation for observation. It does **not** show that the crate's X.509 parsing or
verification is safe against a hostile certificate — no court here is a security or fuzz gate — and
it does **not** show that the crate is a usable OpenSSL. `docs/PARITY_MODEL.md` is the authority on
what the labels mean: `implemented` means a symbol with that name is defined, and a passing bounded
court is a differential result over the behaviours that court exercises. `PARITY_VERIFIED` is not
claimed for any symbol here, and `forensics/STATUS.md:379-385` carries the non-claims the generated
status emits. All 603 `libssl` exports remain `SCAFFOLDED` — a stub present, which cannot count as
parity (`docs/PARITY_MODEL.md:22`) — exactly as `docs/SEAL-CENSUS.md:21` and
`forensics/STATUS.md:124-129` record.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json:39`), named as the
  authority by `artifacts/phase11/COURTS.json:2` and `:5`
- Court results: `artifacts/phase11/COURTS.json` — nine courts, `all_pass` true
  (`artifacts/phase11/COURTS.json:4`), zero residuals; the totals are `docs/SEAL-CENSUS.md`'s
  (`docs/SEAL-CENSUS.md:384`) and the per-court table is §3. All nine are **differential** courts
  (`summary` `pass` 9 of `total` 9, `artifacts/phase11/COURTS.json:163-167`), with `pending_courts`
  empty (`artifacts/phase11/COURTS.json:162`). This stratum has **no correctness `CT-*` court**, and
  §3 states why.
- Obligation ledger: `forensics/phase11-obligations.json` — `open_in_this_stratum` 0
  (`forensics/phase11-obligations.json:9`), `deferred_to_later_phase` 2
  (`forensics/phase11-obligations.json:7`); the working-set rule it enforces is at
  `forensics/phase11-obligations.json:1721`
- Court coverage: `forensics/atlas/court-coverage.json` — phase 11's block at
  `forensics/atlas/court-coverage.json:24780`, its counts at `:24782-24790`; the counts are also
  `docs/SEAL-CENSUS.md` §Court coverage (`docs/SEAL-CENSUS.md:453`), and the weaker meaning of
  `directly_courted` is stated there and in §1 below (D199)
- Derived state: `forensics/phase-state.json:485-504`; it owns **no provider row**, so its
  `provider_rows` is `null` (`:500`) rather than a count
- FRF receipts and claim: **present, and the chain's objects are on disk.** `forensics/tools/
  gen_frf_courts.py`'s `COURTS` table gained a Phase-11 block for the nine differential courts, the
  declarations are under
  `forensics/frf/courts/openssl-rs-rt-x509{,-ref,-store,-verify-surface,-verify-engine,-v3,-pem,-acert,-req}`,
  `--check` reads `ok: 190 file(s) match the table (95 courts)`, and `.frf` now carries nine receipts,
  eighteen challenges, twenty-seven captures and one compiled claim
  (`bbd87a373704a6514dd403fcc040fde1c36dfa8d73b1f3f3fe2c361873101e75`; 100 receipts and 200
  challenges, from the 91 and 182 Phase 10's head change `C95` left). §8 states what that is
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s head
  change is Phase 11's `C97` (`forensics/GEMEL_TRAJECTORY.md:13`) and its `current:` is `K50` —
  `checkpoint.1eab61e42c9371acb92589b62521f04d91b40c1f98a5a91876bdf2e0c50ecec6`
  (`forensics/GEMEL_TRAJECTORY.md:205,216`). The state a reader reaches the stratum's `complete`
  through is this stratum's. §8 states what that is
- Deciding record: `docs/DECISIONS.md` — **D499** through **D508** (`docs/DECISIONS.md:34373-34704`),
  with `docs/PHASE-11-SUBPHASES.md` for the subphase plan this seal closes. §10 is where the
  corrections those entries record are summarised

## 1. What this phase owns, and how that was decided

Phase 11 is **the X.509 stratum**: the certificate, certificate-request, CRL and attribute-
certificate object graphs and the machinery that builds, parses, prints and **verifies** them —
`X509` and its `X509_STORE`/`X509_LOOKUP`/`X509_OBJECT` layers, `X509_REQ`, `X509_CRL`,
`X509_ACERT`, `X509_VERIFY_PARAM`, the `X509_POLICY_*` tree, the `X509V3_EXT_*` method engine and
its configuration reader, and the `PEM_*_X509*` container readers and writers around them
(`docs/PHASE-11-SUBPHASES.md:3-12`). It is deliberately **not** the ASN.1 substrate the objects are
built from — the `ASN1_ITEM` engine, the template macros and the DER/PEM encoder are Phase 5's — and
it is **not** the key objects a certificate names: `EVP_PKEY`, its provider keymgmt and every
`d2i_*`/`i2d_*` codec are Phases 7, 8 and 10, and the `X509_PUBKEY` surface this stratum finishes is
the *carrier*, not the key (`docs/PHASE-11-SUBPHASES.md:14-18`). Nor is it the container families
that carry certificates: `forensics/atlas/symbol-ownership.json` assigns all of `pkcs7.h`, `cms.h`,
`ocsp.h`, `ts.h` and `ct.h` to Phase 12, and `pkcs7.h`'s exports are the worked example of a plan
that must not read "certificates" as "the things containing them" (`docs/PHASE-11-SUBPHASES.md:20-23`).

**The working set is derived, not chosen.** The rule is the ledger's own, at
`forensics/phase11-obligations.json:1721`:

> the stratum's working set is the projection of `forensics/atlas/symbol-ownership.json` for phase
> 11, plus every symbol an earlier stratum's ledger records as handed to it: a symbol belongs to the
> stratum that owns the header declaring it, and a discharged hand-off belongs to the stratum that
> built it

The census's per-stratum row (`docs/SEAL-CENSUS.md:39`) reads `atlas-owned` 1455, `ledger owned`
1467, `implemented` 1465, `deferred` 2, `open` 0. The 1,455 atlas-owned exports are **five headers**
— `x509.h` 548, `x509v3.h` 511, `x509_vfy.h` 241, `x509_acert.h` 103 and `pem.h` 52
(`docs/PHASE-11-SUBPHASES.md:42-48`) — and the 12 are the hand-offs the census enumerates at
`docs/SEAL-CENSUS.md:381-382`: ten from phase 5 (the five
`PEM_X509_INFO_*` reader/writer spellings, `PEM_write[_bio]_X509_REQ_NEW`,
`ASN1_add_stable_module` and the two `ASN1_generate_*` generators) and two from phase 7
(`EVP_CIPHER_CTX_get_algor`, `EVP_PKEY_CTX_get_algor`). The ledger breaks the owned set down by
declaring header at `forensics/phase11-obligations.json:1601-1609`, and the header that moved the
dial is `x509.h`: 548 of the working set, and D175/D177's earlier reading of `PBEPARAM`'s
`x509.h.in` declaration as Phase 10's is a correction this plan *depends on* rather than re-opens
(D431 §4.2, `docs/PHASE-11-SUBPHASES.md:209-214`).

**Unlike every earlier activation except Phase 10, this stratum did not start with a whole working
set open.** 952 of its atlas-owned exports and 2 of its hand-offs — 954 of the 1,467 — were already
`implemented` before its first subphase, landed by Phase 8's 8.8 chain (`ameth_lib.c`, the
`x_algor`/`x_spki`/`t_spki` ASN.1 objects, the `pem.h` key readers) and by Phase 10's pulled-forward
X.509 subphases 10.8–10.16 (`docs/PHASE-11-SUBPHASES.md:25-32,58-69`, D442–D451). The ledger's own
note says the same and records that the split moves as the stratum lands its own units, so its
`counts` block is the live record and §1 of the plan is the activation measurement
(`forensics/phase11-obligations.json:1599`, `docs/PHASE-11-SUBPHASES.md:58-62`). This is the second
time a stratum has inherited a partly-built working set, and it is the reason 11.0's precondition is
not optional: the ledger, the plan, the runner (`forensics/tools/phase11_courts.py`) and the
reference-basis probe (`courts/phase11/rt_coverage_ref_probe.c`) had to land **together**, or
`run_courts.py` and `court_coverage.py` would each fail closed with an activation neither can join
(`docs/PHASE-11-SUBPHASES.md:223-247`).

**The 1,467 symbols are defined by 108 authority translation units, and the work is 44 of them.**
`forensics/atlas/export-defining-units.json` resolves the working set to 108 units, all but the
`crypto/asn1/`, `crypto/pem/`, `crypto/evp/` and `crypto/pkcs12/p12_mutl.c` exceptions under
`crypto/x509/`; 44 still had open symbols at activation and are the whole of §2's work — `x509_lu.c`,
`x509_vfy.c`, `x509_acert.c`, `x509_vpm.c`, `pem_all.c`, `x509_req.c`, `x509_meth.c`, `x_all.c`,
`x509_set.c`, `x_ietfatt.c`, `x_req.c`, `x509aset.c`, `v3_conf.c`, `x509_trust.c` and thirty
narrower units (`docs/PHASE-11-SUBPHASES.md:89-95`). The seven subphase rows above the seal
partition the 513 activation-open exports exactly, 121 + 111 + 76 + 82 + 26 + 54 + 43, and the
partition is derived from the defining units joined to the ledger's `open` list, not typed
(`docs/PHASE-11-SUBPHASES.md:104-122`).

**Phase 11 owns no provider registration row, and that is measured rather than omitted.**
`forensics/atlas/provider-algorithms.json`'s `projection` block names owning phases 8, 9, 10 and 13
only (`forensics/atlas/provider-algorithms.json:75-88`), the phase-11 slice of
`forensics/atlas/provider-court-coverage.json`'s `by_phase` is empty (its keys are 8, 9 and 10), and
`forensics/phase11-obligations.json:1720` carries `provider_rows_owned: 0`. Every X.509 name is an
`libcrypto` export reached through a caller, not a dispatch-table row an `OSSL_ALGORITHM` array
publishes; that is why `phase_state.py`'s provider-row rule and `provider_court_coverage.py` have
nothing to hold against this stratum (`docs/PHASE-11-SUBPHASES.md:97-102`).

**The order is forced twice over, and the second forcing is the stratum's whole story.**
**11.1 before 11.2**, because `X509_verify_cert` reads chains through `X509_STORE_CTX_get1_issuer`
and `X509_STORE_get_by_subject`, so a verification engine with no store to look up in cannot be
tested in isolation; **11.2 before 11.3**, because `X509_ACERT_verify` is a thin
`X509_verify_cert`-shaped entry over the same `X509_STORE_CTX`; and 11.4/11.5 before 11.6, because a
PEM writer serialises an object 11.4 mutates and 11.5's extension methods configure
(`docs/PHASE-11-SUBPHASES.md:150-157`). The second forcing is the **dependency knot**: the
dependency order is `22 -> 11 -> 12 -> ...` (`docs/RELEASE_GATES.md:42`), so "`X509_verify_cert`
waits for Phase 12" is a cycle rather than a schedule. D503 measured the knot — `check_revocation`
keeps its `#ifndef OPENSSL_NO_OCSP` arm, this admitted build does not define `OPENSSL_NO_OCSP`, and
`verify_chain` interleaves the `SSL_DANE` matrix — and wrote the rule down:

> **Pull the implementation dependency forward, not the public ownership.**

Ownership of the `ocsp.h` exports and the SSL layer stays where
`forensics/atlas/symbol-ownership.json` puts it (Phases 12 and 14); what this stratum pulled forward
is the **minimum internal substrate** the verifier's arms reach, landed as internal transcriptions
and recorded in `forensics/prerequisites.json` as pulled forward rather than owned. §2 and §5 state
what landed under that rule and how it is held internal (D503, D506).

**The planes, and which of them this stratum has.** D201's commitment — every *primitive-bearing*
subphase carries a differential `RT-*` court *and* a correctness `CT-*` court — is scoped to
primitive-bearing work, and X.509 owns no primitive: it has **eight behavioural differential courts
and one reference-basis court, and no `CT-*` court**. A reader who expected a correctness plane
should read `docs/PHASE-11-SUBPHASES.md:200-205` rather than infer one. The reference basis is
`RT-X509-REF`, the court D199 requires for a stratum whose exports an earlier stratum landed: it
takes the address of each inherited `implemented` export, so a symbol covered only by it is a proof
of *reference* and not that any arm of it was driven (`artifacts/phase11/COURTS.json:6`). §3 is
where the two readings are tabulated.

## 2. What has been built

**11.0, the plan and the census.** `docs/PHASE-11-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase11-obligations.json` and its generator, the runner
`forensics/tools/phase11_courts.py`, and the reference-basis probe
`courts/phase11/rt_coverage_ref_probe.c` — all in one commit, because §4.3 of the plan makes the
runner and the reference probe a precondition rather than a later slice
(`docs/PHASE-11-SUBPHASES.md:108,223-247`).

**11.1, the `X509_STORE` and the lookup layer.** `x509_lu.c` (the largest single unit), `x509_meth.c`,
`x509_trust.c`, `x509_d2.c`, `by_file.c`, `by_dir.c` and `by_store.c`: the `X509_STORE` object and
its registry, the four `X509_LOOKUP_METHOD`s and their file/`dir`/store implementations, the
`X509_OBJECT` accessors and the `X509_STORE_get_by_subject` read path, the trust table, and the
file/`dir` loaders (`docs/PHASE-11-SUBPHASES.md:109`). It landed in slices — 11.1a the object and
lookup core, 11.1b the trust/name checks, 11.1c the store object and its parameter setters
(D497/D499), 11.1d–f the two lookup constructors and the seven `x509_d2.c` drivers on a build-time
`openssldir` (D504). The ledger's `owned_by_module` block records the per-module shape
(`forensics/phase11-obligations.json:1610-1719`).

**11.2, the verification engine.** `x509_vfy.c`, `x509_vpm.c` and `pcy_tree.c`: `X509_verify_cert`,
the `X509_STORE_CTX` chain-building and check roll, the callback and error surface,
`X509_VERIFY_PARAM`/`X509_VERIFY_PARAM_table` and the policy-tree construction
(`docs/PHASE-11-SUBPHASES.md:110`, D507). The engine is the stratum's *purpose*, and D503/D505/D506
are the three entries that made it reachable: the knot measured and the rule written (D503), the two
HTTP loaders handed on so they are not the blocker (D505), and the OCSP/`SSL_DANE` substrate pulled
forward as internal transcriptions ahead of the engine (D506). The engine slice itself landed the
whole chain roll, the check cluster, the CRL cluster, the four key/sig level checks and the five
exports `X509_STORE_CTX_init`, `X509_STORE_CTX_init_rpk`, `X509_verify_cert`,
`X509_STORE_CTX_verify` and `X509_build_chain` in `src/x509/x509_vfy.rs` (D507).

**11.3, the attribute certificate.** `x509_acert.c`, `x509aset.c`, `x_ietfatt.c` and `t_acert.c`:
the `X509_ACERT`/`X509_ACERT_INFO` item group, its issuer/serial/target/holder/attribute/extension
accessors and setters, the `OSSL_IETF_ATTR_SYNTAX` items and their RFC 5755 mixed-choice refusal,
`X509_ACERT_verify` and the `x509_acert.h` print and `d2i_*`/`i2d_*` surface — the whole of the
header's open 83 (`docs/PHASE-11-SUBPHASES.md:111`, D500). Its two printers wait on
`X509_signature_print` and landed in 11.7 once that was in (D500, `docs/PHASE-11-SUBPHASES.md:347-355`).

**11.4, the request, the CRL and the object mutators.** `x509_req.c`, `x509_set.c`, `x_req.c`,
`x_crl.c`, `t_x509.c`, `t_req.c`, `t_crl.c`, `x_exten.c` and `x509_r2x.c`: `X509_REQ` and its
ASN.1/print/lifecycle surface, the `X509_set_*`/`X509_CRL_set_*`/`X509_REQ_set_*` mutators,
`X509_CRL`'s remaining arms, the extension accessors, `X509_to_X509_REQ` and `X509_REQ_to_X509`, and
the certificate/request/CRL printers whose evidence is the **printed text** rather than a round trip
(`docs/PHASE-11-SUBPHASES.md:112`, D500). `x_crl.c`'s CRL method and lookup surface was pulled
forward to unblock the engine (D495/D500, `docs/PHASE-11-SUBPHASES.md:332-335`).

**11.5, the `v3` function and configuration layer.** `v3_conf.c`, `v3_utl.c`, `v3_prn.c`, `v3_addr.c`
and `v3_asid.c`: `X509V3_EXT_nconf(_file)` and the name-resolution engine, the `X509V3_EXT_*`
helpers (`X509V3_get_section`/`X509V3_get_string`, the `s2i`/`i2s` bridges), the
`GENERAL_NAMES`/`IPAddressFamily`/`ASIdentifiers` printers, the RFC 3779 path-validation entries and
the two deferred `i2s` halves — the whole of `x509v3.h`'s open 26
(`docs/PHASE-11-SUBPHASES.md:113`). Its behavioural court `RT-X509-V3` landed last of all (D508).

**11.6, the PEM X.509 container surface.** `pem_all.c`, `pem_pk8.c`, `pem_info.c`, `pem_x509.c` and
`pem_xaux.c`: `PEM_read[_bio]_X509`, `PEM_write[_bio]_X509`, the `X509_INFO` reader and writer
family, the `X509_REQ`/`X509_CRL`/`X509_ACERT` PEM spellings and `PEM_write[_bio]_X509_REQ_NEW` —
the atlas projection's `pem.h` plus the seven hand-offs (`docs/PHASE-11-SUBPHASES.md:114`). The
contract is the **exact PEM text** (`docs/PHASE-11-SUBPHASES.md:192-198`, §3.4).

**11.7, the shared remainder and the deferred hand-offs.** `x_all.c`'s `d2i_*`/`i2d_*` dispatch for
the certificate family, `evp_lib.rs`'s two `EVP_*_CTX_get_algor` hand-offs, `p5_scrypt.rs`,
`nsseq.rs`, `x509_def.rs`, `x_info.rs`, `x_pkey.rs`, `evp_pkey.rs`, `t_spki.rs`, `p12_mutl.rs` and
`asn_mstbl.rs` — the eleven units whose closures cross into the strata above
(`docs/PHASE-11-SUBPHASES.md:115`). It closed the two follow-ups D500 left (`X509_to_X509_REQ` and
the two `X509_ACERT` printers) and landed the four free-standing default-path answers on a new
build-time constant (D504).

**The pulled-forwards, and why they are internal rather than owned.** Under D503's rule the OCSP
function substrate `check_cert_ocsp_resp` reaches landed as internal `pub(crate)` transcriptions
under `src/ocsp/` (`ocsp_lib.rs`, `ocsp_srv.rs`, `ocsp_cl.rs`, `ocsp_vfy.rs`), and the `SSL_DANE`
representation plus the DANE matrix landed under `src/x509/dane.rs`; **no function of either carries
`#[no_mangle]`**, so ownership stays with Phase 12 and this stratum's own statics, and
`forensics/atlas/implemented-surface.json` is the proof rather than the promise: libcrypto gains no
new `OCSP_*` symbol (D506, `src/ocsp/mod.rs:21`). The OCSP ASN.1 item groups under
`src/ocsp/ocsp_asn.rs` were already exports and are the exception — they keep their `#[no_mangle]`
and were landed before the functions. The related `OPENSSLDIR` gate opened the way `MODULESDIR`
already had: `build.rs` captures `OPENSSL_RS_OPENSSLDIR` (`build.rs:166-172`), and the four
`X509_get_default_*` answers return it or the empty C string when unset, so `by_file_ctrl_ex` fails
to open a default bundle instead of opening the authority's forensic path. Two existence-only
`lstat`/`stat` shims were added beside `openssl_rs_stat_is_dir` (`src/runtime/dir_posix.c:77-103`) so
`get_cert_by_subject_ex`'s candidate-path test is constructible without assuming a field offset
(D504).

**The books that moved with the code.** The implemented surface ended where the census states it:
`docs/SEAL-CENSUS.md:20-22` is the `libcrypto`/`libssl`/total table, and the live internal
`c_style` count is 487, which `docs/CI.md:108` records and `docs_consistency.py` checks against
`forensics/atlas/implemented-surface.json`. Phase 11's own ledger reads `implemented` 1465 of
`owned` 1467 with `deferred` 2 and `open` 0 (`forensics/phase11-obligations.json:5-12`,
`docs/SEAL-CENSUS.md:368-372`), and it discharged the 12 hand-offs rather than passing them on
(`docs/SEAL-CENSUS.md:379-382`). The two deferrals are recorded with their callee and owning
stratum, not merely named: both are one-line delegations to `simple_get_asn1`, whose only external
call is `OSSL_HTTP_get`, and pulling the whole HTTP client forward for two convenience wrappers is
the opposite of D503's trade (D505, `forensics/phase11-obligations.json:13-26`).

## 3. The evidence

Copied from `artifacts/phase11/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. All nine courts are differential; the stratum registers no
correctness `CT-*` court, so no row here carries a `vectors_checked` count.

| court | plane | observations | probe |
|---|---|---|---|
| `RT-X509-REF` | differential (reference basis) | 1007 | `courts/phase11/rt_coverage_ref_probe.c` |
| `RT-X509-STORE` | differential | 525 | `courts/phase11/rt_x509_store_probe.c` |
| `RT-X509-VERIFY-SURFACE` | differential | 197 | `courts/phase11/rt_x509_verify_probe.c` |
| `RT-X509-VERIFY-ENGINE` | differential | 242 | `courts/phase11/rt_x509_verify_engine_probe.c` |
| `RT-X509-V3` | differential | 240 | `courts/phase11/rt_x509_v3_probe.c` |
| `RT-X509-PEM` | differential | 121 | `courts/phase11/rt_x509_pem_probe.c` |
| `RT-X509-ACERT` | differential | 178 | `courts/phase11/rt_x509_acert_probe.c` |
| `RT-X509-REQ` | differential | 76 | `courts/phase11/rt_x509_req_probe.c` |
| `RT-X509` | differential | 52 | `courts/phase11/rt_x509_misc_probe.c` |

Every differential row carries `residual_count: 0` and `verdict: "pass"`
(`artifacts/phase11/COURTS.json:7-161`), and the summary reads `pass` 9 of `total` 9 with
`pending_courts` empty (`artifacts/phase11/COURTS.json:162-167`). The totals over the nine
transcript courts are `docs/SEAL-CENSUS.md`'s (`docs/SEAL-CENSUS.md:384`), and the per-court rows
there (`docs/SEAL-CENSUS.md:386-396`) are the same computation.

**`RT-X509-REF` is not a behavioural court, and its meaning is the weaker one.** Its probe takes the
address of each of the stratum's inherited `implemented` exports and prints whether each is
non-NULL, so a symbol covered only by it means the candidate distribution defines the name — which
the link proves — and **not** that any arm of it was driven (`artifacts/phase11/COURTS.json:6`,
`courts/phase11/rt_coverage_ref_probe.c:5-13`). The court coverage atlas records those at basis
`referenced`, never `called` (`docs/SEAL-CENSUS.md:453`, D199). Its 1,007 names are the 954 the
earlier strata landed, the 39 that 11.1a/11.4a landed but `RT-X509-STORE` cannot reach, and the
fourteen the later slices added because they diverge by construction or need a context the engine
builds (`courts/phase11/rt_coverage_ref_probe.c:15-57`). Eight courts are behavioural:
`RT-X509-STORE` drives the store/lookup/object, mutator, trust, printer, extension-build and
name-check surface; `RT-X509-VERIFY-SURFACE` drives the `X509_VERIFY_PARAM` surface, the
`X509_STORE_CTX` lifecycle and accessors, the free-standing time decisions, the CRL method cluster,
the RFC 3779 path-validation entries and the policy tree; `RT-X509-VERIFY-ENGINE` drives the five
engine exports over a fixed Ed25519 chain; `RT-X509-V3` drives the `v3_addr.c`/`v3_asid.c` builders,
item doors and printers; `RT-X509-PEM` compares exact PEM text and malformed-input coordinates;
`RT-X509-ACERT` drives the attribute-certificate item groups and doors; `RT-X509-REQ` drives the
request and printer surface; and `RT-X509` drives the shared remainder
(`courts/phase11/*_probe.c`, `docs/PHASE-11-SUBPHASES.md:168-198`).

**Why there is no correctness plane, stated rather than left to inference.** D201's commitment is
scoped to primitive-bearing subphases, and this stratum emits no primitive: `docs/PHASE-11-SUBPHASES.md`
§3.5 asks that a name which cannot be driven be named `pending` rather than counted as passing, and
every such name is (`pending.v3_conf.bcons_ca_false`, §5). A `CT-*` court is a vector-driven
construction check with no authority transcript to diff (D13, D201), and none is registered here
because none of §2's work is a primitive whose correctness a vector would establish. The stratum's
evidence is therefore **differential only**, which is a measurement and not an omission.

**The court coverage join is clean, and its meaning is the weaker one.**
`docs/SEAL-CENSUS.md:453` reads phase 11 as 1465 implemented, 1465 `directly_courted` (937 of them
`called` and 528 `referenced`), 0 indirect, 0 non-observable, 0 unmatched; the block is
`forensics/atlas/court-coverage.json:24780` and its counts are at `:24782-24790`. `directly_courted`
means *referenced by a staged candidate probe that ran and produced a transcript*
(`docs/SEAL-CENSUS.md:438-441`), a proof of **reference** rather than that every arm of the symbol
was driven — the same reading Phase 8's, Phase 9's and Phase 10's seals adopt. The provider-row join
is empty by construction: this stratum owns no provider row, so `provider_court_coverage.py` has
nothing to match (`docs/PHASE-11-SUBPHASES.md:97-102`, §4.2).

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
evidence found real defects, in the candidate and in the instrument.

**The printers' text comparison caught a transcription bug.** `X509_print_ex` printed the version as
`l` where the authority prints `l + 1`. That is §3.1's contract working in the direction it was
built for: the printers' evidence is the **printed text** — exact length plus a digest of the
captured bytes — not a round trip, and a round trip would have passed (D500,
`docs/PHASE-11-SUBPHASES.md:172-174`).

**The type plane caught a signature defect on a line a human had already read.**
`PKCS5_pbe2_set_scrypt`'s `aiv` was declared `*const c_uchar` where the authority takes
`unsigned char *aiv` and reads the IV out of it. `ABI-PROTOTYPE` reported `TYPE-MISMATCH
PKCS5_pbe2_set_scrypt`, the parameter is now `*mut c_uchar`, and the court confirms it. The defect
was found *after* a reviewer had read the declaration and believed it, which is the argument for the
type plane (D502).

**A `pass` that could be read as a claim it did not make became an instrument defect.**
`RT-X509-VERIFY` passed while `X509_verify_cert` was still withheld, and the only thing saying so was
prose in the probe header. The project separates `referenced` from `called` and `IMPLEMENTED` from
`PARITY_VERIFIED` precisely so a claim cannot be read out of a weaker one, so the court was renamed
**`RT-X509-VERIFY-SURFACE`** and **`RT-X509-VERIFY-ENGINE`** was registered as a pending court whose
description names what it will establish; the rename was checked against the fail-closed regression
guard first, because the guard treats a baseline court that disappears as a lost result (D502). The
engine court is now registered and `PENDING_COURTS` is empty (D507, D508).

**The pipeline's clippy gate caught what the build did not.** 11.1c's own `cargo build` was clean,
but two `clippy::undocumented_unsafe_blocks` errors in the `BIO_read_filename` expansions survived
it and were caught by the gate; the SAFETY comment now sits on the `unsafe` block rather than on the
`if` that encloses it. A build is not a lint (D499).

**Driving the last surface turned `referenced` into `called`, and it was an evidence move rather
than a code move.** `RT-X509-V3` landed after the stratum derived complete, because the 11.5 surface
*looked* covered — `RT-X509-STORE` calls the `v3_conf.c` builders, the four `v3_prn.c` printers and
the `v3_utl.c` name checks — but measured against `forensics/atlas/court-coverage.json`,
`v3_addr.c`'s and `v3_asid.c`'s own arithmetic and item doors were basis `referenced` and never
driven. Fifty-seven exports moved `referenced` -> `called` by exactly the court's import, and the
candidate matched the authority on every arm, so no `v3_*.rs` change was needed: the finding is the
weaker claim made visible, which is what D502 exists to keep visible (D508). The earlier slices'
courts found their own real behaviour too: the `pbe`/name/print/`v3` arms of `RT-X509-STORE`, the
trust-table and store-setter read-backs, and the `X509_print_ex` version bug above.

**The engine court's first run was correct, and that is recorded rather than smoothed.** No residual
was an engine bug; the transcription matched the authority's decision, error code, error depth,
ordered `verify_cb` sequence and constructed chain on the first run over the Ed25519 chain
(D507). A first-run green is a statement about the fixtures the court can build, not about every
chain, and §6 says so.

**The dependency knot was measured rather than argued, and the measurement changed the plan.** D503
names `check_revocation`'s OCSP arm and `verify_chain`'s `SSL_DANE` matrix, records the measured
OCSP closure (eleven functions plus four item types and their doors), and writes the pull-forward
rule down so no later slice re-derives it; D506 then landed that substrate as internal
transcriptions, and the prerequisite census moved (`x509_vfy.c` 115 -> 94 not-modelled) as the
transcriptions replaced names (D503, D506).

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an uninitialised field, or **aborts**, the court
does not call it and the divergence is recorded with the phase or condition that would make the
behaviour reachable, so the record retires rather than being re-read out of this document. **No
divergence obligation names Phase 11 as its `current_owner`.** `forensics/divergence-obligations.json`
reads 10 rows and **0 blocking** (`forensics/divergence-obligations.json:3-11`), and its rows'
`current_owner` values are 8, 9, 10 and 13; `phase_state.py` refuses to derive any state while an
obligation whose owner is the stratum has `trigger_satisfied` true and `disposition` `open`, so no
live obligation outran this stratum's derived `complete`. The boundaries this stratum actually met
are recorded in the places below.

- **A NULL dereference the probe cannot compare, named in the probe.**
  `X509_TRUST_set_default(NULL)` followed by an unclaimed id is not driven: the authority
  dereferences the NULL slot and the candidate answers 0, which is a fault boundary a probe cannot
  compare. It is named in `courts/phase11/rt_x509_store_probe.c:61-63` rather than called.
- **A divergence in an earlier unit, met by a new caller.** `basicConstraints=CA:FALSE` is withheld:
  the authority's `BASIC_CONSTRAINTS` template is `ASN1_OPT(..., ASN1_FBOOLEAN)` and omits a FALSE
  `ca`, while this crate's `v3_bcons.rs` template names `ASN1_BOOLEAN_it` and encodes it. The
  divergence is in `v3_bcons.rs` and the item encoder — Phase 10's unit, not this one — and the
  probe **names it** with `pending.v3_conf.bcons_ca_false=`
  (`courts/phase11/rt_x509_store_probe.c:1031-1035,1060-1061`) rather than hiding it or counting it
  as passing (`docs/PHASE-11-SUBPHASES.md:204-205`).
- **A bare `EVP_MD_CTX_new()` is a genuine fault boundary in the attribute certificate's sign
  doors**, which dereference a NULL `EVP_PKEY_CTX`; the probe attaches a fresh `EVP_PKEY_CTX` so it
  reaches the doors' own NULL-key refusal instead, identically on both sides
  (`courts/phase11/rt_x509_acert_probe.c:190-204`).
- **The `OPENSSLDIR` default-path answers diverge by construction.** `X509_get_default_cert_area`,
  `_cert_dir`, `_cert_file` and `_private_dir` answer a compile-time path built from the admitted
  build's forensic `OPENSSLDIR`, while the candidate answers its own `OPENSSL_RS_OPENSSLDIR` (empty
  when unset), and the two lookup constructors and the seven `x509_d2.c` drivers cascade into them.
  No observation of them can be equal, so they are covered at basis `referenced`, never `called`
  (D504, `courts/phase11/rt_coverage_ref_probe.c:44-57`). This is the same record
  `docs/SECURITY_DIVERGENCE_POLICY.md:381-397` makes for `CONF_get1_default_config_file` and the
  same constant `OpenSSL_version(OPENSSL_DIR)` already answers `N/A` for; the directory plane
  proper is still Phase 16's.
- **The legacy digest-by-name divergence reaches two names and routes the engine court's fixture
  choice.** `X509_get_signature_info` runs `X509_check_purpose` and then reads the cached `siginf`,
  whose digest-name lookup is the crate's recorded, deferred Phase-13 `EVP_get_digestbyname`
  divergence (D333/D343); driving it would compare that divergence rather than this unit's contract,
  so it is left to the reference basis and named (`courts/phase11/rt_x509_store_probe.c:55-59`). For
  the same reason the verification engine's fixtures are **Ed25519**: an RSA chain would route
  `X509_verify` through the same divergence, so the engine court's decision, error and chain
  observations are the engine's own rather than a recorded Phase-13 divergence's
  (`courts/phase11/rt_x509_verify_engine_probe.c:15-20`).
- **Two `x509.h` exports are handed on rather than reproduced.** `X509_load_http` and
  `X509_CRL_load_http` are one-line delegations to the static `simple_get_asn1`, whose only external
  call is `OSSL_HTTP_get`; the HTTP client, the BIO connect machinery and punycode are the units
  this crate deliberately withholds (D455), so the two names are deferred to Phase 12 with the
  callee, its authority file and line, and the owning stratum named (D505).

**The pull-forwards are the mechanism that kept these boundaries from becoming the stratum's.** D503's
rule landed the OCSP function substrate and the `SSL_DANE` matrix as **internal transcriptions**
without `#[no_mangle]`, and D506's `nm` check over the archive found no new `OCSP_*` symbol, so
ownership of the exports stays with Phase 12 and the SSL layer while the engine that needs them
closes. The two modules carried the `#![allow(dead_code)]` staging marker with a named retiring
commit, and D507 retired every one of them; the three small thunks that reinterpret the crate's
`*mut c_void` callback slots install the same single pointer the authority does (D506, D507). The
`OPENSSL_RS_OPENSSLDIR` constant and the `lstat`/`stat` shims are internal for the same reason
(D504).

**The register's machine form is what makes the boundaries checkable rather than narrated.**
`forensics/tools/divergence_obligations.py` renders `forensics/divergence-obligations.json` from a
table, and the count it reads — 10 rows, 0 blocking — is why no live obligation outran this
stratum's `complete`. The boundaries above are recorded in the probes, in D504/D505/D506, and in
`docs/SECURITY_DIVERGENCE_POLICY.md` where a register row exists; none is a Phase-11-owned
divergence, and none is smoothed.

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with that
   name is defined. `docs/PARITY_MODEL.md` states what each label means; no symbol here is
   `PARITY_VERIFIED`, and `forensics/STATUS.md:379-385` carries the current non-claims. The
   `PARITY_MODEL.md` labels this stratum's evidence reaches are at most `IMPLEMENTED`, plus a
   bounded `SEMANTIC_PASS` over the behaviours its courts exercise — never `PARITY_VERIFIED`.
2. **This is a candidate-transcription claim, and it is not a security claim.** The evidence shows
   the names are defined and the courts' fixtures match; it does **not** show the crate parses or
   verifies certificates safely, and no court here is a fuzz or security gate. `docs/SECURITY_DIVERGENCE_POLICY.md`
   records the boundaries; a boundary not exercised is recorded, not a safety guarantee.
3. **`libssl` is entirely scaffolded.** All 603 `libssl` exports remain `SCAFFOLDED` — a stub
   present, which cannot count as parity (`docs/PARITY_MODEL.md:22`, `docs/SEAL-CENSUS.md:21`,
   `forensics/STATUS.md:124-129`) — this stratum owns no `libssl` export and touches no TLS code.
4. **The `OPENSSLDIR` default-path answers diverge by construction, and this is deliberate.** The
   candidate answers its own build-time `OPENSSL_RS_OPENSSLDIR` (empty when unset) where the
   authority answers the forensic build's path, so the four `X509_get_default_*` names and the nine
   names that cascade into them are covered at basis `referenced`, never `called`, and no court
   compares the string (D504, §5).
5. **The engine court's chain is Ed25519 on purpose, and that is a bound on the claim.** An RSA or
   ECDSA chain would route `X509_verify` through the crate's recorded, deferred Phase-13
   `EVP_get_digestbyname` divergence (D333/D343), so the engine court's 242 observations are its
   own over an Ed25519 chain and not a claim about the classical verify path (D507, §5).
6. **Two `X509_load_http` exports are deferred to Phase 12, not claimed.** `X509_load_http` and
   `X509_CRL_load_http` are named and handed on with their blocker, and the stratum's `owned` 1,467
   resolves to `implemented` 1,465 plus `deferred` 2 plus `open` 0 — the arithmetic is the ledger's
   and the census's (D505, `forensics/phase11-obligations.json:5-12`).
7. **The pulled-forward substrate is internal, and it is not this stratum's exported surface.** The
   OCSP functions under `src/ocsp/` and the `SSL_DANE` matrix under `src/x509/dane.rs` carry no
   `#[no_mangle]`; ownership of `ocsp.h` and the SSL exports stays with Phases 12 and 14, and this
   seal claims nothing about their eventual public behaviour (D503, D506).
8. **A passing court is a differential result over the behaviours its probe exercises, and
   implemented-and-courted is not "is a drop-in replacement".** A symbol recorded `directly_courted`
   is *referenced by a staged candidate probe that ran* — 937 of the stratum's are `called` and 528
   are `referenced` (`docs/SEAL-CENSUS.md:453`) — and `RT-X509-REF` in particular proves only that
   the candidate distribution defines the inherited names. Nothing here claims stderr equivalence,
   full CLI compatibility, build-profile independence beyond the admitted one, or drop-in
   substitution.
9. **The verification claim is bounded by the chains a court can construct.** `X509_verify_cert` is
   a decision procedure, and the engine court compares the decision, the error code, the depth, the
   ordered `verify_cb` sequence and the constructed chain over one three-level Ed25519 chain plus an
   expired and a wrong-name sibling; it does not establish that every chain the authority refuses,
   the candidate refuses identically (`docs/PHASE-11-SUBPHASES.md:176-183`, :200-205).
10. **Nothing here is a parity claim `docs/PARITY_MODEL.md` does not already scope, and every ledger
    and coverage count is `docs/SEAL-CENSUS.md`'s.** This document types none of those itself; the
    exceptions are §3's per-court table and the head matter's court and coverage figures, each of
    which names the artefact it was read from.
11. **The FRF and Gemel evidence is a bounded `sensitivity-backed` claim over nine courts, and it
    is not a parity claim.** The nine differential courts' compiled claim (`bbd87a37…`, §8) binds
    the authority's first stdout line and its exit class for the nine courts' fixture families only,
    with `blockers: []` and `excluded_evidence: []`; this stratum registers no `CT-*` court, and a
    `referenced`-basis name in `RT-X509-REF` remains a proof of reference only, not a driven arm.
    The claim's own non-claims are emitted beside it, and `forensics/frf/README.md` says what the
    `sensitivity-backed` policy means (§7, §8).

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process (`docs/PHASE-11-SUBPHASES.md:258-264`) — a subphase lands its code, its court and
its regenerated artefacts in **one commit**; every export carries a court edge on the commit that
lands it (D236); this stratum publishes no provider row (D245 has nothing to hold against it) — and
its §4.3 precondition (the reference-basis probe and the runner land **with** the ledger). Every
clause below is checked against a generated artefact rather than asserted.

| criterion | evidence |
|---|---|
| every export is implemented or handed on with the dependency named | `forensics/phase11-obligations.json`: `open_in_this_stratum` 0 (`:9`) and `deferred_to_later_phase` 2 (`:7`); the generator `forensics/tools/phase11_obligations.py` fails closed, so `implemented + deferred + open == owned` |
| every implemented export is observed by a court | `forensics/atlas/court-coverage.json` phase-11 block (`:24780`); `unmatched` 0 (`:24789`), enforced for `complete` by `forensics/tools/phase_state.py` |
| the reference basis covers the inherited exports | `RT-X509-REF` (`courts/phase11/rt_coverage_ref_probe.c`), registered at 11.0 with the ledger and runner (`docs/PHASE-11-SUBPHASES.md:108,223-247`); D199/D236 |
| no authority fault is reproduced | §5, and the boundaries recorded in the probes, D504–D506 and `docs/SECURITY_DIVERGENCE_POLICY.md` |
| no divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking (`:3-11`); `current_owner` values are 8, 9, 10 and 13 |
| `ABI-PROTOTYPE`, `ABI-SYMBOL` and `ABI-DYNAMIC` stay clean | `forensics/atlas/ownership-audit.json`: `problems` empty (`:1245`), `implemented_by_two_strata` empty (`:1008`) |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 (`:11`) |
| the dispatch court clean | `forensics/atlas/dispatch-court.json`: `problems` 0 (`:18`) |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` empty (`:629`); D507's ten `forensics/prerequisites.json` unit records are what keep it there |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` empty (`:32`) |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json:647` |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |

**`docs/RELEASE_GATES.md` §2's ten items, each checked rather than assumed.** The first column is
the authority's own list (`docs/RELEASE_GATES.md:54-64`); the second says what this stratum's
evidence for it is, and, where an item is **not met**, says so plainly rather than leaving the row
empty.

| # | item | this stratum's evidence |
|---|---|---|
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json:39` pins `openssl-3.6.4-production`; `artifacts/phase11/COURTS.json:2` names it |
| 2 | obligation inventory | `forensics/phase11-obligations.json` (`:5-12`); this stratum owns no provider row |
| 3 | court manifests | `artifacts/phase11/COURTS.json` |
| 4 | raw captures | **met in both venues.** The nine staged `artifacts/phase11/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (`artifacts/phase11/COURTS.json:19-22` and each row's `staged_binaries`), and `.frf/captures/` carries twenty-seven Phase-11 runs — the real run and the two challenged runs of each differential court (§8) |
| 5 | residual set | **met in the court venue.** Every court's `residual_count` is 0 and its `residuals` list empty (`artifacts/phase11/COURTS.json:7-161`), `summary` reads `pass` 9 of 9 and `pending_courts` is empty (`:162-167`) |
| 6 | mutation / sensitivity evidence | **met.** Eighteen challenge records — both declared axes on each of the nine differential courts — every one adjudicated, and the claim is `sensitivity-backed` (§8); `forensics/frf/README.md:160` counts 95 runtime courts, the Phase-11 nine among them |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-11 FRF residual exists to carry one |
| 8 | FRF receipts | **met.** Nine `.frf/receipts/` records — one per differential court — each with an empty `residuals` list (`receipt-run-openssl-rs-rt-x509…`; §8) |
| 9 | generated parity projection | `forensics/STATUS.md` (`:146-160`), rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s head change is Phase 11's `C97` (`:13`) and its `current:` is `K50` — `checkpoint.1eab61e4…` (`:205,216`), the state `C97` leaves; one checkpoint, because this stratum's chain carries no finding, fix or disposition (§8) |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10, with item 4 met in both venues
— and item 7 is not applicable rather than wanting: `--resolution-run` is required only for a
`fixed` disposition, and none attaches to a Phase-11 FRF residual, because the eighteen residual
records the challenges produced are all `open` by design.** The stratum entered the FRF chain and
produced the declarations, captures, receipts, challenges, claim and checkpoint §8 describes, with
`blockers: []` and `excluded_evidence: []`. Item 10's checkpoint, `K50`, is the state this stratum's
head change leaves, and it has landed (§8).

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and every object it produces is on disk.**
`forensics/tools/gen_frf_courts.py`'s `COURTS` table is the registry of declarations (D58), and it
gained a Phase 11 block — `("rt-x509-ref", 11, …)` through `("rt-x509", 11, …)`. Phase 9's chain
entry shows what one requires, and D424 fixes it: rows for every **differential** court, each naming
the `artifacts/phase11/probes/<probe>.{authority,candidate}` pair the court stages and the
`courts/phase11/<probe>.c` it was compiled from, then the store **added to** rather than recreated,
producing one receipt and two challenge records per court, a compiled `sensitivity-backed` claim, and
a Gemel checkpoint. This stratum registers **nine differential courts and no `CT-*` court**, so the
D413 reason that excludes a vector-driven court from a manifest (`CT-PKCS12` was Phase 10's one
exclusion) has nothing to exclude here: all nine of `RT-X509-REF`, `RT-X509-STORE`,
`RT-X509-VERIFY-SURFACE`, `RT-X509-VERIFY-ENGINE`, `RT-X509-V3`, `RT-X509-PEM`, `RT-X509-ACERT`,
`RT-X509-REQ` and `RT-X509` are declared, run, receipted, challenged and compiled. **`RT-X509-REF`
is declared, unlike the earlier strata's `-REF` courts**, because its probe is fixture-driven and
diffs a real authority transcript rather than taking addresses, so it is a chain subject with a
capture to compare and not a reference basis with nothing to diff (D199).

- **Nine declarations.** `forensics/tools/gen_frf_courts.py`'s table gained the Phase-11 block, and
  the generated declarations are under
  `forensics/frf/courts/openssl-rs-rt-x509{,-ref,-store,-verify-surface,-verify-engine,-v3,-pem,-acert,-req}`.
  `gen_frf_courts.py --check` reads `ok: 190 file(s) match the table (95 courts)`, and
  `forensics/frf/README.md:160` counts **95 runtime courts** — the Phase-11 nine among them, which
  moves the manifest count the `docs/RELEASE_GATES.md` alternative names with it (D200/D413/D424).
- **Nine receipts, eighteen challenges, twenty-seven captures.** One receipt per court, each with an
  empty `residuals` list; both declared axes challenged and adjudicated on each court; and three runs
  captured per court — the real run and the two challenged runs. They are in `.frf/receipts/`,
  `.frf/challenges/` and `.frf/captures/` under the `openssl-rs-rt-x509…` names.
- **One `sensitivity-backed` claim.**
  `bbd87a373704a6514dd403fcc040fde1c36dfa8d73b1f3f3fe2c361873101e75` binds authority
  `openssl-rt-3.6.4-r2` to candidate `openssl-rs 0.0.21` (`identity_hash e4f60d8b…`) in environment
  `x86_64-linux (77b5d08d)` over the nine differential courts, with `blockers: []` and
  `excluded_evidence: []` (`.frf/claims/bbd87a37….json`). Every one of its nine premises carries both
  axes — `observable_scope [stdout, exit]`, relation `eq(stdout-first-line), eq(exit-code)` — so no
  cell is narrowed, and its eighteen `capability` entries are the two challenged axes per court.
  **The identity moved with the 0.0.21 release.** The store was recreated from clean at candidate
  0.0.21 — FRF run identities are content-addressed on the declaration, which carries the candidate
  version, so every claim identity moves with a release — and the id quoted here supersedes the
  previous generation's `fd6683bc…`, the 0.0.19 claim.
- **One Gemel checkpoint, `K50`.** `forensics/GEMEL_TRAJECTORY.md`'s head change is `C97` — "Phase 11
  joins the FRF chain: the X.509 stratum adds nine differential declarations"
  (`forensics/GEMEL_TRAJECTORY.md:13`) — and its `current:` is the state that change's checkpoint
  leaves, `checkpoint.1eab61e42c9371acb92589b62521f04d91b40c1f98a5a91876bdf2e0c50ecec6`, listed as
  `K50` (`forensics/GEMEL_TRAJECTORY.md:205,216`). **One checkpoint rather than the three Phase 8
  needed**, because this stratum's chain contains no finding, fix or disposition for the trajectory
  to carry in order: the nine courts' real runs raise no residual on a claimed surface, the claim
  compiles with zero blockers and no narrowed cell on the first pass, and the only residuals the
  chain produces are the eighteen mutant residuals of the challenge records, which are open by design
  because a mutant's divergence is the challenge's evidence. **The store was added to, not
  recreated**: `.frf` moved receipts 91 → 100, challenges 182 → 200, captures 273 → 300 and claims
  10 → 11, the figures Phase 10's head change `C95` left.

**What the seal does *not* do is invent any of these objects.** The declarations, the receipts, the
challenges, the captures, the claim and the checkpoint are produced by running the chain in the FRF
tooling container, never on the host, and all six are cited above from disk —
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
Items 6, 8 and 10 of §7 retire with this entry, exactly as they did for Phase 10's `C95`.

## 9. What happens next

**Nothing is handed from this stratum to a later one except the two names it deliberately did not
build.** `forensics/phase11-obligations.json`'s `deferred` list is the two HTTP loaders
(`:13-26`) and its `deferred_by_phase` reads `{12: 2}` (`:27-29`); the census reads `deferred to a
later stratum with a stated reason: 2` (`docs/SEAL-CENSUS.md:371`). Every other export this stratum
owns is implemented, and the 12 it *received* are discharged rather than passed on
(`docs/SEAL-CENSUS.md:379-382`).

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF chain entry has landed.** §8's subject: nine declarations, the nine receipts, eighteen
  challenges and twenty-seven captures they produced, the compiled `sensitivity-backed` claim
  `bbd87a37…`, and the `K50` checkpoint the chain leaves. This stratum registers no `CT-*` court, so
  the entry covers all nine differential courts and nothing is recorded as not declarable. No object
  of the entry is still owed.
- **This seal's §7 and §8 are corrected, and its bytes moved with the correction.** The receipts,
  claim id and checkpoint id were produced by running the chain in the FRF tooling container, never
  on the host, and `seal_sha256` is recomputed from the document's new bytes. Phase 10's seal was
  corrected the same way.
- **`ossl_x509_check_cert_time` is now landed, and Phase 10's §9 follow-up is satisfied.** Phase 10
  recorded it as a divergence with its blocker until Phase 11 modelled `X509_VERIFY_PARAM`,
  `X509_STORE_CTX` and `X509_cmp_time` (`docs/PHASE-10-KEYFORMATS-SEAL.md:509-511,674-676`); the
  engine transcribed it internally in `src/x509/x509_vfy.rs` (D507), and the prerequisite record
  that named it is retired.
- **Phase 12 begins on a landed internal core.** The OCSP function substrate and the `SSL_DANE`
  matrix are in the crate at `pub(crate)` with no `#[no_mangle]`, so Phase 12 implements its own
  exported `ocsp.h` surface around them and the SSL layer implements the DANE exports around
  `src/x509/dane.rs`; this stratum owns neither (D503, D506).
- **`forensics/phase11-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and coverage figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections the phase-11 decision record **D499–D508** made to earlier
statements, the corrections this seal makes to the plan's own account, and the corrections the
evidence forced rather than the ones a reviewer might have preferred.

1. **D507's reconciliation rewrote ten `forensics/prerequisites.json` unit records, and the seal
   states what changed rather than the count alone.** Nine `units` records that had deferred the
   policy graph, the attribute certificate and the store/parameter/trust units to a `not-started`
   Phase 11 became stale deferrals when the stratum derived `complete`, and the plan's row 11.1
   names `crypto/x509/by_dir.c`, whose only export is the constructor and whose every other function
   is `static` (so `internal-symbols.json` records none of them). All ten were rewritten as
   `reached_by_a_named_construct` records naming the crate module and the built names — the honest
   disposition once the code is there — and `plan_reconciliation.py` is green again. The ten records
   are `pcy_tree.c`, `pcy_cache.c`, `pcy_data.c`, `pcy_map.c`, `pcy_node.c`, `x509_acert.c`,
   `x509_lu.c`, `x509_vpm.c`, `x509_trust.c` and `by_dir.c`
   (`forensics/prerequisites.json:1076-1189`).
2. **The verifier's dependency knot is a correction to the schedule, and the rule that resolves it
   is written down.** D503 records that `X509_verify_cert`'s remaining closure crosses *forward*
   into Phase 12 and the SSL layer, that the dependency order `22 -> 11 -> 12` makes "wait for Phase
   12" a cycle, and that the answer is to pull the *implementation* dependency forward while the
   *ownership* stays put. The plan's §2.1 now carries the same rule and the same measured OCSP
   closure, so the plan and the decision record one figure (`docs/PHASE-11-SUBPHASES.md:124-148`,
   D503).
3. **The pulled-forward substrate is internal, and D506 landed it before the engine that calls it.**
   The OCSP functions under `src/ocsp/` and the `SSL_DANE` representation under `src/x509/dane.rs`
   carry no `#[no_mangle]`, so ownership stays with Phase 12 and this stratum's statics and
   libcrypto gains no new `OCSP_*` symbol; that is D503's rule applied rather than a deviation from
   it (D506).
4. **The two HTTP loaders are deferred rather than pulled forward, and the correction is the
   direction of the trade.** D505 records that `X509_load_http` and `X509_CRL_load_http` are one-line
   delegations to `simple_get_asn1`'s `OSSL_HTTP_get`, and that pulling a whole HTTP client, the BIO
   connect machinery and punycode forward for two convenience wrappers is the opposite of D503's
   trade; the ledger records them with their callee, authority file and line, and owning stratum
   (`forensics/phase11-obligations.json:13-26`).
5. **`RT-X509-VERIFY` passed without the thing it was named for, and the correction is two courts
   rather than a caveat.** D502 records that the court passed while `X509_verify_cert` was withheld
   and only prose said so; the registered court became `RT-X509-VERIFY-SURFACE` and
   `RT-X509-VERIFY-ENGINE` was registered as a pending court describing the decision, error code,
   error depth, `verify_cb` sequence and constructed chain it would establish. `PENDING_COURTS` is
   now empty (D507, D508), so the correction is closed rather than standing.
6. **A signature defect was on a line a human had already read, and the type plane is what found
   it.** D502 records `PKCS5_pbe2_set_scrypt`'s `aiv` as `*const c_uchar` against the authority's
   `unsigned char *`, reported as `TYPE-MISMATCH` and corrected to `*mut c_uchar`. The declaration
   had been read and believed before the plane objected; that is the plane's purpose.
7. **The `OPENSSLDIR` gate was opened the way `MODULESDIR` was, and the answer is deliberately
   empty rather than fabricated.** D504 records that the four `X509_get_default_*` names and the
   nine that cascade into them waited on a build fact, that `build.rs` captures a new
   `OPENSSL_RS_OPENSSLDIR`, and that the answers return the empty C string when it is unset so a
   default-bundle load fails rather than opening the authority's forensic path. The four and the
   nine are `referenced`, never `called`, because no observation of them can be equal; the directory
   plane proper remains Phase 16's.
8. **`ossl_x509_check_cert_time` is no longer a divergence with a blocker; Phase 11 modelled what
   it needed.** Phase 10 recorded it as a divergence with its blocker rather than landing it
   (`docs/PHASE-10-KEYFORMATS-SEAL.md:509-511`) and named landing it as the follow-up when Phase 11
   modelled `X509_VERIFY_PARAM`, `X509_STORE_CTX` and `X509_cmp_time` (`:674-676`). The engine
   transcribed it internally, and the record that covered it is retired (D507).
9. **The plan's §1 and §5 figures are activation measurements, and the seal cites the ledger instead
   of them.** `docs/PHASE-11-SUBPHASES.md:58-62` reads 954 implemented and 513 open at activation;
   the ledger (`forensics/phase11-obligations.json:5-12`) and the census (`docs/SEAL-CENSUS.md:39`)
   now read `implemented` 1465, `deferred` 2, `open` 0. The plan's §5 itself says the split moves as
   the stratum lands its own units, and the ledger is the live record.
10. **The certificate-graph ownership correction is Phase 10's, and this plan depends on it.** D431
    §4.2 records that D175/D177 read `PBEPARAM`'s `x509.h.in` declaration as Phase 10's; measured,
    all 548 `x509.h` exports are phase 11's and `forensics/atlas/typedef-owners.json` gives
    `PBEPARAM` `owner_phase: 11`. This plan does not re-open the correction, it rests on it
    (`docs/PHASE-11-SUBPHASES.md:209-214`).
11. **The `pass` this seal cites is a differential result over the fixtures, and §6 is where the
    bound is.** Every count in this document is the census's or the ledger's, and the one table it
    carries is copied from `artifacts/phase11/COURTS.json`; a number inside an older decision entry
    is the value current when that entry was written and is not this document's count.
