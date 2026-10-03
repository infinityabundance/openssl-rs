# Phase 12 — CMS / OCSP / CMP / CT / TS and the remaining families: seal

**STATUS: derived.** This status is not typed; it is the state
`forensics/tools/phase_state.py` derives from artefact existence. The stratum's export ledger is empty
of open rows — `forensics/phase12-obligations.json:9` reads `open_in_this_stratum: 0` — every
earlier stratum is `complete`, and the FRF/Gemel chain entry §8 records has landed, so
`phase-state.json` reports phase 12 **`complete`** with an empty blocking reason. That derived state
is the phase-exit predicate, and D522 records that the ledger's own `complete` is *not* it
(`docs/DECISIONS.md:35074-35076`). `seal_sha256` is derived too: this document is named in
`forensics/tools/atlas_common.py`'s `SEAL_DOCS` table, which `forensics/tools/render_seal_census.py`
and `phase_state.py` read, so the line is recomputed whenever this document changes and is not
restated here. Reaching `complete` means the stratum has reached the state a seal *records*
(D421); it is **not** a parity claim, and this document is where what the derivation does and does
not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This seal
cites that document rather than restating its arithmetic, because a number typed here is a number
that can drift from the evidence it summarises (D97), and the census's own header
(`docs/SEAL-CENSUS.md:6-9`) says so. The one table this document *does* carry — §3's court list — is
copied from `artifacts/phase12/COURTS.json`, and it says so.

**This seal records a candidate-transcription claim, and it is neither a security claim nor a
parity claim.** Its evidence shows that the candidate distribution defines the names this stratum
owns and that the behaviours its eleven courts exercise match the pinned authority's over fixed
fixtures, observation for observation. It does **not** show that the crate's container parsing,
signature verification or protocol engines are safe against a hostile input — no court here is a
security or fuzz gate — and it does **not** show that the crate is a usable OpenSSL.
`docs/PARITY_MODEL.md` is the authority on what the labels mean: `implemented` means a symbol with
that name is defined, and a passing bounded court is a differential result over the behaviours that
court exercises. `PARITY_VERIFIED` is not claimed for any symbol here, and `forensics/STATUS.md`'s
non-claims are the generated projection's. All 603 `libssl` exports remain `SCAFFOLDED` — a stub
present, which cannot count as parity (`docs/PARITY_MODEL.md:22`) — exactly as
`docs/SEAL-CENSUS.md:21` and `forensics/STATUS.md:127-129` record.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json:39`), named as the
  authority by `artifacts/phase12/COURTS.json:2` and `:5`
- Court results: `artifacts/phase12/COURTS.json` — eleven courts, `all_pass` true
  (`artifacts/phase12/COURTS.json:4`), zero residuals; the totals are `docs/SEAL-CENSUS.md`'s
  (`docs/SEAL-CENSUS.md:419`) and the per-court table is §3. All eleven are **differential** courts
  (`summary` `pass` 11 of `total` 11, `artifacts/phase12/COURTS.json:201-205`), with `pending_courts`
  empty (`artifacts/phase12/COURTS.json:200`). This stratum has **no correctness `CT-*` court**, and
  §3 states why.
- Obligation ledger: `forensics/phase12-obligations.json` — `open_in_this_stratum` 0
  (`forensics/phase12-obligations.json:9`), `deferred_to_later_phase` 3
  (`forensics/phase12-obligations.json:7`); the working-set rule it enforces is at
  `forensics/phase12-obligations.json:1236`
- Court coverage: `forensics/atlas/court-coverage.json` — phase 12's block at
  `forensics/atlas/court-coverage.json:35202`, its counts at `:35204-35212`; the counts are also
  `docs/SEAL-CENSUS.md` §Court coverage (`docs/SEAL-CENSUS.md:491`), and the weaker meaning of
  `directly_courted` is stated there and in §1 below (D199)
- Derived state: `forensics/phase-state.json:505-524`; it owns **no provider row**, so its
  `provider_rows` is `null` rather than a count
- FRF receipts and claim: **present, and the chain's objects are on disk.** `.frf` carries ten
  receipts for the ten declarable courts
  (`receipt-run-openssl-rs-rt-{http,pkcs7,cms,cmp,ts,ocsp,crmf,ess,srp,cms-remainder}-*`), twenty
  adjudicated challenge records (both operators on every court) and the `sensitivity-backed` claim
  `574379772186cc3c71a2f174a9478f7e6e721fa18e0c1fa59a4723e8b3d726df`, binding
  `openssl-rt-3.6.4-r2` to `openssl-rs 0.0.16` with zero blockers and all ten premises carrying
  stdout and exit. §8 states what that is
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s head
  change is Phase 12's `C98` (`forensics/GEMEL_TRAJECTORY.md:13`) and its `current:` is `K51` —
  `checkpoint.c9ca28bdb0077b7a338901381580cc06fb0b27e442843e518395323d22ea4abc`
  (`forensics/GEMEL_TRAJECTORY.md:209,220`). The state a reader reaches the stratum's `complete`
  through is this stratum's. §8 states what that is
- Deciding record: `docs/DECISIONS.md` — **D510** through **D522** (`docs/DECISIONS.md:34728-35087`),
  with `docs/PHASE-12-SUBPHASES.md` for the subphase plan this seal closes. §10 is where the
  corrections those entries record are summarised

## 1. What this phase owns, and how that was decided

Phase 12 is **the container-and-protocol stratum**: the signed, enveloped and encrypted container
formats and the certificate-status and protocol machinery built over Phase 11's X.509 objects —
`CMS` and its `PKCS7` predecessor, `OCSP`, `CMP` with `CRMF`, `TS`, `CT`, the S/MIME bridge that
carries them — and the remaining `libcrypto` families the earlier strata left: `SRP`, `ESS` and the
HTTP client (`docs/PHASE-12-SUBPHASES.md:3-12`). It is deliberately **not** the X.509 object graph
the containers carry (Phase 11's), **not** the ASN.1 substrate they are built from (Phase 5's), and
**not** the key objects they carry (Phases 7, 8 and 10): `docs/PHASE-12-SUBPHASES.md:14-23` records
the split, and `forensics/atlas/symbol-ownership.json` assigns every export declared in `ts.h`,
`ocsp.h`, `cmp.h`, `cms.h`, `pkcs7.h`, `crmf.h`, `ct.h`, `ess.h`, `srp.h`, `http.h`, `cmp_util.h` and
four `pem.h`/headerless spellings to phase 12.

**The working set is derived, not chosen.** The rule is the ledger's own, at
`forensics/phase12-obligations.json:1236`:

> the stratum's working set is the projection of `forensics/atlas/symbol-ownership.json` for phase
> 12, plus every symbol an earlier stratum's ledger records as handed to it: a symbol belongs to the
> stratum that owns the header declaring it, and a discharged hand-off belongs to the stratum that
> built it

The census's per-stratum row (`docs/SEAL-CENSUS.md:40`) reads `atlas-owned` 1024, `ledger owned`
1033, `implemented` 1030, `deferred` 3, `open` 0. The 1,024 atlas-owned exports are **twelve
headers** — `ts.h` 184, `ocsp.h` 169, `cmp.h` 157, `cms.h` 149, `pkcs7.h` 118, `crmf.h` 92, `ct.h`
60, `ess.h` 30, `srp.h` 29, `http.h` 24, `cmp_util.h` 4 and `pem.h` 4 — plus four headerless
`PEM_*_CMS` spellings (`docs/PHASE-12-SUBPHASES.md:42-56`); the 9 are the hand-offs the census
enumerates at `docs/SEAL-CENSUS.md:414-417`: seven from phase 5 (`ASN1_ITEM_get`,
`ASN1_ITEM_lookup`, the five `SMIME_*` faces) and two from phase 11 (`X509_load_http`,
`X509_CRL_load_http`).

**Like Phases 10 and 11, this stratum did not start with a whole working set open.** 149 of its
atlas-owned exports were already `implemented` before its first subphase — the whole `ocsp_asn.c`
item group (75), the CT `ct_sct.c`/`ct_log.c`/`ct_policy.c`/`ct_oct.c`/`ct_b64.c`/`ct_prn.c` units
(59), `pk7_asn1.c` with `pk7_lib.c` (14) and `http_lib.c`'s `OSSL_parse_url` (1) — landed as
substrate Phase 10's pulled-forward `OSSL_STORE` arm and Phase 11's verification path needed, so
`open_in_this_stratum` opened at **884**, not 1,033 (`docs/PHASE-12-SUBPHASES.md:25-32,66-72`). The
split moves as the stratum lands its own units, so the ledger's `counts` is the live record and
§1 of the plan is the activation measurement.

**The 1,033 symbols are defined by 67 authority translation units, and 61 had open symbols at
activation.** `forensics/atlas/export-defining-units.json` resolves the working set to units under
`crypto/cms/`, `crypto/cmp/`, `crypto/ts/`, `crypto/ocsp/`, `crypto/pkcs7/`, `crypto/crmf/`,
`crypto/ess/`, `crypto/srp/`, `crypto/ct/`, `crypto/http/` and `crypto/pem/`, with three that live
in `crypto/asn1/` and `crypto/x509/` (`asn_mime.c`, `asn1_item_list.c`, `x_all.c`) because the
hand-offs are declared there; the ledger's `owned_by_module` block
(`forensics/phase12-obligations.json:1162-1231`) records the per-crate-module shape reached at
closure. The nine subphase rows above the seal partition the 884 activation-open exports exactly,
23 + 103 + 153 + 161 + 184 + 94 + 122 + 29 + 15 = 884, and the partition is derived from the
defining units joined to the ledger's `open` list, not typed (`docs/PHASE-12-SUBPHASES.md:132-135`).

**Phase 12 owns no provider registration row, and that is measured rather than omitted.**
`forensics/atlas/provider-algorithms.json`'s projection names owning phases 8, 9, 10 and 13 only
(996 rows, 636/306/39/15), so the phase-12 slice of that census is empty and
`forensics/phase12-obligations.json:1233` carries `provider_rows_owned: 0`. Every container, OCSP,
CMP, TS and CT name is an `libcrypto` export reached through a caller, not a dispatch-table row an
`OSSL_ALGORITHM` array publishes; that is why `phase_state.py`'s provider-row rule and
`provider_court_coverage.py` have nothing to hold against this stratum
(`docs/PHASE-12-SUBPHASES.md:109-114`).

**The order is forced, and the forcing is the authority's domain structure rather than a measured
call graph.** 12.1 before 12.3/12.4/12.6 because the CMS S/MIME writer, the CMP HTTP arm and the
OCSP client all reach the HTTP transport; 12.2 before 12.3 because `cms_smime.c` emits a
`PKCS7`-shaped message for the older format; 12.4 before 12.7 because CMP's message engine carries
`OSSL_CRMF` certificate requests; 12.3 before 12.5 and 12.6 because a timestamp token's and an OCSP
response's signed body are both built with CMS signer-infrastructure; and 12.9 last because its
shared units (`asn1_item_list.c` enumerates every stratum's items) close over the strata above
(`docs/PHASE-12-SUBPHASES.md:137-145`, D510). The dependency of 12.4/12.5/12.7 on 12.3 is inferred
from that domain structure rather than a measured call graph, and D510 records it as a dependency to
be corrected at each slice.

**The plane, and which one this stratum's evidence is.** D201's commitment — every
*primitive-bearing* subphase carries a differential `RT-*` court *and* a correctness `CT-*` court —
is scoped to primitive-bearing work, and this stratum emits no primitive: it has **ten behavioural
differential courts and one reference-basis court, and no `CT-*` court**. A reader who expected a
correctness plane should read `docs/PHASE-12-SUBPHASES.md:184-189` rather than infer one. The
reference basis is `RT-PHASE12-REF`, the court D199 requires for a stratum whose exports an earlier
stratum landed: it takes the address of each of the 149 inherited `implemented` exports, so a symbol
covered only by it is a proof of *reference* and not that any arm of it was driven
(`artifacts/phase12/COURTS.json:6`). §3 is where the two readings are tabulated.

## 2. What has been built

**12.0, the plan and the census.** `docs/PHASE-12-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase12-obligations.json` and its generator, the runner
`forensics/tools/phase12_courts.py`, and the reference-basis probe
`courts/phase12/rt_coverage_ref_probe.c` — all landed together, because §4.3 of the plan makes the
runner and the reference probe a precondition rather than a later slice
(`docs/PHASE-12-SUBPHASES.md:208-229`, D510).

**12.1, the HTTP client.** `crypto/http/`'s whole surface in `src/http/http_client.rs` and
`src/http/http_lib.rs`: the `OSSL_HTTP_REQ_CTX_*` request context and its memory BIO, the
`OSSL_HTTP_open`/`_set1_request`/`_exchange`/`_close`/`_transfer` and `OSSL_HTTP_get` entry points,
the per-request header and redirection surface, and the two `http_lib.c` names
`OSSL_HTTP_parse_url`/`OSSL_HTTP_adapt_proxy` — 23 open rows over 2 units, now zero. `RT-HTTP`
(`courts/phase12/rt_http_probe.c`) drives the request engine over memory BIOs with canned HTTP/1.1
responses and the high-level path over a caller-supplied BIO pair, with no socket and no wall clock
(D511).

**12.2, the PKCS#7 remainder.** `crypto/pkcs7/`'s whole surface in `src/pkcs7/` (`pk7_asn1.rs`,
`pk7_lib.rs`, `pk7_doit.rs`, `pk7_attr.rs`, `pk7_smime.rs`, `pk7_mime.rs`, `bio_pk7.rs`) plus
`pem_all.c`'s four `PEM_read[_bio]_PKCS7`/`PEM_write[_bio]_PKCS7` — 103 open rows over 8 units, now
zero (D513). `RT-PKCS7` drives them from fixed DER fixtures.

**12.3, the CMS container.** `crypto/cms/` in three slices: the object model and item graph
(`cms_asn1.c`, `cms_lib.c`, `cms_att.c`, `cms_enc.c`), the signer and recipient engines (`cms_sd.c`,
`cms_env.c`, `cms_kari.c`, `cms_kemri.c`, `cms_pwri.c`), and the remainder (`cms_smime.c`'s
`CMS_sign`/`CMS_verify`/`CMS_encrypt`/`CMS_decrypt`/data/digest surface, `cms_io.c`'s PEM/BIO readers
and `cms_ess.c`'s receipt surface) — 153 open rows over 12 units, now zero, the largest subphase and
the stratum's namesake (`src/cms/`, D514). `RT-CMS` drives the decode/encode round trip, the
accessors, the signer/recipient/verifier and receipt engines, and the BIO/PEM readers over a fixed
cert+key.

**12.4, CMP.** `crypto/cmp/` in `src/cmp/`: `cmp_asn.c`, `cmp_ctx.c`, `cmp_hdr.c`, `cmp_status.c`,
`cmp_util.c`, `cmp_msg.c`, `cmp_http.c`, `cmp_vfy.c`, `cmp_client.c`, `cmp_server.c` and the engine
units `cmp_protect.rs`, `cmp_genm.rs` — 161 open rows over 11 units, now zero. 12.4 left fifteen rows
open on `crmf_lib.c`/`crmf_pbm.c` and 12.4b closed them once 12.7 had landed (D515, D519).
`RT-CMP` drives the context accessors, the message and header item groups, the `ATAV`/`ITAV`/
`CRLSTATUS` builders, and the client/server engine over an in-process `OSSL_CMP_SRV_CTX`.

**12.5, timestamping.** `crypto/ts/` in `src/ts/`: `ts_asn1.c`, `ts_req_utils.c`, `ts_rsp_utils.c`,
`ts_lib.c`, `ts_req_print.c`, `ts_rsp_print.c`, `ts_verify_ctx.c`, `ts_conf.c`, and the response
engine `ts_rsp_sign.c`/`ts_rsp_verify.c` — 184 open rows over 10 units, of which 182 land here and
two are handed on (§6). `RT-TS` drives the DER round trips, the accessors, the printers, the verify
context, the response builder and verifier over a fixed token, and the `CONF` readers (D516, D520).

**12.6, OCSP.** `crypto/ocsp/` in `src/ocsp/`: `ocsp_ext.c`, `ocsp_cl.c`, `ocsp_srv.c`,
`ocsp_lib.c`, `ocsp_prn.c`, `ocsp_vfy.c`, `ocsp_http.c` — 94 open rows over 7 units, now zero.
Sixteen of the 94 are promoted from the internal `pub(crate)` transcriptions Phase 11 pulled forward
for `X509_verify_cert` (D506), and seventy-eight are newly transcribed; **the exported ownership
migrates without the pulled-forward substrate moving a byte** (D517). `RT-OCSP` drives hand-built
object graphs and a fixed DER response, including the two byte-for-byte printers and the
`OCSP_basic_verify` object graph.

**12.7, CRMF and ESS.** `crypto/crmf/` (`crmf_asn.rs`, `crmf_lib.rs`, `crmf_pbm.rs`) and
`crypto/ess/` (`ess_asn1.rs`, `ess_lib.rs`) — 122 open rows over 5 units, now zero. The item groups
12.4 pulled forward crate-internally as `src/cmp/crmf_asn.rs` moved to `src/crmf/crmf_asn.rs` and
published their exports, so the object model did not move a byte (D518). `RT-CRMF` and `RT-ESS`
drive the item groups, the controls, the `ProofOfPossession` pair and the `OSSL_ESS_*` builders over
a fixed RSA key and certificate.

**12.8, SRP.** `crypto/srp/` in `src/srp/` (`srp_lib.rs`, `srp_vfy.rs`) over the RFC 5054 groups in
`src/bn/bn_srp.rs` — 29 open rows over 2 units, of which 28 land here and `SRP_VBASE_init` is handed
on (§6) (D521). `RT-SRP` drives the arithmetic over fixed BIGNUMs and the seven known groups, the
`SRP_user_pwd_*` record and the verifier database; the random-salt arms print only invariants, so no
random byte is compared.

**12.9, the CT remainder, the shared dispatch and the hand-offs.** `src/asn1/asn1_item_list.rs`
(`ASN1_ITEM_lookup`/`ASN1_ITEM_get` over the 147-entry generated list in its exact order),
`src/ct/ct_log.rs` (`CTLOG_STORE_load_default_file`), `src/x509/x_all.rs` (the shared
`PKCS7_ISSUER_AND_SERIAL_digest`, the four `PKCS7` BIO/FILE codecs and the two Phase-11
`X509_load_http` hand-offs) and `src/asn1/asn_mime.rs` (the MIME reader/writer, `SMIME_read_ASN1`/
`_ex`, `SMIME_write_ASN1`/`_ex`, `SMIME_text`, `asn1_write_micalg`) — 15 open rows over 6 units, now
zero (D522). `RT-CMS-REMAINDER` drives them over fixed fixtures.

**The books that moved with the code.** The implemented surface ended where the census states it:
`docs/SEAL-CENSUS.md:20-22` is the `libcrypto`/`libssl`/total table, and the live internal
`c_style` count is what `docs/CI.md:108` records and `docs_consistency.py` checks against
`forensics/atlas/implemented-surface.json`. Phase 12's own ledger reads `implemented` 1030 of
`owned` 1033 with `deferred` 3 and `open` 0 (`forensics/phase12-obligations.json:5-12`,
`docs/SEAL-CENSUS.md:400-407`), and it discharged the nine hand-offs rather than passing them on
(`docs/SEAL-CENSUS.md:414-417`). The three deferrals are recorded with their callee, authority
file and line, and owning stratum — not merely named (`forensics/phase12-obligations.json:13-31`,
§6).

## 3. The evidence

Copied from `artifacts/phase12/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. All eleven courts are differential; the stratum registers no
correctness `CT-*` court, so no row here carries a `vectors_checked` count.

| court | plane | observations | probe |
|---|---|---|---|
| `RT-PHASE12-REF` | differential (reference basis) | 149 | `courts/phase12/rt_coverage_ref_probe.c` |
| `RT-HTTP` | differential | 128 | `courts/phase12/rt_http_probe.c` |
| `RT-PKCS7` | differential | 126 | `courts/phase12/rt_pkcs7_probe.c` |
| `RT-CMS` | differential | 176 | `courts/phase12/rt_cms_probe.c` |
| `RT-CMP` | differential | 320 | `courts/phase12/rt_cmp_probe.c` |
| `RT-TS` | differential | 275 | `courts/phase12/rt_ts_probe.c` |
| `RT-OCSP` | differential | 266 | `courts/phase12/rt_ocsp_probe.c` |
| `RT-CRMF` | differential | 138 | `courts/phase12/rt_crmf_probe.c` |
| `RT-ESS` | differential | 47 | `courts/phase12/rt_ess_probe.c` |
| `RT-SRP` | differential | 149 | `courts/phase12/rt_srp_probe.c` |
| `RT-CMS-REMAINDER` | differential | 71 | `courts/phase12/rt_cms_remainder_probe.c` |

Every differential row carries `residual_count: 0` and `verdict: "pass"`
(`artifacts/phase12/COURTS.json:7-199`), and the summary reads `pass` 11 of `total` 11 with
`pending_courts` empty (`artifacts/phase12/COURTS.json:200-205`). The totals over the eleven
transcript courts are `docs/SEAL-CENSUS.md`'s (`docs/SEAL-CENSUS.md:419`), and the per-court rows
there (`docs/SEAL-CENSUS.md:423-433`) are the same computation.

**`RT-PHASE12-REF` is not a behavioural court, and its meaning is the weaker one.** Its probe takes
the address of each of the stratum's 149 inherited `implemented` exports and prints whether each is
non-NULL, so a symbol covered only by it means the candidate distribution defines the name — which
the link proves — and **not** that any arm of it was driven (`artifacts/phase12/COURTS.json:6`,
`courts/phase12/rt_coverage_ref_probe.c`). The court coverage atlas records those at basis
`referenced`, never `called` (`docs/SEAL-CENSUS.md:491`, D199). Ten courts are behavioural:
`RT-HTTP` drives the request/response engine over memory BIOs; `RT-PKCS7` drives the `PKCS7` item
groups and the sign/verify/encrypt surface from fixed DER; `RT-CMS` drives the container, signer,
recipient and receipt engines; `RT-CMP` drives the context, message, header and engine surface;
`RT-TS` drives the RFC 3161 request, response, printer and `CONF` surface; `RT-OCSP` drives the
request, responder, verifier and printer surface; `RT-CRMF` and `RT-ESS` drive the CRMF object graph
and the ESS signed-attribute groups; `RT-SRP` drives the SRP arithmetic and verifier database; and
`RT-CMS-REMAINDER` drives the item table, the shared dispatch and the S/MIME reader/writer
(`courts/phase12/*_probe.c`, `docs/PHASE-12-SUBPHASES.md:258-416`).

**Why there is no correctness plane, stated rather than left to inference.** D201's commitment is
scoped to primitive-bearing subphases, and this stratum emits no primitive: every subphase builds a
container, a protocol state machine or an arithmetic surface over Phase 8's primitives, and a
`CT-*` court is a vector-driven construction check with no authority transcript to diff (D13, D201).
The stratum's evidence is therefore **differential only**, which is a measurement and not an
omission, and every name that could not be driven is named `pending.` rather than counted as passing
(§5).

**The court coverage join is clean, and its meaning is the weaker one.**
`docs/SEAL-CENSUS.md:491` reads phase 12 as 1030 implemented, 1030 `directly_courted` (902 of them
`called` and 128 `referenced`), 0 indirect, 0 non-observable, 0 unmatched; the block is
`forensics/atlas/court-coverage.json:35202` and its counts are at `:35204-35212`. `directly_courted`
means *referenced by a staged candidate probe that ran and produced a transcript*
(`docs/SEAL-CENSUS.md:475-478`), a proof of **reference** rather than that every arm of the symbol
was driven — the same reading Phase 8's, Phase 9's, Phase 10's and Phase 11's seals adopt. The
referenced 128 are the inherited `RT-PHASE12-REF` names the behavioural courts do not call, and the
called 902 are the names — the stratum's own work and the inherited names its courts reach — that a
probe actually invokes.

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
evidence found real defects, in the candidate and in the instrument.

**The plan's own guessed names did not exist, and the court is what checked.** `RT-HTTP`'s brief
named `OSSL_HTTP_REQ_CTX_set_request`, `parse_response_line`, `_nbio_d2i_ex`, `_set_mem_buf`,
`_get_mem_buf`, `OSSL_HTTP_get_ex`, `OSSL_HTTP_get0_status` and more; measured against the admitted
authority's `include/openssl/http.h` and `crypto/http/http_client.c`, **none of those names exists**
in `openssl-3.6.4` (`courts/phase12/rt_http_probe.c:21-32`, D511). They were not landed, because
there was nothing to land; each corresponds to a real arm the court drives under the authority's
actual name.

**A width bug in an inherited ASN.1 struct was exposed by a new caller.** The crate's
`Asn1StreamArg` was ordered `{out, boundary, ndef_bio}` where the authority's `asn1t.h.in:711-718` is
`{out, ndef_bio, boundary}`, so the 12.3a streaming callback wrote the boundary into the `ndef_bio`
slot and corrupted the heap, segfaulting in `BIO_new_CMS`/`i2d_CMS_bio_stream`; it was fixed at
12.3c (D514). A pre-existing latent defect the new caller exposed, and exactly the class the
differential court exists to reach.

**The authority's build configuration was corrected by measurement rather than assumed.**
`OPENSSL_NO_ZLIB` is defined in the admitted authority's `configuration.h`, so
`CMS_compress`/`CMS_uncompress` are the `#else` refusal arms, `cms_cd.c` defines nothing, and the
`compressedData` dispatch arm is guarded out (`cms_lib.c:170-173`). The ZLIB-enabled premise was
wrong and the crate follows the authority (D514).

**A lower-unit identity gap surfaced rather than being hidden.** `PKCS7_set_cipher` and the
digest/enveloped `PKCS7_dataInit` fetch path compare the candidate's `EVP_MD_get_type`/
`EVP_CIPHER_get_type`, which answer 0 where the authority answers 672/419, so those two arms are
printed as `pending.` lines with the reason rather than driven, and the `data` container's
fetch-free `dataInit`/`dataFinal` is driven instead (D513,
`courts/phase12/rt_pkcs7_probe.c:309-313,426-430`). This is a lower-unit divergence a new caller
made observable; §5 records every arm it reaches.

**A Phase-8 defect was surfaced by a Phase-12 caller and fixed at its own layer.** The new
`OSSL_ESS_*` callers exposed a wrong `EVP_MD_is_a` result in `src/evp/`, fixed in Phase 8's unit
rather than worked around here (D518). The authority-tier atlas was re-derived and is byte-identical
on a second run.

**A real engine bug was found and fixed.** 12.4b found and fixed a `cmp_server.c` failure-funnel
bug; the authority-tier atlas is byte-identical on re-derivation (D519). The court that grew to
cover the engine — `RT-CMP`, 230 → 320 observations with 0 residuals — is what exercises the funnel.

**The pulled-forwards were promoted rather than re-implemented.** D517 records that 16 of OCSP's 94
exports are promoted from the internal `pub(crate)` transcriptions Phase 11 landed for
`X509_verify_cert` (D506), and that the exported ownership migrates to Phase 12 without the
substrate moving a byte. That is D503's pull-forward rule (§1) completing its round trip: the
implementation dependency was pulled ahead, and the public ownership now follows it back.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an unset field, or **crashes**, the court does
not call it and the divergence is recorded with the phase or condition that would make the behaviour
reachable. **No divergence obligation names Phase 12 as its `current_owner`.**
`forensics/divergence-obligations.json` reads 10 rows and **0 blocking**
(`forensics/divergence-obligations.json:3-11`), and its rows' `current_owner` values are 8, 9, 10 and
13; `phase_state.py` refuses to derive any state while an obligation whose owner is the stratum has
`trigger_satisfied` true and `disposition` `open`, so no live obligation outran this stratum's
evidence. The boundaries this stratum actually met are recorded in the places below.

- **The fetched `EVP_MD`/`EVP_CIPHER` identity divergence is named, not hidden.** A fetched digest or
  cipher reports type 0 on the candidate where the authority reports the NID
  (`EVP_MD_get_type`/`EVP_CIPHER_get_type`), so every arm that reaches it is printed as a `pending.`
  line rather than compared: `RT-PKCS7`'s `PKCS7_dataInit`/`PKCS7_set_cipher`
  (`courts/phase12/rt_pkcs7_probe.c:309-313,426-430`), `RT-CMS`'s digest/sign/cipher arms
  (`courts/phase12/rt_cms_probe.c:716-845`), `RT-CMP`'s engine
  (`courts/phase12/rt_cmp_probe.c:989-995`) and `RT-CRMF`'s signature POPO
  (`courts/phase12/rt_crmf_probe.c:398-405`). D513 records it as the lower-unit identity gap the
  new caller made observable.
- **The legacy `EVP_get_digestbyname`/`OBJ_NAME` lookup divergence routes several arms.** It is the
  crate's recorded, deferred Phase-13 legacy digest-name table (D333/D343), and the authority
  resolves a digest through it where the candidate cannot. `RT-TS`'s `CONF` readers
  (`courts/phase12/rt_ts_probe.c:1384-1428`), `RT-OCSP`'s signature-verifying
  `OCSP_basic_verify` (`courts/phase12/rt_ocsp_probe.c:578-582`), `RT-CMP`'s signed transaction and
  PBM protection (`courts/phase12/rt_cmp_probe.c:983-995`) and `RT-CRMF`'s POPO signature
  verification (`courts/phase12/rt_crmf_probe.c:398-405`) are named `pending.` for that reason; the
  comparable arms run the same engine unprotected or over `raVerified` POPO, so every observation
  stays a function of the library.
- **The Phase-11 `X509_NAME` printer divergence is a boundary this stratum does not own.** `RT-CMS`'s
  printed-text arm names `pending.<tag>_print` = `x509-name-printer-divergence`, because the
  authority's and the candidate's `X509_NAME` printers differ on the fixture — a Phase 11 `x_name.c`
  divergence (`courts/phase12/rt_cms_probe.c:382-389`).
- **The `asn1_write_micalg` legacy arm is named rather than compared.** `SMIME_write_ASN1_ex`
  reaches `asn1_write_micalg`, whose `EVP_get_digestbynid`/`md_ctrl` path is the same Phase-13 legacy
  digest-name divergence; the authority's own `switch (md_nid)` still supplies the strings, so the
  arm is recorded as an honest limit rather than a pass (D522,
  `docs/PHASE-12-SUBPHASES.md:411-416`).
- **The SMIME-detached random boundary is not compared.** `SMIME_DETACHED` would generate a random
  MIME boundary, so `RT-CMS-REMAINDER` writes a fixed opaque value instead
  (`courts/phase12/rt_cms_remainder_probe.c:22-24`, D522).
- **The authority's FILE-refusal arms crash it, so the probes avoid them.** `d2i_PKCS7_fp(NULL, …)`
  and `i2d_PKCS7_fp(NULL, …)` install a null `FILE *` into a `BIO_s_file` and then read or write it;
  measured against the authority, both segfault, so the `_fp` refusals in `RT-CMS-REMAINDER` drive a
  bad-content decode and a null-value encode instead
  (`courts/phase12/rt_cms_remainder_probe.c:31-38`, D522).
- **A response with no responder name is a genuine fault boundary in the authority.**
  `OCSP_basic_verify` dereferences the unset responder name, so the arm is named
  (`pending.resp.basic_verify_nosigner=authority_derefs_unset_responder_name_fault_boundary`) rather
  than driven (`courts/phase12/rt_ocsp_probe.c:620-624`).
- **`SRP_Calc_u`'s NULL arms crash the authority.** It has no NULL guard: it forwards to
  `srp_Calc_xy`, whose `BN_ucmp(x, N)` dereferences the pointer, so a NULL `A`/`B`/`N` crashes both
  sides and compares nothing; those arms are omitted in favour of the four functions that do guard
  (`courts/phase12/rt_srp_probe.c:199-204`, D521).
- **Three TS status-info setters are referenced rather than called.** `TS_RESP_CTX_set_status_info`,
  `_set_status_info_cond` and `_add_failure_info` have no landed entry point that can make
  `ctx->response` non-NULL, so the atlas records them at the honest `referenced` basis
  (`docs/PHASE-12-SUBPHASES.md:357`, `courts/phase12/rt_ts_probe.c`).
- **The `RT-OCSP`/`RT-CRMF` `EVP_get_digestbyname` arm and the `pending.` set are the register's
  machine form.** The boundaries above are recorded in the probes and in D511–D522;
  `forensics/phase12-obligations.json` carries the three handed-on rows with their callee, and
  `forensics/divergence-obligations.json`'s 10 rows and 0 blocking are why no live obligation
  outran this stratum's evidence.

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with that
   name is defined. `docs/PARITY_MODEL.md` states what each label means; no symbol here is
   `PARITY_VERIFIED`, and `forensics/STATUS.md` carries the current non-claims. The `PARITY_MODEL.md`
   labels this stratum's evidence reaches are at most `IMPLEMENTED`, plus a bounded `SEMANTIC_PASS`
   over the behaviours its courts exercise — never `PARITY_VERIFIED`.
2. **This is a candidate-transcription claim, and it is not a security claim.** The evidence shows
   the names are defined and the courts' fixtures match; it does **not** show the crate parses or
   verifies certificates, containers or protocol messages safely, and no court here is a fuzz or
   security gate. `docs/SECURITY_DIVERGENCE_POLICY.md` records the boundaries; a boundary not
   exercised is recorded, not a safety guarantee.
3. **`libssl` is entirely scaffolded.** All 603 `libssl` exports remain `SCAFFOLDED` — a stub
   present, which cannot count as parity (`docs/PARITY_MODEL.md:22`, `docs/SEAL-CENSUS.md:21`,
   `forensics/STATUS.md:127-129`) — this stratum owns no `libssl` export and touches no TLS code.
4. **Three rows are handed to Phase 13, and they are not claimed.** The two `ts.h` `CONF` readers
   `TS_CONF_set_crypto_device` and `TS_CONF_set_default_engine` have their whole body in the ENGINE
   lookup and installation — `crypto/ts/ts_conf.c:171` (the delegation), `:188` (`ENGINE_by_id`) and
   `:192` (`ENGINE_set_default`) — and `engine.h`'s names are Phase 13's (`engine_by_id` is withheld
   on `crypto/engine/eng_dyn.c`); `SRP_VBASE_init` reads and releases a verifier file through
   `TXT_DB_read` (`crypto/srp/srp_vfy.c:423`) and `TXT_DB_free` (`:504`), which are `txt_db.h`'s and
   Phase 13's. Pulling either registry forward to satisfy these rows is disproportionate, so they are
   handed on rather than stubbed (`forensics/phase12-obligations.json:13-31`,
   `deferred_by_phase` `{13: 3}` at `:33-35`). The stratum's `owned` 1,033 resolves to `implemented`
   1,030 plus `deferred` 3 plus `open` 0 — the arithmetic is the ledger's and the census's.
5. **A passing court is a differential result over the behaviours its probe exercises, and
   implemented-and-courted is not "is a drop-in replacement".** A symbol recorded `directly_courted`
   is *referenced by a staged candidate probe that ran* — 902 of the stratum's are `called` and 128
   are `referenced` (`docs/SEAL-CENSUS.md:491`) — and `RT-PHASE12-REF` in particular proves only
   that the candidate distribution defines the inherited names. Nothing here claims stderr
   equivalence, full CLI compatibility, build-profile independence beyond the admitted one, or
   drop-in substitution.
6. **The protocol courts compare transcripts a probe can construct, not every message.**
   `OSSL_CMP_validate_msg`'s signed arm, `OCSP_basic_verify`'s signature arm and `TS_RESP_verify_*`'s
   signature arm are named `pending.` because they reach the legacy digest-name table (§5); their
   comparable arms are the engine running unprotected or over `raVerified` POPO. A green court is a
   statement about the fixtures the court can build, not about every exchange or response.
7. **The stratum owns no provider row, and claims none.** `provider_rows_owned: 0`
   (`forensics/phase12-obligations.json:1233`) is a measurement, not an omission; §1 states why, and
   `provider_court_coverage.py` has nothing to hold against this stratum.
8. **The FRF and Gemel evidence is established, and §8 records what it is.** `docs/RELEASE_GATES.md`
   §2 items 6, 8 and 10 are met by the chain entry §8 records: ten receipts, twenty adjudicated
   challenge records, the `sensitivity-backed` claim
   `574379772186cc3c71a2f174a9478f7e6e721fa18e0c1fa59a4723e8b3d726df` with zero blockers, and the
   Gemel checkpoint `K51` whose summary names Phase 12 and the FRF chain. Phase 12's derived state is
   `complete`.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process (`docs/PHASE-12-SUBPHASES.md:239-247`) — a subphase lands its code, its court and
its regenerated artefacts in **one commit**; every export carries a court edge on the commit that
lands it (D236); this stratum publishes no provider row (D245 has nothing to hold against it) — and
its §4.3 precondition (the reference-basis probe and the runner land **with** the ledger). Every
clause below is checked against a generated artefact rather than asserted.

| criterion | evidence |
|---|---|
| every export is implemented or handed on with the dependency named | `forensics/phase12-obligations.json`: `open_in_this_stratum` 0 (`:9`) and `deferred_to_later_phase` 3 (`:7`); the generator `forensics/tools/phase12_obligations.py` fails closed, so `implemented + deferred + open == owned` |
| every implemented export is observed by a court | `forensics/atlas/court-coverage.json` phase-12 block (`:35202`); `unmatched` 0 (`:35211`), enforced for `complete` by `forensics/tools/phase_state.py` |
| the reference basis covers the inherited exports | `RT-PHASE12-REF` (`courts/phase12/rt_coverage_ref_probe.c`), registered with the ledger and runner (`docs/PHASE-12-SUBPHASES.md:208-229`); D199/D236 |
| no authority fault is reproduced | §5, and the boundaries recorded in the probes and D511–D522 |
| no divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking (`:3-11`); `current_owner` values are 8, 9, 10 and 13 |
| `ABI-PROTOTYPE`, `ABI-SYMBOL` and `ABI-DYNAMIC` stay clean | `forensics/atlas/ownership-audit.json`: `problems` empty (`:1289`), `implemented_by_two_strata` empty (`:1026`) |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 (`:11`) |
| the dispatch court clean | `forensics/atlas/dispatch-court.json`: `problems` 0 (`:18`) |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` empty (`:702`) |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` empty (`:33`) |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json`'s rule line |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |

**`docs/RELEASE_GATES.md` §2's ten items, each checked rather than assumed.** The first column is
the authority's own list (`docs/RELEASE_GATES.md:54-63`); the second says what this stratum's
evidence for it is, and, where an item is **not met**, says so plainly rather than leaving the row
empty.

| # | item | this stratum's evidence |
|---|---|---|
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json:39` pins `openssl-3.6.4-production`; `artifacts/phase12/COURTS.json:2` names it |
| 2 | obligation inventory | `forensics/phase12-obligations.json` (`:5-12`); this stratum owns no provider row |
| 3 | court manifests | `artifacts/phase12/COURTS.json` |
| 4 | raw captures | **met.** The eleven staged `artifacts/phase12/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (`artifacts/phase12/COURTS.json:19-22` and each row's `staged_binaries`), and `.frf/captures/` carries the FRF venue's captures for the ten declarable courts, produced by §8's chain |
| 5 | residual set | **met in the court venue.** Every court's `residual_count` is 0 and its `residuals` list empty (`artifacts/phase12/COURTS.json:7-199`), `summary` reads `pass` 11 of 11 and `pending_courts` is empty (`:200-205`) |
| 6 | mutation / sensitivity evidence | **met.** `.frf/challenges/` carries twenty adjudicated Phase-12 records — both declared axes (`stdout-first-line`, `exit-class`) on each of the ten declarable courts, every one `saw_defect` and `specificity_clean` |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-12 FRF residual exists to carry one |
| 8 | FRF receipts | **met.** `.frf/receipts/` carries one receipt per declarable court (`receipt-run-openssl-rs-rt-{http,pkcs7,cms,cmp,ts,ocsp,crmf,ess,srp,cms-remainder}-*`), each with an empty `residuals` list |
| 9 | generated parity projection | `forensics/STATUS.md` (`:165-173`), rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s head change is Phase 12's `C98` and its `current:` is `K51`, whose summary names Phase 12 and the FRF chain (`:13,209,220`) |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and item 7 is not applicable
rather than wanting, because `--resolution-run` is required only for a `fixed` disposition and none
attaches to a Phase-12 FRF residual.** Items 6, 8 and 10 retired when §8's chain landed, and
`phase_state.py` now derives `complete` with an empty blocking reason.

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and this section records what it is.**

- **Ten declarations are on disk.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table gained a
  Phase-12 block — `("rt-http", 12, …)` through `("rt-cms-remainder", 12, …)` — and
  `gen_frf_courts.py` wrote the declarations under
  `forensics/frf/courts/openssl-rs-rt-{http,pkcs7,cms,cmp,ts,ocsp,crmf,ess,srp,cms-remainder}`.
  `gen_frf_courts.py --check` reads `ok: 210 file(s) match the table (105 courts)`, and
  `forensics/frf/README.md:160` counts **105 runtime courts** — the Phase-12 ten among them, which
  moves the manifest count the `docs/RELEASE_GATES.md` alternative names with it (D200/D413/D424/D475).
  **`RT-PHASE12-REF` is not declared, unlike Phase 11's `RT-X509-REF`**, because its probe takes
  addresses and diffs no transcript, so it is a reference basis with nothing to stage and cannot
  carry a declaration (D199).
- **The chain's objects are on disk.** `.frf/receipts/` carries ten Phase-12 receipts, one per
  declarable court (`receipt-run-openssl-rs-rt-{http,pkcs7,cms,cmp,ts,ocsp,crmf,ess,srp,cms-remainder}-*`),
  each with an empty `residuals` list. `.frf/challenges/` carries twenty adjudicated challenge
  records — both declared axes (`stdout-first-line` and `exit-class`) on each of the ten courts,
  every one `saw_defect` and `specificity_clean` — which is what makes the claim
  `sensitivity-backed` rather than merely green (D13). `.frf/claims/` carries the compiled claim
  `574379772186cc3c71a2f174a9478f7e6e721fa18e0c1fa59a4723e8b3d726df`, compiled at
  `--policy sensitivity-backed` over the ten receipts, binding authority `openssl-rt-3.6.4-r2` to
  candidate `openssl-rs 0.0.16` with zero blockers and all ten premises asserting both `stdout` and
  `exit`.
- **The Gemel change and checkpoint are this stratum's.** The change `C98`
  (`change.af2e7ed0eb05b4de2a6bf471ddc611d07ff6475dd1434a967a071319aa6bdb83`) names Phase 12 and
  the FRF chain, and the checkpoint `K51`
  (`checkpoint.c9ca28bdb0077b7a338901381580cc06fb0b27e442843e518395323d22ea4abc`) closes it; the
  projection `forensics/GEMEL_TRAJECTORY.md` carries both (`:13,209`), and the checkpoint's summary
  names Phase 12 and the FRF chain (`:210`). Items 6, 8 and 10 of §7 retired with that entry, exactly
  as they did for Phase 9's `C94`, Phase 10's `C95` and Phase 11's `C97`.

**The declarations are produced by `gen_frf_courts.py`; the receipts, challenges, claim and
checkpoint were produced by running the chain in the FRF tooling container, never on the host.**
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
This section records the objects that are on disk.

## 9. What happens next

**Nothing is handed from this stratum to a later one except the three names it deliberately did not
build.** `forensics/phase12-obligations.json`'s `deferred` list is the two `ts.h` `CONF` readers and
`SRP_VBASE_init` (`:13-31`) and its `deferred_by_phase` reads `{13: 3}` (`:33-35`); the census reads
`deferred to a later stratum with a stated reason: 3` (`docs/SEAL-CENSUS.md:406`). Every other
export this stratum owns is implemented, and the 9 it *received* are discharged rather than passed on
(`docs/SEAL-CENSUS.md:414-417`).

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF/Gemel chain entry has landed.** §8's subject is now the objects on disk: the ten
  declarations, ten receipts, twenty adjudicated challenges, the claim
  `574379772186cc3c71a2f174a9478f7e6e721fa18e0c1fa59a4723e8b3d726df` and the checkpoint `K51`.
  This stratum registers no `CT-*` court, so the entry covers the ten behavioural differential
  courts and nothing is recorded as not declarable; `RT-PHASE12-REF` is the reference basis and is
  not declarable. Items 6, 8 and 10 of §7 retired with it, and `phase_state.py` derives `complete`.
- **This seal's §7 and §8 were corrected, and its bytes moved with the correction.** The receipts,
  claim id and checkpoint id were produced by running the chain in the FRF tooling container, never
  on the host, and `seal_sha256` is recomputed from the document's new bytes. Phase 10's and
  Phase 11's seals were corrected the same way.
- **Phase 13 begins on a landed container substrate.** `ocsp.h`'s exports are now Phase 12's
  (`src/ocsp/`), and the legacy/deprecated compatibility layer takes the three handed-on rows
  (`TXT_DB`-backed `SRP_VBASE_init`, and the two ENGINE-backed `TS_CONF_*` setters) together with
  the rest of `crypto/engine/`, `crypto/txt_db/` and the deprecated spellings it owns.
- **`forensics/phase12-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and coverage figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections the phase-12 decision record **D510–D522** made to earlier
statements, the corrections this seal makes to the plan's own account, and the corrections the
evidence forced rather than the ones a reviewer might have preferred.

1. **The stratum's export ledger reaches zero open before the stratum is complete, and D522 writes
   the distinction down.** `phase12_obligations.py`'s `complete` is the ledger-level emptiness check,
   not the phase-exit predicate; the stratum is not complete until 12.10's seal and the FRF/Gemel
   chain (D522, `docs/DECISIONS.md:35074-35076`). This seal is that 12.10 document, and §7's
   item 6/8/10 rows are the predicate's remaining input.
2. **The plan's guessed HTTP names were checked against the authority and do not exist.** The twelve
   names the subphase brief listed (`OSSL_HTTP_REQ_CTX_set_request`, `parse_response_line`,
   `_nbio_d2i_ex`, `_set_mem_buf`, `_get_mem_buf`, `OSSL_HTTP_get_ex`, `OSSL_HTTP_get0_status`, the
   four readers) have no counterpart in 3.6.4; each corresponds to a real arm the court drives
   instead, and none was fabricated to meet the brief (D511, `courts/phase12/rt_http_probe.c:21-32`).
3. **`OPENSSL_NO_ZLIB` is defined in the admitted authority, and the ZLIB-enabled premise was
   wrong.** `CMS_compress`/`CMS_uncompress` are the `#else` refusal arms, `cms_cd.c` defines nothing,
   and the `compressedData` dispatch arm is guarded out (`cms_lib.c:170-173`) (D514).
4. **The `ASN1_STREAM_ARG` field order was wrong in the crate, and a new caller exposed it.** The
   crate's `Asn1StreamArg` was `{out, boundary, ndef_bio}` where the authority's `asn1t.h.in:711-718`
   is `{out, ndef_bio, boundary}`, so the 12.3a callback corrupted the heap; fixed at 12.3c (D514).
5. **A lower-unit identity divergence was surfaced by a new caller and is recorded, not smoothed.**
   `EVP_MD_get_type`/`EVP_CIPHER_get_type` answer 0 on the candidate where the authority answers the
   NID, so the fetch-bearing PKCS#7 and CMS arms are `pending.` with the reason (D513,
   `courts/phase12/rt_pkcs7_probe.c:309-313`). §5 collects every arm the divergence reaches.
6. **A Phase-8 defect was surfaced by an `OSSL_ESS_*` caller and fixed at Phase 8's layer.**
   `EVP_MD_is_a` answered wrongly in `src/evp/`; the fix is in the owning unit rather than a
   workaround in Phase 12, and the authority-tier atlas re-derives byte-identically (D518).
7. **The OCSP exports are promotions, not re-implementations.** Sixteen of `ocsp.h`'s 94 are the
   internal `pub(crate)` transcriptions Phase 11 pulled forward for `X509_verify_cert`, now given
   their exported surface without the substrate moving a byte (D517, D506). This is D503's
   pull-forward rule closing its round trip.
8. **The two ENGINE-backed `TS_CONF_*` setters and `SRP_VBASE_init` are handed to Phase 13 rather
   than stubbed.** Their blockers are named with the authority file and line
   (`crypto/ts/ts_conf.c:171,188,192`; `crypto/srp/srp_vfy.c:423,504`) and the owning stratum, not
   merely counted (D520, D521, `forensics/phase12-obligations.json:13-31`).
9. **The plan's row 12.10 named the seal `docs/PHASE-12-CMS-SEAL.md`, and the seal is
   `docs/PHASE-12-PROTOCOL-FAMILIES-SEAL.md`.** The stratum is the whole protocol-family set rather
   than CMS alone, so the row is corrected to the document that exists and is registered in
   `forensics/tools/atlas_common.py`'s `SEAL_DOCS`.
10. **The activation partition in the plan's §1 is an activation measurement, and the ledger is the
    live record.** `docs/PHASE-12-SUBPHASES.md:66-72` reads 884 open at activation and 149 already
    implemented; the ledger reads `implemented` 1030, `deferred` 3, `open` 0 and the census reads the
    same (`docs/SEAL-CENSUS.md:40,400-407`). The plan's §1 itself says the split moves as the stratum
    lands its own units. A number inside an older decision entry is the value current when that entry
    was written and is not this document's count.
 11. **The FRF/Gemel chain entry landed after the seal was first written, and §7 and §8 record it.**
     The seal's first revision recorded items 6, 8 and 10 as owed; the chain entry added the ten
     declarations, ten receipts, twenty adjudicated challenges, the `sensitivity-backed` claim
     `574379772186cc3c71a2f174a9478f7e6e721fa18e0c1fa59a4723e8b3d726df` and the Gemel change `C98` /
     checkpoint `K51`, so the three items retired and `phase_state.py` derives `complete`. The
     correction is appended here for the reason item 1 gives.
