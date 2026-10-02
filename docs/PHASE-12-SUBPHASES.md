# Phase 12 — CMS, OCSP, CMP, CT, TS and the remaining families, as subphases

## 0. What this stratum is, and what it is not

Phase 12 is the container-and-protocol stratum: the signed, enveloped and encrypted container
formats and the certificate-status and protocol machinery built over Phase 11's X.509 objects —
`CMS` and its `PKCS7` predecessor, `OCSP`, `CMP` with `CRMF`, `TS`, `CT`, the S/MIME bridge that
carries them and the remaining `libcrypto` families the earlier strata left (`SRP`, `ESS`, the HTTP
client). Its name in `docs/RELEASE_GATES.md` §1 is "CMS / OCSP / CMP / CT / TS and remaining
libcrypto families", and `forensics/atlas/symbol-ownership.json` gives it every export declared in
`ts.h`, `ocsp.h`, `cmp.h`, `cms.h`, `pkcs7.h`, `crmf.h`, `ct.h`, `ess.h`, `srp.h`, `http.h` and
`cmp_util.h`, plus the `pem.h` spellings whose bodies are its units.

It is **not** the X.509 object graph the containers carry. The `X509`/`X509_REQ`/`X509_CRL`/
`X509_ACERT` items, the store and the verification engine are Phase 11's, and
`docs/PHASE-11-SUBPHASES.md` §0 already recorded the split: a `PKCS7` is a signed container, not an
X.509 object, and a plan that read "certificates" as "the things containing them" would claim a
stratum's work twice. Nor is it the ASN.1 substrate the containers are built from: the `ASN1_ITEM`
engine, the template macros and the DER/PEM encoder are Phase 5's, and the seven names Phase 5
handed here (`SMIME_read_ASN1`, `SMIME_read_ASN1_ex`, `SMIME_text`, `SMIME_write_ASN1`,
`SMIME_write_ASN1_ex`, `ASN1_ITEM_get`, `ASN1_ITEM_lookup`) can only be finished once the containers
they dispatch over exist. Nor is it the key objects the signed containers carry: `EVP_PKEY` and its
codecs are Phases 7, 8 and 10, and `CMS` reaches them as callers.

**Why this stratum is being planned while Phase 11 has sealed.** `forensics/tools/phase_state.py`'s
`REQUIRES` derives `requires(12) == (11,)`, and Phase 11 is `complete`. As with Phase 11, the
measurement finds that **149 of this stratum's atlas-owned exports were already `implemented`**
before its first subphase: the whole `ocsp_asn.c` item group, the six `ct_*` object units,
`pk7_asn1.c` with `pk7_lib.c` and `http_lib.c`'s `OSSL_parse_url`. They landed as substrate earlier
strata needed — the OCSP items for the Phase-11 verification path's `check_cert_ocsp_resp`, the
`PKCS7` items for the `PEM_X509_INFO_read` bundle reader — and what remains open (884 names) is the
container and protocol surface those landings did not cover. This document is that scope, measured.

## 1. The measurement this plan rests on

Every number below is read from `forensics/atlas/`, not typed, and
`forensics/phase12-obligations.json` is authoritative for the present.

**Phase 12's atlas-owned universe is 1,024 exports, all `libcrypto`, over twelve headers.** Reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 12`:

| header | exports | what it declares |
|---|---|---|
| `ts.h` | 184 | `TS_REQ`/`TS_RESP`/`TS_TST_INFO`/`TS_STATUS_INFO`/`TS_ACCURACY`, the timestamp authority context and the `TS_RESP_CTX_*` engine |
| `ocsp.h` | 169 | `OCSP_REQUEST`/`OCSP_RESPONSE`/`OCSP_BASICRESP`/`OCSP_SINGLERESP`/`OCSP_CERTID`, their extensions, printing and the client/server/verifier surface |
| `cmp.h` | 157 | the `OSSL_CMP_*` transaction surface: the ctx, message, PKI header/status/protection, general messages and the client/server engines |
| `cms.h` | 149 | `CMS_ContentInfo` and the `CMS_*` signed/enveloped/encrypted/digested-data surface |
| `pkcs7.h` | 118 | the `PKCS7` content types, their item groups, signing/enveloping and the S/MIME helpers |
| `crmf.h` | 92 | `OSSL_CRMF_CERTREQUEST`/`OSSL_CRMF_CERTREQMSG`, the controls and the `OSSL_CRMF_*` accessors |
| `ct.h` | 60 | `SCT`/`SCT_LIST`, the `CTLOG` and `CTLOG_STORE`, `CT_POLICY_EVAL_CTX` and the SCT printers |
| `ess.h` | 30 | the `ESS_SIGNING_CERT[_V2]`/`ESS_CERT_ID[_V2]` item groups and their accessors |
| `srp.h` | 29 | the SRP verifier database, the six-argument calculation surface and the TLS glue |
| `http.h` | 24 | the `OSSL_HTTP_*` client: the request context, the transfer and its error coordinates |
| `cmp_util.h` | 4 | the CMP utility helpers |
| `pem.h` | 4 | `PEM_read[_bio]_PKCS7`, `PEM_write[_bio]_PKCS7` |
| *(none)* | 4 | `PEM_read[_bio]_CMS`, `PEM_write[_bio]_CMS`, defined in `crypto/cms/cms_io.c` and recorded without a `declaring_header` |

**It also receives 9 hand-offs**, discovered from the other ledgers (`phase*-obligations.json` rows
whose `owning_phase` is 12) rather than listed here:

| from phase | count | header | what it is |
|---|---|---|---|
| 5 | 7 | `asn1.h` | `SMIME_read_ASN1`, `SMIME_read_ASN1_ex`, `SMIME_text`, `SMIME_write_ASN1`, `SMIME_write_ASN1_ex`, `ASN1_ITEM_get`, `ASN1_ITEM_lookup` |
| 11 | 2 | `x509.h` | `X509_load_http`, `X509_CRL_load_http` |

That is a working set of **1,033 exports**. **At activation, 149 of them were already implemented**
and `forensics/atlas/implemented-surface.json` is where each is read from. So `open_in_this_stratum`
opened at **884**, not 1,033. **That split moves as this stratum lands its own units: the ledger's
`counts` is the live record and this section is the activation measurement.** The 149 are the whole
of `crypto/ocsp/ocsp_asn.c` (75), the CT units `ct_sct.c`/`ct_log.c`/`ct_policy.c`/`ct_oct.c`/
`ct_b64.c`/`ct_prn.c` (59), `crypto/pkcs7/pk7_asn1.c` with `pk7_lib.c` (14) and
`crypto/http/http_lib.c`'s `OSSL_parse_url` (1).

**Open, by declaring header** (`forensics/phase12-obligations.json`'s `open` rows, counted from
their own `declaring_header`):

| header | open |
|---|---|
| `ts.h` | 184 |
| `cmp.h` | 157 |
| `cms.h` | 149 |
| `pkcs7.h` | 104 |
| `ocsp.h` | 94 |
| `crmf.h` | 92 |
| `ess.h` | 30 |
| `srp.h` | 29 |
| `http.h` | 23 |
| `cmp_util.h` | 4 |
| `pem.h` | 4 |
| `ct.h` | 1 |
| `asn1.h` | 7 |
| `x509.h` | 2 |
| *(none)* | 4 |

The `asn1.h` 7 and `x509.h` 2 are the hand-offs, declared in another stratum's header; the `pem.h`
4 are the `PKCS7` PEM spellings, and the four with no `declaring_header` are the `PEM_*_CMS`
readers. The atlas projection's own open subset is 875; the 9 hand-offs make up the difference.

**The 1,033 symbols are defined by 67 authority translation units**
(`forensics/atlas/export-defining-units.json`), under `crypto/cms/`, `crypto/cmp/`, `crypto/ts/`,
`crypto/ocsp/`, `crypto/pkcs7/`, `crypto/crmf/`, `crypto/ess/`, `crypto/srp/`, `crypto/ct/`,
`crypto/http/` and `crypto/pem/`, with five that live in `crypto/asn1/` and `crypto/x509/`
(`asn_mime.c`, `asn1_item_list.c`, `x_all.c`) because the hand-offs are declared there. **Sixty-one
of those units still have open symbols**, and they are the whole of §2's work: `cmp_ctx.c` (61
open), `cmp_asn.c` (53), `crmf_asn.c` (50), `ts_asn1.c` (47), `ocsp_ext.c` (44), `pk7_asn1.c` (43),
`ts_rsp_utils.c` (43), `crmf_lib.c` (40), `ess_asn1.c` (27), `cms_smime.c` (25), `ts_req_utils.c`
(24), `ts_rsp_sign.c` (23), `cms_lib.c` (22), `http_client.c` (21), and fifty narrower units.

**Phase 12 owns no provider registration row**, and that is a measurement rather than an omission:
`forensics/atlas/provider-algorithms.json` records rows for owning phases 8, 9, 10 and 13 only (996
rows, 636/306/39/15), so the phase-12 slice of that census is empty and
`forensics/phase12-obligations.json`'s `provider_rows_owned` is `0`. Every container, OCSP, CMP, TS
and CT name is an `libcrypto` export reached through a caller, not a dispatch-table row an
`OSSL_ALGORITHM` array publishes.

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 12.0 | **The plan and the census** | `docs/PHASE-12-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase12-obligations.json`) and its generator land with it. **The runner and the reference-basis probe land with it too, and §4.3 is why they cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner and `court_coverage.py` refuses the inherited `implemented` exports until a reference probe covers them, and neither can be satisfied by a later subphase without leaving the pipeline red in between. | 11 | — |
| 12.1 | **The HTTP client** | `http_client.c` (21), `http_lib.c` (2): the `OSSL_HTTP_REQ_CTX_*` request context and its BIO, the `OSSL_HTTP_transfer`/`OSSL_HTTP_get`/`OSSL_HTTP_post` entry points, the per-request header and redirection surface and `OSSL_HTTP_parse_url`/`OSSL_parse_url`'s remaining companions. **23 open rows over 2 units.** | 12.0 | `RT-HTTP` |
| 12.2 | **The PKCS#7 remainder** | `pk7_asn1.c` (43), `pk7_lib.c` (19), `pk7_doit.c` (16), `pk7_smime.c` (9), `pk7_attr.c` (6), `pk7_mime.c` (5), `bio_pk7.c` (1) and `pem_all.c` (4: `PEM_read[_bio]_PKCS7`, `PEM_write[_bio]_PKCS7`): the `PKCS7` item groups, the sign/verify/encrypt/decrypt chain, the attribute stack and the S/MIME writer. **103 open rows over 8 units.** | 12.0 | `RT-PKCS7` |
| 12.3 | **The CMS container** | `cms_smime.c` (25), `cms_lib.c` (22), `cms_att.c` (20), `cms_env.c` (20), `cms_sd.c` (19), `cms_io.c` (13), `cms_kari.c` (10), `cms_ess.c` (9), `cms_asn1.c` (7), `cms_kemri.c` (5), `cms_pwri.c` (2), `cms_enc.c` (1): `CMS_ContentInfo` and the `CMS_*` signed, enveloped, encrypted, digested and authenticated-enveloped surface, the recipient-info and signer-info engines, the KARI/KEMRI key agreement and the `PEM_*_CMS` container readers. **153 open rows over 12 units** — the largest subphase, and the stratum's namesake. | 12.1, 12.2 | `RT-CMS` |
| 12.4 | **CMP** | `cmp_ctx.c` (61), `cmp_asn.c` (53), `cmp_msg.c` (13), `cmp_server.c` (12), `cmp_client.c` (5), `cmp_genm.c` (4), `cmp_util.c` (4), `cmp_hdr.c` (3), `cmp_status.c` (3), `cmp_vfy.c` (2), `cmp_http.c` (1): the `OSSL_CMP_CTX` and its accessors, the message and PKI header/status/protection item groups, the general-message engine, the client and server state machines and the HTTP transport arm. **161 open rows over 11 units.** | 12.1, 12.3 | `RT-CMP` |
| 12.5 | **Timestamping** | `ts_asn1.c` (47), `ts_rsp_utils.c` (43), `ts_req_utils.c` (24), `ts_rsp_sign.c` (23), `ts_conf.c` (20), `ts_verify_ctx.c` (15), `ts_lib.c` (5), `ts_rsp_print.c` (3), `ts_rsp_verify.c` (3), `ts_req_print.c` (1): the `TS_REQ`/`TS_RESP`/`TS_TST_INFO` item groups, the `TS_RESP_CTX_*` authority engine, the response signing and verification and the `CONF`-driven configuration reader. **184 open rows over 10 units** — the whole of `ts.h`'s open 184. | 12.3 | `RT-TS` |
| 12.6 | **OCSP** | `ocsp_ext.c` (44), `ocsp_cl.c` (20), `ocsp_srv.c` (15), `ocsp_lib.c` (5), `ocsp_prn.c` (5), `ocsp_vfy.c` (3), `ocsp_http.c` (2): the OCSP extension engine, the request/response sign-and-send surface, the responder server state machine, the response verifier and the HTTP transport arm. **94 open rows over 7 units** — the whole of `ocsp.h`'s open 94. | 12.1, 12.3 | `RT-OCSP` |
| 12.7 | **CRMF and ESS** | `crmf_asn.c` (50), `crmf_lib.c` (40), `crmf_pbm.c` (2), `ess_asn1.c` (27), `ess_lib.c` (3): the `OSSL_CRMF_*` certificate-request item groups, controls and accessors, and the `ESS_SIGNING_CERT`/`ESS_CERT_ID` item groups CMP and CMS both reach. **122 open rows over 5 units** — the whole of `crmf.h`'s open 92 and `ess.h`'s open 30. | 12.4 | `RT-CRMF`; `RT-ESS` |
| 12.8 | **SRP** | `srp_vfy.c` (15), `srp_lib.c` (14): the SRP verifier database (`SRP_VBASE_*`), the `SRP_user_pwd_*` record and the `SRP_Calc_*`/`SRP_create_verifier_*` calculation surface. **29 open rows over 2 units** — the whole of `srp.h`'s open 29. | 12.0 | `RT-SRP` |
| 12.9 | **The CT remainder, the shared dispatch and the hand-offs** | `ct_log.c` (1: `CTLOG_STORE_load_default_file`), the shared `x_all.c` dispatch (5: `PKCS7_ISSUER_AND_SERIAL_digest`, `d2i_PKCS7_bio`/`_fp`, `i2d_PKCS7_bio`/`_fp`) and the 9 hand-offs (`asn_mime.c` 5, `asn1_item_list.c` 2, `x_all.c` 2). **15 open rows over 6 units.** The units are the ones whose closure crosses into the strata above; each is "to be measured at its slice", as §2 of `docs/PHASE-10-SUBPHASES.md` measured its own remainder. | 12.1–12.8 | `RT-CMS-REMAINDER` |
| 12.10 | **The seal** | nothing in the crate — evidence: `docs/PHASE-12-CMS-SEAL.md` | 12.0–12.9 | — |

The nine rows above the seal partition the 884 open exports exactly, by defining unit: 23 + 103 +
153 + 161 + 184 + 94 + 122 + 29 + 15 = 884 (the activation partition, which moves as subphases
land), and the 61 open units each appear in exactly one row. The partition is derived from
`forensics/atlas/export-defining-units.json` joined to the ledger's `open` list, not typed.

**2.1 The order, and the dependency it rests on.** 12.1 before 12.3 and 12.6 because the CMS
S/MIME writer and the OCSP client both reach the HTTP transport for their fetch and post arms, and
12.1 is that transport. 12.2 before 12.3 because `cms_smime.c`'s writer emits a `PKCS7`-shaped
message when it is asked for the older format, so the container surface it delegates to must exist.
12.4 before 12.7 because CMP's message engine carries `OSSL_CRMF` certificate requests. 12.3 before
12.5 and 12.6 because a timestamp token's and an OCSP response's signed body are both built with the
CMS signer-infrastructure, and 12.3's `cms_sd.c` is where it lives. 12.8 and 12.9 are independent
of the container chain; 12.9's shared units land last because their closure crosses into every
stratum above.

**The measurement that ordering rests on is unit-level, and it is honest about what it cannot
settle.** The 67 units' own internal call graph (which open `cms_lib.c` helper each open
`cms_sd.c` entry needs, and in what order) is measured at each slice, the way D442 and D444 were. A
slice that discovers its unit is somewhere else records that rather than forcing the row (§5).

## 3. What each subphase must honour

**3.1 A container's identity is a DER document, and its bytes are the contract.** The `CMS`,
`PKCS7`, `OCSP`, `TS` and `CRMF` item groups are ASN.1 templates, so a transcription's output is
comparable byte for byte against the authority's: the `SignedData`'s field order, the
`SignerInfo`'s signed-attribute set and each `eContent`'s inner DER. The differential courts compare
the container bytes rather than a parsed structure, and the print surface (`cms_io.c`'s
`CMS_ContentInfo_print_ctx`, `ocsp_prn.c`, `ts_req_print.c`, `ts_rsp_print.c`) is compared line for
line, because the authority's text has a fixed shape.

**3.2 OCSP and TS answer a decision, and the error is part of it.** `OCSP_basic_verify`,
`OCSP_check_validity`, `TS_RESP_verify_response` and `TS_RESP_verify_token` are not predicates: each
returns an integer and leaves a status on its context. Two implementations can both refuse a
response and be different libraries, so the court compares the *decision*, the *status* and the
error coordinate. The `OCSP_response_status`/`OCSP_resp_find_status` read path and the
`TS_STATUS_INFO`/`TS_VERIFY_CTX` surface are the second half, and their enumerated values are read
from the authority rather than typed.

**3.3 CMP is a transaction, and the transcript is observable.** `OSSL_CMP_CTX_new` and the
`OSSL_CMP_*` engine drive a request/response exchange whose observable is the sequence of messages
and the protection they carry. A differential court can compare the DER of each `OSSL_CMP_MSG`, the
`OSSL_CMP_PKISI` status and the `OSSL_CMP_CTX` error code after a refused or rejected transaction.
The `OSSL_CMP_MSG_*`/`OSSL_CMP_PKIHEADER_*` item groups are the container half and are compared as
§3.1 requires.

**3.4 The S/MIME bridge is a byte codec with an error coordinate.** `SMIME_read_ASN1`,
`SMIME_write_ASN1` and `SMIME_text` produce and consume MIME text, so their evidence is the exact
encoding of a fixed message and the error queue and coordinate for each malformed-input arm. The
reader is the subtle one: it classifies a body into a `CMS` or `PKCS7` object by its Content-Type,
and a probe that only reads one would measure half of it; the classification of each arm is printed
as `pending.` with its blocker rather than driven where the container is not yet landed.

**3.5 Nothing here is a parity claim about a container's meaning.** A transcription that parses
the authority's bytes for a container this crate can build has not been shown to parse every
container, and §3.2's decision is only as good as the responses a court can construct. The measured
surface is the one above, and a name that cannot be driven is named as `pending` rather than counted
as passing — the contract Phase 8's `PENDING_CORRECTNESS_COURTS` and every later activation
established.

## 4. Measured corrections, and the precondition

**4.1 The inherited 149 are this stratum's, and the atlas assignment is the reason.** The whole of
`ocsp_asn.c` and the CT item groups are declared in `ocsp.h` and `ct.h`, which
`forensics/atlas/symbol-ownership.json` assigns to phase 12 and to no other; `pk7_asn1.c` is
`pkcs7.h`'s; and `OSSL_parse_url` is `http.h`'s. They were landed by Phase 10's pulled-forward
`OSSL_STORE` arm and Phase 11's verification substrate rather than by this stratum, and
`docs/PHASE-11-SUBPHASES.md` §3.4 names the `PKCS7` arm those landings owed here. This plan does not
re-open the assignment; it depends on it, because 149 of the working set is those names.

**4.2 This stratum owns no provider row, and the ledger says so rather than leaving it implied.**
Reading `forensics/atlas/provider-algorithms.json` for `owning_phase == 12` yields the empty set —
the census's rows belong to phases 8, 9, 10 and 13 — so `phase_state.py`'s provider-row rule and
`provider_court_coverage.py` have nothing to hold against this stratum, and
`forensics/phase12-obligations.json` carries `provider_rows_owned: 0`. A reader who expected a
container stratum to publish dispatch rows would otherwise have to infer the zero from the census.

**4.3 The precondition this plan places on 12.0, and it is not optional.** Two fail-closed joiners
refuse this stratum's activation as specified, and both are measured rather than argued:

* `run_courts.py` refuses a stratum that is not `not-started` and has no runner: "phase 12
  (in-progress) is not `not-started` and has no runner". Phase 11 satisfied this by landing
  `forensics/tools/phase11_courts.py` in the same commit; this stratum must land
  `forensics/tools/phase12_courts.py`, whose only runnable court until 12.1 is the reference basis.
* `court_coverage.py` refuses the inherited `implemented` exports: "`N` implemented export(s) of a
  stratum that has begun is in none of directly-courted, indirectly-courted or non-observable".
  **The 149 inherited exports are the number at activation**, and the ledger's landing is what moved
  them into scope, so the commit that lands it also lands a phase-12 reference-basis probe that
  references them by name, registered in `court-coverage-rows.json`'s `reference_probes` as
  `RT-RUNTIME-REF`, `RT-BIO-CONF-REF`, `RT-BN-ASN1-REF`, `RT-PROVIDER-REF`, `RT-EVP-REF`,
  `RT-KEYFORMAT-REF` and `RT-X509-REF` are for theirs. The probe references; it does not call, and
  the atlas records every name covered only by it at basis `referenced`, never `called`.

So the activation order is: the ledger, the plan, the runner and the reference probe land
**together**, or `forensics/tools/pipeline.sh` fails at `run_courts.py` and `court_coverage.py` and
the tree carries an activation whose two evidence joiners refuse it. This document states the
precondition; the runner is `forensics/tools/phase12_courts.py` and the probe is
`courts/phase12/rt_coverage_ref_probe.c`, and both are `courts/`-side work rather than this plan's
files.

**4.4 "CMS/OCSP/CMP/CT/TS" here is the container and protocol surface, not the objects or keys it
carries.** `docs/PHASE-11-SUBPHASES.md` §4.4 already recorded the split for the X.509 objects
("the `PKCS7` reads `PEM_X509_INFO_read` performs ... are *callers* of this stratum's objects, not
part of it"); measured, `forensics/atlas/symbol-ownership.json` assigns 118 `pkcs7.h` exports and
the whole of `cms.h`/`ocsp.h`/`cmp.h`/`ts.h`/`ct.h` to phase 12, and every one of the container
items reaches `EVP_PKEY` through a caller. The `X509` a `CMS` signature verifies against is Phase
11's; the key that signs it is Phase 8's.

## 5. Process

This stratum inherits Phases 8 through 11's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every export carries a court edge in
`forensics/atlas/court-coverage.json` on the commit that lands it (D236) — **and §4.3 is the
measurement of what that rule means for a stratum whose exports were landed by an earlier one**;
every provider row it publishes is named by a probe of a court that covers it (D245), though this
stratum publishes none; and an artefact that a source change moves is regenerated in the same
commit. `docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the census's, and the census will correct them.** The subphase
table above was written from the defining units in `forensics/atlas/export-defining-units.json` and
the 884-row measurement in §1. D283's equivalent table for Phase 8 was corrected twice by
measurement — by D285, which found most of a slice was another stratum's, and by D287, which found a
prerequisite the slice's name could not show — and Phase 10's and 11's were each corrected inside
their own activation. The same is expected here and is not a defect in this document: the census is
the authority, and a subphase that discovers its unit is somewhere else records that rather than
forcing the row.

**Landed exports (checked against the ledger):**

The pre-activation slices below are not this stratum's own; every name in them is a landing
that the ledger's implemented list already carried *before* 12.1, and the ledger is the record. The
whole `ocsp_asn.c` item group is in: `OCSP_REQUEST_new`, `OCSP_RESPONSE_it`, `d2i_OCSP_BASICRESP`,
`i2d_OCSP_SINGLERESP`, `d2i_OCSP_CERTID`, `OCSP_CERTSTATUS_free`, `OCSP_CRLID_it`,
`OCSP_ONEREQ_new`, `d2i_OCSP_REQINFO`, `OCSP_RESPBYTES_new`, `OCSP_RESPDATA_it`,
`OCSP_RESPID_free`, `d2i_OCSP_REVOKEDINFO`, `OCSP_SERVICELOC_new` and `d2i_OCSP_SIGNATURE`. The CT
units `ct_sct.c`, `ct_log.c`, `ct_policy.c`, `ct_oct.c`, `ct_b64.c` and `ct_prn.c` contribute
`SCT_new`, `SCT_validate`, `SCT_set1_log_id`, `SCT_print`, `o2i_SCT`, `i2o_SCT`, `i2d_SCT_LIST`,
`d2i_SCT_LIST`, `SCT_LIST_validate`, `SCT_LIST_print`, `SCT_free`, `CTLOG_new`, `CTLOG_STORE_new`,
`CTLOG_STORE_get0_log_by_id`, `CTLOG_new_from_base64`, `CTLOG_get0_public_key`,
`CT_POLICY_EVAL_CTX_new`, `CT_POLICY_EVAL_CTX_get0_cert` and `CT_POLICY_EVAL_CTX_set_time`.
`pk7_asn1.c` with `pk7_lib.c` contributes `PKCS7_new`, `PKCS7_it`, `PKCS7_set_type`,
`PKCS7_DIGEST_new`, `PKCS7_ENCRYPT_it` and `PKCS7_ENC_CONTENT_new`; `http_lib.c` contributes
`OSSL_parse_url`. The bulk of that list was landed before this stratum's first slice by Phase 10's
pulled-forward STORE arm and Phase 11's verification substrate; the ledger is the record and this
sentence names only what those landings left here. Subphase 12.1 lands this stratum's own first
slice. `crypto/http/http_client.c`'s whole surface is
in: `OSSL_HTTP_REQ_CTX_new`, `OSSL_HTTP_REQ_CTX_free`, `OSSL_HTTP_REQ_CTX_get0_mem_bio`,
`OSSL_HTTP_REQ_CTX_get_resp_len`, `OSSL_HTTP_REQ_CTX_set_max_response_length`,
`OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines`, `OSSL_HTTP_REQ_CTX_set_request_line`,
`OSSL_HTTP_REQ_CTX_add1_header`, `OSSL_HTTP_REQ_CTX_set_expected`, `OSSL_HTTP_REQ_CTX_set1_req`,
`OSSL_HTTP_REQ_CTX_nbio`, `OSSL_HTTP_REQ_CTX_nbio_d2i`, `OSSL_HTTP_REQ_CTX_exchange`,
`OSSL_HTTP_is_alive`, `OSSL_HTTP_open`, `OSSL_HTTP_set1_request`, `OSSL_HTTP_exchange`,
`OSSL_HTTP_get`, `OSSL_HTTP_transfer`, `OSSL_HTTP_close` and `OSSL_HTTP_proxy_connect` -- and
`http_lib.c`'s remaining two `http.h` names, `OSSL_HTTP_parse_url` and `OSSL_HTTP_adapt_proxy`,
land with it. Every one of the 23 is now implemented rather than open; `RT-HTTP`
(`courts/phase12/rt_http_probe.c`) drives them.

Subphase 12.2 lands the PKCS#7 remainder: `pk7_asn1.c`'s other three `ANY DEFINED BY` arms
(`signed`, `enveloped`, `signedAndEnveloped`) and the streaming callback's four arms, the whole of
`pk7_lib.c` (`PKCS7_add_signer`/`add_certificate`/`add_recipient`, `PKCS7_set_cipher`,
`PKCS7_stream` and the rest), and the new units `pk7_doit.c`, `pk7_attr.c`, `pk7_smime.c`,
`pk7_mime.c` and `bio_pk7.c`, together with `pem_all.c`'s four
`PEM_read[_bio]_PKCS7`/`PEM_write[_bio]_PKCS7`. Every one of the 103 is now implemented rather
than open; `RT-PKCS7` (`courts/phase12/rt_pkcs7_probe.c`) drives them from fixed DER fixtures.

Subphase 12.3 opens the CMS container and has landed, so far, its object model and item groups:
`cms_asn1.c`'s `CMS_ContentInfo_it`, `CMS_EnvelopedData_it`/`_dup`, `CMS_ReceiptRequest_it`,
`CMS_SharedInfo_encode` and `CMS_SignedData_new`/`_free`; the whole of `cms_lib.c`
(`CMS_ContentInfo_new`/`_new_ex`/`_free`/`_print_ctx`, `d2i_CMS_ContentInfo`/`i2d_CMS_ContentInfo`,
the `CMS_get0_*`/`CMS_get1_*`/`CMS_is_detached`/`CMS_set_detached`/`CMS_set1_eContentType`
accessors, the certificate and CRL choice builders and `CMS_dataInit`/`CMS_dataFinal`); the whole
of `cms_att.c` (the twenty `CMS_{signed,unsigned}_*` attribute exports); `cms_io.c`'s `CMS_stream`;
and `cms_enc.c`'s `CMS_EncryptedData_set1_key`. That is **107 of the 153 open rows**. The S/MIME
entry points (`cms_smime.c`), the receipt surface (`cms_ess.c`) and the `PEM_*_CMS` readers
(`cms_io.c`) still open here and are this subphase's remaining pass; the forty-six CMS
rows that remain open are recorded in the ledger. `RT-CMS` (`courts/phase12/rt_cms_probe.c`) drives the
landed surface over the fixed DER fixtures `courts/phase12/rt_cms_der.h` embeds: the decode/encode
round trip, the accessors, the certificate/CRL choices, `CMS_stream`, the `data` container's
init/final cycle, `CMS_SharedInfo_encode` and the `CMS_EncryptedData_set1_key` refusal arms. The
twenty attribute exports are referenced and driven only through the accessor that reaches a
`CMS_SignerInfo`, which is part of the remaining pass, so their behaviour is named `pending` in the
probe rather than hidden.

Subphase 12.3b lands the signer and recipient engines in full: `cms_sd.c`'s `CMS_get0_SignerInfos`, `CMS_get0_signers`, `CMS_SignerInfo_get0_algs`/`_get0_md_ctx`/`_get0_pkey_ctx`/`_get0_signature`/`_get0_signer_id`/`_set1_signer_cert`/`_cert_cmp`/`_sign`/`_verify`/`_verify_content`, `CMS_SignedData_init`/`_verify`, `CMS_add1_signer`, `CMS_add_smimecap`, `CMS_add_simple_smimecap`, `CMS_add_standard_smimecap` and `CMS_set1_signers_certs`; `cms_env.c`'s `CMS_get0_RecipientInfos`, `CMS_RecipientInfo_type`/`_get0_pkey_ctx`/`_ktri_get0_algs`/`_ktri_get0_signer_id`/`_ktri_cert_cmp`/`_set0_pkey`/`_kekri_id_cmp`/`_kekri_get0_id`/`_set0_key`/`_decrypt`/`_encrypt`, `CMS_add0_recipient_key`/`_add0_recipient_password`/`_add1_recipient`/`_add1_recipient_cert` and `CMS_EnvelopedData_create`/`_create_ex`/`_decrypt` and `CMS_AuthEnvelopedData_create`/`_create_ex`; `cms_kari.c`'s key-agreement surface (`CMS_RecipientInfo_kari_get0_alg`/`_get0_reks`/`_get0_orig_id`/`_orig_id_cmp`/`_get0_ctx`/`_set0_pkey`/`_set0_pkey_and_peer`/`_decrypt` and `CMS_RecipientEncryptedKey_get0_id`/`_cert_cmp`); `cms_kemri.c`'s `CMS_RecipientInfo_kemri_cert_cmp`/`_get0_ctx`/`_get0_kdf_alg`/`_set0_pkey`/`_set_ukm`; and `cms_pwri.c`'s `CMS_RecipientInfo_set0_password` and `CMS_add0_recipient_password`. Every one of the 106 further CMS rows is now implemented rather than open; `RT-CMS` drives the signer/recipient surface over the same fixed DER fixtures.

**Open exports (checked against the ledger):**

Open is the 651-name remainder, and it is the whole of the container and protocol surface 12.2's
PKCS#7 landing left. CMS opens 12.3 with `CMS_sign`, `CMS_verify`, `CMS_EncryptedData_encrypt`
and `PEM_read_CMS`. CMP opens 12.4 with `OSSL_CMP_ATAV_create`,
`OSSL_CMP_ATAVS_new` and `OSSL_CMP_ATAVS_free`. TS opens 12.5 with `TS_REQ_new`, `TS_RESP_CTX_new`
and `TS_RESP_create_response`. OCSP opens 12.6 with `OCSP_request_sign`, `OCSP_basic_verify`,
`OCSP_response_status`, `OCSP_cert_to_id`, `OCSP_check_validity` and `OCSP_resp_count`. CRMF opens
12.7 with `OSSL_CRMF_CERTID_gen` and `OSSL_CRMF_CERTID_get0_issuer`, and ESS with `ESS_CERT_ID_new`,
`ESS_SIGNING_CERT_new` and `ESS_ISSUER_SERIAL_free`. SRP opens 12.8 with `SRP_create_verifier`,
`SRP_user_pwd_new`, `SRP_VBASE_new` and `SRP_Calc_A`. 12.9 opens the CT remainder with
`CTLOG_STORE_load_default_file`, the shared `x_all.c` dispatch with `d2i_PKCS7_bio` and
`PKCS7_ISSUER_AND_SERIAL_digest`, and the nine hand-offs with `SMIME_read_ASN1`, `SMIME_write_ASN1`,
`ASN1_ITEM_get` and `X509_load_http`. A stratum is complete only when no export it owns is neither
implemented nor handed on, and this is not that state yet — the seal is 12.10's.
