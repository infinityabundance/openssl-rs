# Phase 11 — X.509 and verification, as subphases

## 0. What this stratum is, and what it is not

Phase 11 is the X.509 stratum: the certificate, certificate-request, CRL and attribute-certificate
object graphs and the machinery that builds, parses, prints and **verifies** them — `X509` and its
`X509_STORE`/`X509_LOOKUP`/`X509_OBJECT` layers, `X509_REQ`, `X509_CRL`, `X509_ACERT`,
`X509_VERIFY_PARAM`, the `X509_POLICY_*` tree, the `X509V3_EXT_*` method engine and its
configuration reader, and the `PEM_*_X509*` container readers and writers around them. Its name in
`docs/RELEASE_GATES.md` §1 is "X.509 + verification", and `forensics/atlas/symbol-ownership.json`
gives it every export declared in `x509.h`, `x509v3.h`, `x509_vfy.h` and `x509_acert.h`, plus the
X.509-specific `pem.h` spellings.

It is **not** the ASN.1 substrate the objects are built from. The `ASN1_ITEM` engine, the template
macros and the DER/PEM encoder are Phase 5's; `x_algor.c`'s `X509_ALGOR` and the `X509_PUBKEY`
carrier landed there and here only as objects Phase 8 needed. Nor is it the key objects a
certificate names: `EVP_PKEY`, its provider keymgmt and every `d2i_*`/`i2d_*` codec are Phases 7,
8 and 10, and the `X509_PUBKEY` surface this stratum finishes is the *carrier*, not the key.

Nor is it the container families that carry certificates. `forensics/atlas/symbol-ownership.json`
assigns all of `pkcs7.h`, `cms.h`, `ocsp.h`, `ts.h` and `ct.h` to Phase 12, and `pkcs7.h`'s 118
exports are the worked example: a `PKCS7` is a signed container, not an X.509 object, and a plan
that read "certificates" as "the things containing them" would claim a stratum's work twice.

**Why this stratum is being planned while Phase 10 has sealed.** Phase 10's plan §6 pulled a
"first slice" of the certificate graph forward — 10.8 through 10.16 — because its own blocked rows
(`PKCS12_add_cert`, `PKCS12_parse`, the `OSSL_STORE` CERT/CRL arms) reach `X509_it`, `X509_free`,
`X509_digest` and `X509_check_private_key`, and no Phase 10 row could land without them. The result
is that **952 of this stratum's atlas-owned exports were already `implemented`** before its first
subphase, and the 513 open names are what those landings did *not* cover: the store, the
verification engine, the attribute certificate, the request and mutator surface, the `v3`
functions and the PEM X.509 containers. This document is that scope, measured.

## 1. The measurement this plan rests on

Every number below is read from `forensics/atlas/`, not typed, and
`forensics/phase11-obligations.json` is authoritative for the present.

**Phase 11's atlas-owned universe is 1,455 exports, all `libcrypto`, over five headers.** Reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 11`:

| header | exports | what it declares |
|---|---|---|
| `x509.h` | 548 | `X509`/`X509_CINF`/`X509_EXTENSION`/`X509_VAL`, `X509_REQ`, `X509_CRL`, `X509_ALGOR`, `X509_ATTRIBUTE`, the `X509_*` public API and the `PBEPARAM`/`PKCS8_PRIV_KEY_INFO` glue |
| `x509v3.h` | 511 | the `X509V3_EXT_METHOD` engine, `X509V3_CTX`, the `GENERAL_NAME`/`BASIC_CONSTRAINTS`/`AUTHORITY_KEYID`/`NAME_CONSTRAINTS`/policy items and `X509V3_EXT_nconf` |
| `x509_vfy.h` | 241 | `X509_STORE`, `X509_LOOKUP`, `X509_OBJECT`, `X509_VERIFY_PARAM`, `X509_STORE_CTX` and `X509_verify_cert` |
| `x509_acert.h` | 103 | `X509_ACERT`, its issuer/serial/target/holder/attribute/extension accessors and `X509_ACERT_verify` |
| `pem.h` | 52 | `PEM_read[_bio]_X509*`, `PEM_write[_bio]_X509*`, `PEM_X509_INFO_*` and the `PEM_*_X509_REQ` spellings |

**It also receives 12 hand-offs**, discovered from the other ledgers (`phase*-obligations.json`
rows whose `owning_phase` is 11) rather than listed here:

| from phase | count | header | what it is |
|---|---|---|---|
| 5 | 10 | `asn1.h` (3), `pem.h` (7) | `ASN1_add_stable_module`, `ASN1_generate_nconf`/`ASN1_generate_v3`, the five `PEM_X509_INFO_*` readers and writer, `PEM_write[_bio]_X509_REQ_NEW` |
| 7 | 2 | `evp.h` | `EVP_CIPHER_CTX_get_algor`, `EVP_PKEY_CTX_get_algor` |

That is a working set of **1,467 exports**. **At activation, 954 of them were already
implemented** — 952 atlas-owned exports and 2 hand-offs — and
`forensics/atlas/implemented-surface.json` is where each is read from. So `open_in_this_stratum`
opened at **513**, not 1,467. **That split moves as this stratum lands its own units: the ledger's
`counts` is the live record and this section is the activation measurement.** The 952 were landed
by two earlier strata, not by this one: Phase 8's
8.8 chain (`crypto/evp/ameth_lib.c`, `crypto/asn1/{x_algor,x_spki,t_spki}.c`, the `pem.h` key
readers) and Phase 10's pulled-forward X.509 subphases 10.8–10.16 (`docs/PHASE-10-SUBPHASES.md`
§6–§7, D442–D451), which transcribed `x_x509.c`, `x_name.c`, `x_exten.c`, `x_val.c`, `x_pubkey.c`,
`x509_cmp.c`, `x509_v3.c`, `x509_ext.c`, `x509_obj.c`, `x509_txt.c`, `x509_autofree.c`'s siblings,
the leaf `v3_*` items and `x_all.c`'s first half. The two hand-offs
(`ASN1_generate_nconf`, `ASN1_generate_v3`) were landed in Phase 5's `crypto/asn1/asn1_gen.c`.

**Open, by declaring header** (`forensics/phase11-obligations.json`'s `open` rows, counted from
their own `declaring_header`):

| header | open |
|---|---|
| `x509_vfy.h` | 225 |
| `x509.h` | 122 |
| `x509_acert.h` | 83 |
| `pem.h` | 54 |
| `x509v3.h` | 26 |
| `asn1.h` | 1 |
| `evp.h` | 2 |

The `pem.h` 54 is 47 from the atlas projection plus the 7 `PEM_*` hand-offs; the `asn1.h` 1 is
`ASN1_add_stable_module`; the `evp.h` 2 are the `EVP_*_CTX_get_algor` hand-offs. The atlas
projection's own open subset (503) reads `x509_vfy.h` 225, `x509.h` 122, `x509_acert.h` 83,
`pem.h` 47, `x509v3.h` 26; the 10 hand-offs make up the difference.

**The 1,467 symbols are defined by 108 authority translation units**
(`forensics/atlas/export-defining-units.json`), all but one under `crypto/x509/` (the exceptions
are `crypto/asn1/`, `crypto/pem/`, `crypto/evp/` and `crypto/pkcs12/p12_mutl.c`). **Forty-four of
those units still have open symbols**, and they are the whole of §2's work: `x509_lu.c` (73 open),
`x509_vfy.c` (70), `x509_acert.c` (48), `x509_vpm.c` (39), `pem_all.c` (33), `x509_req.c` (24),
`x509_meth.c` (20), `x_all.c` (18), `x509_set.c` (16), `x_ietfatt.c` (14), `x_req.c` (14),
`x509aset.c` (12), `v3_conf.c` (11), `x509_trust.c` (11), and thirty narrower units.

**Phase 11 owns no provider registration row**, and that is a measurement rather than an omission:
`forensics/atlas/provider-algorithms.json` records rows for owning phases 8, 9, 10 and 13 only (996
rows, 636/306/39/15), so the phase-11 slice of that census is empty and
`forensics/phase11-obligations.json`'s `provider_rows_owned` is `0`. Every X.509 name is an
`libcrypto` export reached through a caller, not a dispatch-table row an `OSSL_ALGORITHM` array
publishes.

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 11.0 | **The plan and the census** | `docs/PHASE-11-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase11-obligations.json`) and its generator land with it. **The runner and the reference-basis probe land with it too, and §4.3 is why they cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner and `court_coverage.py` refuses the inherited `implemented` exports until a reference probe covers them, and neither can be satisfied by a later subphase without leaving the pipeline red in between. | 8.8; 10.8–10.16 | — |
| 11.1 | **The `X509_STORE` and the lookup layer** | `x509_lu.c` (73 exports), `x509_meth.c` (20), `x509_trust.c` (11), `x509_d2.c` (9), `by_file.c` (6), `by_dir.c` (1), `by_store.c` (1): the `X509_STORE` object and its registry, the four `X509_LOOKUP_METHOD`s and their file/`dir`/store implementations, `X509_OBJECT` and the `X509_STORE_get_by_subject` read path, and the trust/reject helpers. **121 open rows over 7 units, 2,555 authority lines.** | 11.0 | `RT-X509-STORE` |
| 11.2 | **The verification engine** | `x509_vfy.c` (70), `x509_vpm.c` (39), `pcy_tree.c` (2): `X509_verify_cert`, the `X509_STORE_CTX` chain-building and check roll, the callback and error surface, `X509_VERIFY_PARAM`/`X509_VERIFY_PARAM_table` and the policy-tree construction. **111 open rows over 3 units, 5,358 authority lines** — the largest subphase, and the stratum's *purpose*: §3.2 is the decision procedure it must reproduce. **It depends on the Phase-22 X.509 closure slice, and that dependency is metered, not aspirational** (`forensics/tools/phase22_x509_gate.py`, `docs/PHASE-22-SUBPHASES.md` §8): a *new* export of these three units while the slice is unsatisfied fails the pipeline. The slice is satisfied when `forensics/atlas/phase22/compatibility-closure.json`'s `body.x509_slice.satisfied` is true, which 22.14 sets when no `UNKNOWN` residual intersects the X.509 roots. | 11.1; the Phase-22 X.509 closure slice | `RT-X509-VERIFY-SURFACE`; `RT-X509-VERIFY-ENGINE` (pending) |
| 11.3 | **The attribute certificate** | `x509_acert.c` (48), `x_ietfatt.c` (14), `x509aset.c` (12), `t_acert.c` (2): the `X509_ACERT`/`X509_ACERT_INFO` item group, its issuer/serial/target/holder/attribute/extension accessors and setters, the `X509_ACERT_verify` entry and the `x509_acert.h` print and `d2i_*`/`i2d_*` surface. **76 open rows over 4 units, 1,033 authority lines** — the whole of `x509_acert.h`'s open 83. | 11.1, 11.2 | `RT-X509-ACERT` |
| 11.4 | **The request, the CRL and the object mutators** | `x509_req.c` (24), `x509_set.c` (16), `x_req.c` (14), `x_crl.c` (9), `t_x509.c` (9), `t_req.c` (3), `t_crl.c` (3), `x_exten.c` (3), `x509_r2x.c` (1): `X509_REQ` and its ASN.1/print/lifecycle surface, the `X509_set_*`/`X509_CRL_set_*`/`X509_REQ_set_*` mutators, `X509_CRL`'s remaining arms, the extension accessors and `X509_to_X509_REQ`. **82 open rows over 9 units, 2,335 authority lines.** | 11.0 | `RT-X509-REQ` |
| 11.5 | **The `v3` function and configuration layer** | `v3_conf.c` (11), `v3_utl.c` (7), `v3_prn.c` (4), `v3_addr.c` (2), `v3_asid.c` (2): `X509V3_EXT_nconf(_file)` and the `v3_conf.c` name-resolution engine, the `X509V3_EXT_*` helpers (`X509V3_get_section`/`X509V3_get_string`, the `s2i`/`i2s` bridges), the `GENERAL_NAMES`/`IPAddressFamily`/`ASIdentifiers` printers the `RT-X509-V3` court drives, and the two deferred `i2s` halves. **26 open rows over 5 units, 4,493 authority lines** — the whole of `x509v3.h`'s open 26. | 11.4 | `RT-X509-V3` |
| 11.6 | **The PEM X.509 container surface** | `pem_all.c` (33), `pem_pk8.c` (8), `pem_info.c` (5), `pem_x509.c` (4), `pem_xaux.c` (4): `PEM_read[_bio]_X509`, `PEM_write[_bio]_X509`, the `X509_INFO` reader and writer family, the `X509_REQ`/`X509_CRL`/`X509_ACERT` PEM spellings and `PEM_write[_bio]_X509_REQ_NEW`. **54 open rows over 5 units, 844 authority lines** — 47 from the atlas projection's `pem.h` plus the 7 hand-offs. | 11.1–11.5 | `RT-X509-PEM` |
| 11.7 | **The remaining shared units and the deferred hand-offs** | `x_all.c` (18: the `d2i_*`/`i2d_*` dispatch for the certificate family), `evp_lib.c` (2: the two `EVP_*_CTX_get_algor` hand-offs), `p5_scrypt.c` (6), `nsseq.c` (5), `x509_def.c` (4), `x_info.c` (2), `x_pkey.c` (2), `evp_pkey.c` (1), `t_spki.c` (1), `p12_mutl.c` (1), `asn_mstbl.c` (1: `ASN1_add_stable_module`). **43 open rows over 11 units, 3,924 authority lines.** The units are the ones whose closure crosses into the strata above; each is "to be measured at its slice", as §2 of `docs/PHASE-10-SUBPHASES.md` measured its own remainder. | 11.1–11.6 | `RT-X509` |
| 11.8 | **The seal** | nothing in the crate — evidence: `docs/PHASE-11-X509-SEAL.md` | 11.0–11.7 | — |

The seven rows above the seal partition the 513 open exports exactly, by defining unit: 121 + 111 +
76 + 82 + 26 + 54 + 43 = 513 (the activation partition, which moves as subphases land), and the 44
open units each appear in exactly one row. The partition
is derived from `forensics/atlas/export-defining-units.json` joined to the ledger's `open` list,
not typed.

**2.1 The verifier's dependency knot, and the rule that resolves it.** `X509_verify_cert`'s
remaining closure crosses into strata that come *after* this one. `check_revocation`
(`x509_vfy.c:1062`) keeps its `#ifndef OPENSSL_NO_OCSP` arm, and this admitted build does **not**
define `OPENSSL_NO_OCSP`, so a faithful transcription must call `check_cert_ocsp_resp` (`:1174`),
whose callees are `crypto/ocsp/`'s and absent from the crate. `verify_chain` likewise interleaves
the `SSL_DANE` matrix (`:3087-3490`), whose `SSL_DANE` is the SSL layer's. Since the dependency
order is `22 -> 11 -> 12 -> ...`, "`X509_verify_cert` waits for Phase 12" is not available: Phase 12
cannot progress before Phase 11 closes. The rule is:

> **Pull the implementation dependency forward, not the public ownership.**

Ownership of the `ocsp.h` and SSL exports stays where `forensics/atlas/symbol-ownership.json` puts
it (Phases 12 and 14). What this stratum pulls forward is the **minimum internal substrate** the
verifier's arms reach -- landed as internal transcriptions, recorded in
`forensics/prerequisites.json` as pulled forward rather than owned -- so the later stratum
implements its own exported surface around an already-landed internal core.

The measured OCSP closure of `check_cert_ocsp_resp` is `OCSP_response_status`,
`OCSP_response_get1_basic`, `OCSP_cert_to_id`, `OCSP_id_cmp`, `OCSP_id_get0_info`,
`OCSP_resp_count`, `OCSP_resp_find_status`, `OCSP_resp_get0`, `OCSP_SINGLERESP_get0_id`,
`OCSP_check_validity` and `OCSP_basic_verify`, plus the four item types (`OCSP_RESPONSE`,
`OCSP_BASICRESP`, `OCSP_SINGLERESP`, `OCSP_CERTID`) and their `d2i`/`i2d` and free doors;
`OCSP_basic_verify` additionally needs `crypto/ocsp/ocsp_vfy.c`'s signer checks. That substrate, and
the `SSL_DANE` representation the DANE arm reads, are the only things between this stratum and its
purpose.

The order is forced twice over, and the second forcing is the same one Phase 10 recorded. **11.1
before 11.2** because `X509_verify_cert` reads chains through `X509_STORE_CTX_get1_issuer` and
`X509_STORE_get_by_subject` (`crypto/x509/x509_vfy.c`'s own first calls), so a verification engine
with no store to look up in is not a slice that can be tested in isolation. **11.2 before 11.3**
because `X509_ACERT_verify` is a thin `X509_verify_cert`-shaped entry over the same
`X509_STORE_CTX`, and because 11.3's own reference surface (`X509_ACERT_get0_signature`) prints
through `v3_utl.c`'s helpers, which arrive in 11.5. 11.4 and 11.5 precede 11.6 because a PEM writer
serialises an object 11.4 mutates and 11.5's extension methods configure.

**The measurement that ordering rests on is unit-level, and it is honest about what it cannot
settle.** The three landed units the open work calls most — `x509_cmp.c`, `x509_v3.c` and
`x509_ext.c` — are already `implemented`, so 11.1's and 11.2's dependency closures begin inside the
crate; the open units' *own* internal call graph (which open `x509_vfy.c` helper each open
`x509_lu.c` entry needs, and in what order) is measured at each slice, the way D442 and D444 were.
A slice that discovers its unit is somewhere else records that rather than forcing the row (§5).

## 3. What each subphase must honour

**3.1 An X.509 object's identity is a DER document, and its bytes are the contract.** The
`X509`/`X509_REQ`/`X509_CRL`/`X509_ACERT` item groups are ASN.1 templates, so a transcription's
output is comparable byte for byte against the authority's: the `TBSCertificate`'s field order,
the `Validity`'s encoding form, the extension set's order and each `extnValue`'s inner DER. The
differential courts compare the container bytes rather than a parsed structure, and the print
surface (`t_x509.c`, `t_req.c`, `t_crl.c`, `t_acert.c`) is compared line for line, because the
authority's text has a fixed shape.

**3.2 Verification is a decision procedure, and the error code is part of it.** `X509_verify_cert`
is not a predicate: it answers an integer, and on failure it leaves `X509_STORE_CTX_get_error`,
`get_error_depth` and the error chain on the context. Two implementations can both refuse a chain
and be different libraries, so the court compares the *decision*, the *error code*, the *depth*,
and the sequence in which the `verify_cb` callback is invoked. The `X509_VERIFY_PARAM` flags and
their setter surface (`X509_VERIFY_PARAM_set_flags`, `set1_host`, `set_time`, the `INHIBIT_*` and
`PARTIAL_CHAIN` arms) are the second half, and `X509_V_FLAG_*`'s defaults are read from the
authority rather than typed.

**3.3 The store is a lookup contract, and its refusals are observable.** `X509_STORE_load_file`/
`load_path`/`add_cert`/`add_crl` and the `X509_LOOKUP` registry resolve a subject through the
`X509_OBJECT` cache; what a differential court can compare is the object's `type`, the refcount
surface, the cache's hit/miss behaviour under `X509_STORE_get_by_subject`, and — like Phase 10's
STORE — the refusal arms (a NULL subject, an unregistered `X509_LOOKUP_METHOD`, a store with no
lookup) with their error coordinates.

**3.4 The PEM surface is a byte codec with an error coordinate.** `PEM_read[_bio]_X509` and
`PEM_write[_bio]_X509` produce and consume PEM text, so their evidence is the exact encoding of a
fixed certificate against the authority and the error queue and coordinate for each malformed-input
arm. `PEM_X509_INFO_read[_bio]` is the subtle one: it reads a *bundle* and classifies each block
into the `X509_INFO`'s cert/CRL/PKCS7/key slots, and a probe that only reads a single certificate
would measure a third of it — the `pkcs7.h` arm is Phase 12's, and the reader's classification of a
`PKCS7` block is printed as `pending.` with its blocker rather than driven.

**3.5 Nothing here is a parity claim about a certificate's meaning.** A transcription that parses
the authority's bytes for a certificate this crate can build has not been shown to parse every
certificate, and §3.2's decision procedure is only as good as the chains a court can construct. The
measured surface is the one above, and a name that cannot be driven is named as `pending` rather
than counted as passing — the contract Phase 8's `PENDING_CORRECTNESS_COURTS` and every later
activation established.

## 4. Measured corrections, and the precondition

**4.1 `x509.h` is this stratum's, and an earlier plan already recorded the correction.** D431 §4.2
records that D175 and D177 gate two units "on Phase 10, by a *type*", reading `PBEPARAM`'s
declaration in `x509.h.in` and concluding the stratum owning `x509.h` is Phase 10; measured,
`forensics/atlas/symbol-ownership.json` gives all 548 of `x509.h`'s exports to phase 11 and none to
phase 10, and `forensics/atlas/typedef-owners.json` gives `PBEPARAM` `owner_phase: 11`. This plan
does not re-open the correction; it depends on it, because 548 of the working set is that header.

**4.2 This stratum owns no provider row, and the ledger says so rather than leaving it implied.**
Reading `forensics/atlas/provider-algorithms.json` for `owning_phase == 11` yields the empty set —
the census's rows belong to phases 8, 9, 10 and 13 — so `phase_state.py`'s provider-row rule and
`provider_court_coverage.py` have nothing to hold against this stratum, and
`forensics/phase11-obligations.json` carries `provider_rows_owned: 0`. A reader who expected an
X.509 stratum to publish dispatch rows would otherwise have to infer the zero from the census.

**4.3 The precondition this plan places on 11.0, and it is not optional.** Two fail-closed joiners
refuse this stratum's activation as specified, and both are measured rather than argued:

* `run_courts.py` refuses a stratum that is not `not-started` and has no runner: "phase 11
  (in-progress) is not `not-started` and has no runner". Phase 10 satisfied this by landing
  `forensics/tools/phase10_courts.py` in the same commit; this stratum must land
  `forensics/tools/phase11_courts.py`, whose only runnable court until 11.1 is the reference basis.
* `court_coverage.py` refuses the inherited `implemented` exports: "`N` implemented export(s) of a
  stratum that has begun is in none of directly-courted, indirectly-courted or non-observable".
  **The 954 inherited exports are the number at activation**, and 401 of them were already
  imported by a staged candidate probe — measured with `forensics/tools/elf_symbols.py` over every
  `artifacts/phase*/probes/*.candidate` — while the remaining **553** were named by nothing.
  **The ledger's landing is what moved all 954 into scope**, and the commit that landed it also
  land a phase-11 reference-basis probe that references them by name, registered in
  `court-coverage-rows.json`'s `reference_probes` as `RT-RUNTIME-REF`, `RT-BIO-CONF-REF`,
  `RT-BN-ASN1-REF`, `RT-PROVIDER-REF`, `RT-EVP-REF` and `RT-KEYFORMAT-REF` are for theirs. The
  probe references; it does not call, and the atlas records every name covered only by it at basis
  `referenced`, never `called`.

So the activation order is: the ledger, the plan, the runner and the reference probe land
**together**, or `forensics/tools/pipeline.sh` fails at `run_courts.py` and `court_coverage.py` and
the tree carries an activation whose two evidence joiners refuse it. This document states the
precondition; the runner is `forensics/tools/phase11_courts.py` and the probe is
`courts/phase11/rt_coverage_ref_probe.c`, and both are `courts/`-side work rather than this plan's
files.

**4.4 "X.509" here is the object graph and its verifier, not the containers that carry it.** D64
already recorded the split for Phase 5's hand-offs ("141 to Phase 12 (`cms.h`, `ocsp.h`, `ts.h`,
`pkcs7.h`, ...)"); measured, `forensics/atlas/symbol-ownership.json` assigns 118 `pkcs7.h` exports
and the whole of `cms.h`/`ocsp.h`/`ts.h`/`ct.h` to phase 12. The `PKCS7` reads `PEM_X509_INFO_read`
performs (§3.4) and the `PKCS12` container Phase 10 built are *callers* of this stratum's objects,
not part of it.

## 5. Process

This stratum inherits Phases 8 through 10's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every export carries a court edge in
`forensics/atlas/court-coverage.json` on the commit that lands it (D236) — **and §4.3 is the
measurement of what that rule means for a stratum whose exports were landed by an earlier one**;
every provider row it publishes is named by a probe of a court that covers it (D245), though this
stratum publishes none; and an artefact that a source change moves is regenerated in the same
commit. `docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the census's, and the census will correct them.** The subphase
table above was written from the defining units in `forensics/atlas/export-defining-units.json` and
the 513-row measurement in §1. D283's equivalent table for Phase 8 was corrected twice by
measurement — by D285, which found most of a slice was another stratum's, and by D287, which found a
prerequisite the slice's name could not show — and Phase 10's was corrected by D285's sibling
inside its own activation. The same is expected here and is not a defect in this document: the
census is the authority, and a subphase that discovers its unit is somewhere else records that
rather than forcing the row.

**Landed exports (checked against the ledger):**

The slices landed so far -- 11.1a, 11.1b, 11.4a and 11.5 -- are in, and every name below is in the
ledger's implemented list: `X509_LOOKUP_store`, `X509_STORE_load_store`,
`X509_STORE_load_store_ex`, `X509_TRUST_add`, `X509_TRUST_get0`, `X509_TRUST_get_by_id`,
`X509_TRUST_set`, `X509_check_trust`, `X509_check_host`, `X509_check_email`, `X509_check_ip`,
`X509_check_ip_asc`, `X509_get1_email`, `X509_get1_ocsp`, `X509_set_serialNumber`,
`X509_set_issuer_name`, `X509_set_subject_name`, `X509_set_pubkey`, `X509_REQ_new`,
`X509_REQ_get0_pubkey`, `X509_REQ_get_attr_count`, `X509_REQ_set_version`,
`X509_NAME_add_entry_by_txt`, `X509V3_EXT_nconf`, `X509V3_EXT_conf`, `X509V3_EXT_add_nconf`,
`X509V3_EXT_print`, `X509V3_EXT_print_fp`, `X509V3_extensions_print`, `X509V3_EXT_val_prn`. 11.4b
adds the X509_EXTENSIONS wrapper and the request extension functions:
`X509_EXTENSIONS_it`, `d2i_X509_EXTENSIONS`, `i2d_X509_EXTENSIONS`, `X509_REQ_get_extensions`,
`X509_REQ_add_extensions`, `X509_REQ_add_extensions_nid`, `X509_REQ_get1_email`,
`X509V3_EXT_REQ_add_nconf` and `X509V3_EXT_REQ_add_conf`. 11.6 adds the PEM X.509 container surface
and the three items it needs: `PEM_read_X509`, `PEM_read_bio_X509`, `PEM_write_X509`,
`PEM_write_bio_X509`, `PEM_read_X509_AUX`, `PEM_read_bio_X509_AUX`, `PEM_write_X509_AUX`,
`PEM_write_bio_X509_AUX`, `PEM_read_X509_REQ`, `PEM_read_bio_X509_REQ`, `PEM_write_X509_REQ`,
`PEM_write_bio_X509_REQ`, `PEM_write_X509_REQ_NEW`, `PEM_write_bio_X509_REQ_NEW`,
`PEM_read_X509_CRL`, `PEM_read_bio_X509_CRL`, `PEM_write_X509_CRL`, `PEM_write_bio_X509_CRL`,
`PEM_read_X509_PUBKEY`, `PEM_read_bio_X509_PUBKEY`, `PEM_write_X509_PUBKEY`,
`PEM_read_NETSCAPE_CERT_SEQUENCE`, `PEM_read_bio_NETSCAPE_CERT_SEQUENCE`,
`PEM_write_NETSCAPE_CERT_SEQUENCE`, `PEM_write_bio_NETSCAPE_CERT_SEQUENCE`, `PEM_read_RSA_PUBKEY`,
`PEM_read_bio_RSA_PUBKEY`, `PEM_write_RSA_PUBKEY`, `PEM_write_bio_RSA_PUBKEY`,
`PEM_read_DSA_PUBKEY`, `PEM_read_bio_DSA_PUBKEY`, `PEM_write_DSA_PUBKEY`,
`PEM_write_bio_DSA_PUBKEY`, `PEM_read_EC_PUBKEY`, `PEM_read_bio_EC_PUBKEY`, `PEM_write_EC_PUBKEY`,
`PEM_write_bio_EC_PUBKEY`, `PEM_write_PUBKEY`, `PEM_write_bio_PUBKEY`, `PEM_write_PUBKEY_ex`,
`PEM_write_bio_PUBKEY_ex`, `PEM_X509_INFO_read`, `PEM_X509_INFO_read_ex`,
`PEM_X509_INFO_read_bio`, `PEM_X509_INFO_read_bio_ex`, `PEM_X509_INFO_write_bio`, `PEM_read_PKCS8`,
`PEM_read_bio_PKCS8`, `PEM_write_PKCS8`, `PEM_write_bio_PKCS8`, `PEM_read_PKCS8_PRIV_KEY_INFO`,
`PEM_read_bio_PKCS8_PRIV_KEY_INFO`, `PEM_write_PKCS8_PRIV_KEY_INFO`,
`PEM_write_bio_PKCS8_PRIV_KEY_INFO`, `NETSCAPE_CERT_SEQUENCE_new`, `NETSCAPE_CERT_SEQUENCE_free`,
`NETSCAPE_CERT_SEQUENCE_it`, `d2i_NETSCAPE_CERT_SEQUENCE`, `i2d_NETSCAPE_CERT_SEQUENCE`,
`X509_INFO_new`, `X509_INFO_free`, `X509_PKEY_new` and `X509_PKEY_free`. The
bulk of the implemented list was landed before this stratum's first slice by Phase 8's 8.8 chain
and Phase 10's pulled-forward X.509 subphases, with `ASN1_generate_nconf` and `ASN1_generate_v3`
handed over by Phase 5; the ledger is the record and this sentence names only what the slices above
added. 11.2 adds the verification engine's landed surface: the X509_VERIFY_PARAM object, table and
every accessor (`X509_VERIFY_PARAM_new`, `X509_VERIFY_PARAM_free`, `X509_VERIFY_PARAM_inherit`,
`X509_VERIFY_PARAM_set1`, `X509_VERIFY_PARAM_lookup`, `X509_VERIFY_PARAM_get0`), the
X509_STORE_CTX lifecycle and accessors (`X509_STORE_CTX_new`, `X509_STORE_CTX_free`,
`X509_STORE_CTX_cleanup`, `X509_STORE_CTX_get0_param`, `X509_STORE_CTX_set0_param`,
`X509_STORE_CTX_get1_issuer`), the free-standing time surface (`X509_cmp_time`,
`X509_cmp_current_time`, `X509_cmp_timeframe`, `X509_time_adj`, `X509_time_adj_ex`,
`X509_gmtime_adj`), `X509_get_pubkey_parameters` and `X509_policy_tree_free`. Seven of the three
units' open names are withheld, each with its blocker recorded in `src/x509/x509_vfy.rs`'s and
`src/x509/pcy_tree.rs`'s module docs: the engine's three entry points, the two context
constructors, the CRL difference helper and the policy-tree entry point.

11.4's `x_crl.c` CRL method and lookup surface, pulled forward to unblock the engine, adds
`X509_CRL_add0_revoked`, `X509_CRL_verify`, `X509_CRL_get0_by_serial`, `X509_CRL_get0_by_cert`,
`X509_CRL_set_default_method`, `X509_CRL_METHOD_new`, `X509_CRL_METHOD_free`,
`X509_CRL_set_meth_data` and `X509_CRL_get_meth_data`; 11.5's RFC 3779 path validation adds
`X509v3_asid_validate_path`, `X509v3_asid_validate_resource_set`, `X509v3_addr_validate_path`
and `X509v3_addr_validate_resource_set`. 11.1c adds the store object and its parameter setters, the
seven names the missing `X509_VERIFY_PARAM` had withheld: `X509_STORE_new`, `X509_STORE_free`,
`X509_STORE_set1_param`, `X509_STORE_set_flags`, `X509_STORE_set_depth`, `X509_STORE_set_purpose`
and `X509_STORE_set_trust`; and 11.1c's file loaders add `X509_load_cert_file`,
`X509_load_cert_file_ex`, `X509_load_crl_file`, `X509_load_cert_crl_file` and
`X509_load_cert_crl_file_ex`. The two lookup-method constructors, `X509_LOOKUP_file` and
`X509_LOOKUP_hash_dir`, stay withheld on the `OPENSSLDIR` defaults
`X509_get_default_cert_file`/`_dir`, which are 11.7's and Phase 16's.

11.3 adds the whole attribute-certificate surface: the `X509_ACERT` item group and its accessors
and setters (`x509_acert.c`, `x509aset.c`), the `OSSL_IETF_ATTR_SYNTAX` items (`x_ietfatt.c`) and
the `x_all.c` sign/verify/`_fp`/`_bio` doors, leaving only the two `X509_ACERT` printers, which
wait on `X509_signature_print`. 11.4 adds the certificate, request and CRL printers (`t_x509.c`,
`t_req.c`, `t_crl.c`) and `X509_REQ_to_X509` (`x509_r2x.c`). 11.7 adds the shared remainder --
`p5_scrypt.rs`, `evp_lib.rs`, `asn_mstbl.rs`, `evp_pkey.rs`, `t_spki.rs` and `p12_mutl.rs` -- and
closes the two follow-ups the previous commit left: `X509_to_X509_REQ` (`x509_req.rs`) and the two
`X509_ACERT` printers (`t_acert.rs`), now that `X509_REQ_sign` and `X509_signature_print` are
landed. 11.2 adds `X509_CRL_diff` and `X509_policy_check` with its `pcy_*` internals.

**Open exports (checked against the ledger):**

The store and verification layer is still open at `X509_verify_cert`; the attribute certificate
surface is closed but for the verify-callback printer
`X509_STORE_CTX_print_verify_cb`; and
the remaining shared units at `X509_get_default_cert_file`, `X509_load_http`
and `X509_CRL_load_http`. Every name
here is in the ledger's open list; the counts move as the slices land, so the ledger, not this
sentence, carries them.
