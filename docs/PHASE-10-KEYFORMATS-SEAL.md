# Phase 10 — Key formats, PKCS#12 and STORE: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. `forensics/phase-state.json:482` reads `complete` for phase 10,
`docs/SEAL-CENSUS.md:335` reads `complete` and `docs/SEAL-CENSUS.md:38` carries the same stratum's
row, `forensics/phase10-obligations.json:9` reads `open_in_this_stratum: 0`, and every earlier
stratum is `complete`, which the rule `forensics/phase-state.json:622` states. `seal_sha256` is
derived too: `forensics/phase-state.json:481` now carries this document's hash and
`docs/SEAL-CENSUS.md:336` names the seal, so the line is recomputed whenever this document changes
and is not restated here (both read `null` / `seal: none written yet (unnamed)` in the tree before
this document existed). Reaching `complete` means the stratum has reached the state a seal
*records* (D421); it is **not** a parity claim, and this document is where what the derivation
does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This seal
cites that document rather than restating its arithmetic, because a number typed here is a number
that can drift from the evidence it summarises (D97), and the census's own header
(`docs/SEAL-CENSUS.md:6-9`) says so. The one table this document *does* carry — §3's court list —
is copied from `artifacts/phase10/COURTS.json`, and it says so.

This is **not** a claim that openssl-rs is a usable OpenSSL, and it is **not a parity claim**.
`docs/PARITY_MODEL.md` is the authority on what the labels mean: `implemented` means a symbol with
that name is defined, and a passing bounded court is a differential result over the behaviours that
court exercises. `PARITY_VERIFIED` is not claimed for any symbol here, and
`forensics/STATUS.md:311-317` carries the non-claims the generated status emits. All `libssl`
exports remain `SCAFFOLDED` and abort when called, exactly as `docs/SEAL-CENSUS.md:21` and
`forensics/STATUS.md:89` record.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json:39`, the second
  entry), named as the authority by `artifacts/phase10/COURTS.json:2` and `:5`
- Court results: `artifacts/phase10/COURTS.json` — six courts, `all_pass` true
  (`artifacts/phase10/COURTS.json:4`), zero residuals; the totals are `docs/SEAL-CENSUS.md`'s
  (`docs/SEAL-CENSUS.md:349-360`) and the per-court table is §3. The five **differential** courts
  pass on both sides, and so does the one **correctness** court: `CT-PKCS12` records
  `vectors_passed` 6 of `vectors_checked` 6 (`artifacts/phase10/COURTS.json:148-150`), with
  `pending_courts` empty (`artifacts/phase10/COURTS.json:154`) and `summary` `pass` 6 of `total` 6
  (`artifacts/phase10/COURTS.json:155-159`)
- Obligation ledger: `forensics/phase10-obligations.json` — `open_in_this_stratum` 0
  (`forensics/phase10-obligations.json:9`), `deferred_to_later_phase` 0
  (`forensics/phase10-obligations.json:7`); the working-set rule it enforces is at
  `forensics/phase10-obligations.json:628`
- Court coverage: `forensics/atlas/court-coverage.json` — phase 10's block at
  `forensics/atlas/court-coverage.json:27251`, its counts at `:27254-27260`; the counts are also
  `docs/SEAL-CENSUS.md` §Court coverage, and the weaker meaning of `directly_courted` is stated
  there and in §1 below (D199)
- Derived state: `forensics/phase-state.json:460-483`
- Provider rows: `forensics/atlas/provider-algorithms.json`'s `projection` block
  (`forensics/atlas/provider-algorithms.json:75-84`) and the `provider_rows` block of
  `forensics/phase-state.json` (`forensics/phase-state.json:476-480`) — every registration row the
  plan gives this stratum is implemented
- FRF receipts and claim: **present, and the chain's objects are on disk.** `forensics/tools/
  gen_frf_courts.py`'s `COURTS` table gained a Phase-10 block for the five differential courts
  (`forensics/tools/gen_frf_courts.py:470-484`, the table closing at `:485`), the declarations are
  under `forensics/frf/courts/openssl-rs-rt-{keyformat-ref,codec,keyformat,pkcs12,store}`, and `.frf`
  now carries five receipts, ten challenges, fifteen captures and one compiled claim
  (`c39bbb1a6f3b95a984f0bbb9b02d61f747d0410c331e9a8dbb21af3a7cd9f69b`; 91 receipts and 182
  challenges, from the 86 and 172 Phase 9's head change `C94` left). §8 states what that is
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s head
  change is Phase 10's `C95` (`forensics/GEMEL_TRAJECTORY.md:13`) and its `current:` is `K49` —
  `checkpoint.c26506bf0280601d6dda185e0ae98d418f5e3a68b409ac4918ff9256f200ba37`
  (`forensics/GEMEL_TRAJECTORY.md:156,163`). The state a reader reaches the stratum's `complete`
  through is this stratum's. §8 states what that is
- Deciding record: `docs/DECISIONS.md` — **D431** (the activation), the 10.1 series **D434–D437**,
  the 10.2–10.6 series **D438–D450**, the pulled-forward X.509 series **D451–D463**, the table
  series **D464–D472** and the closing **D473**; with `docs/PHASE-10-SUBPHASES.md` for the subphase
  plan this seal closes. §10 is where the corrections those entries record are summarised

## 1. What this phase owns, and how that was decided

Phase 10 is **the key-format layer**: the `OSSL_ENCODER`/`OSSL_DECODER` codec framework and the
provider rows that publish its codecs, the PKCS#12 container, `OSSL_STORE`, and the
`PEM_*`/`d2i_*`/`i2d_*` key-format helpers the earlier strata handed forward
(`docs/PHASE-10-SUBPHASES.md:5-7`). It is deliberately **not** the primitives the codecs encode:
the asymmetric key types, their ASN.1 method objects and their provider keymgmt are Phase 8's, and
the `EVP_PKEY` layer the rows construct into is Phase 7's. Nor is it PKCS#7: the stratum's name in
`docs/RELEASE_GATES.md:22` reads "Key formats + PKCS + STORE", and **"PKCS" here is PKCS#12
alone** — `forensics/atlas/symbol-ownership.json` assigns every one of the 118 `pkcs7.h` exports to
Phase 12 and every one of the 117 `pkcs12.h` exports to this stratum
(`docs/PHASE-10-SUBPHASES.md:9-15,301-307`).

**The working set is derived, not chosen.** The rule is the ledger's own, at
`forensics/phase10-obligations.json:628`:

> the stratum's working set is the projection of `forensics/atlas/symbol-ownership.json` for phase
> 10, plus every symbol an earlier stratum's ledger records as handed to it: a symbol belongs to the
> stratum that owns the header declaring it, and a discharged hand-off belongs to the stratum that
> built it

The census's per-stratum row (`docs/SEAL-CENSUS.md:38`) reads `atlas-owned` 272, `ledger owned` 298,
`implemented` 298, `deferred` 0, `open` 0; the ledger's `counts` block
(`forensics/phase10-obligations.json:5-12`) reads `atlas_owned` 272, `received_by_handoff` 26,
`owned` 298. The 272 are this stratum's own four headers (`pkcs12.h` 117, `store.h` 76, `decoder.h`
41, `encoder.h` 38, `docs/PHASE-10-SUBPHASES.md:33-38`) and the 26 are the hand-offs the census
enumerates at `docs/SEAL-CENSUS.md:346-347`: sixteen from phase 5 (the `pem.h` PVK readers and
writers and the `d2i_PKCS8PrivateKey*`/`i2d_PKCS8PrivateKey*` spellings) and ten from phase 7
(`PEM_write_bio_PrivateKey_traditional`, the four `d2i_PrivateKey*`/`d2i_AutoPrivateKey*` and the
five `i2d_*` names).

**Unlike every earlier activation, this stratum did not start with a whole working set open.**
Eighty-seven of its atlas-owned exports were already `implemented` before its first subphase — all
79 `encoder.h`/`decoder.h` exports and 8 `pkcs12.h` ones, landed by Phase 8's 8.8/8.9 chain
(D362–D367) because `crypto/evp/p_lib.c:1196`'s `print_pkey` reaches
`OSSL_ENCODER_CTX_new_for_pkey` first and the `pem.h` readers reach
`OSSL_DECODER_CTX_new_for_pkey` (`docs/PHASE-10-SUBPHASES.md:17-23,252-263`). The plan names this
as §4.1's correction: the ownership atlas assigns the codec framework here, but Phase 8 landed it.

**The 272 atlas-owned exports are defined by 25 authority translation units and the 636 provider
rows are 318 tables twice over.** `docs/PHASE-10-SUBPHASES.md:54-63` names the 25 units; §1a
(`docs/PHASE-10-SUBPHASES.md:73-111`) measures that the 636 `OSSL_OP_ENCODER`/`OSSL_OP_DECODER`/
`OSSL_OP_STORE` registration rows are the `default` and `base` providers' copies of **318 distinct
dispatch-table symbols**, because both provider files `#include` the same generated
`providers/encoders.inc`/`decoders.inc`. The census reads `row_count` 996 over all providers
(`forensics/atlas/provider-algorithms.json:482`), and the phase-10 slice is 636 of them
(`forensics/phase-state.json:476-480`) with `open["10"]` 0
(`forensics/atlas/provider-algorithms.json:83`). **The irreducible unit is the translation unit,
not the row**: measurement resolves the 636 rows to **eleven row-publishing units**
(`docs/PHASE-10-SUBPHASES.md:92-105`).

**The order is forced twice over, and then measured again.** 10.1's codec rows cannot be fetched
before the framework that dispatches them, so 10.1 is first among the work
(`docs/PHASE-10-SUBPHASES.md:181-185`); 10.5's `file` loader decodes what 10.4's PKCS#8 half
produces, so the store's decoder arm lands after the decryption pair it calls. Then the
`nm --undefined-only` join over the authority's own objects moved the order a third time
(`docs/PHASE-10-SUBPHASES.md:187-202`): `decode_der2key.c` waits on four PQC codec helpers rather
than on 10.6, and `encode_key2any.c` waits on those helpers, six container writers **and 10.4's
`PKCS8_encrypt_ex`**, so the two big units are gated on units the plan's §2 order did not name.

**The seven subphases the plan did not originally own are the pulled-forward X.509 subset.** D450
measured the stratum's remaining distance as "14 exports and 2 provider rows, all reachable only
through ~45,000 lines of Phase 11's object graph", and the owner chose to measure the subset and
pull it forward rather than defer it (D442's and D444's precedent, extended at D451). That subset is
`docs/PHASE-10-SUBPHASES.md` §6 and §7: `10.8` the object core through `10.16` the STORE result and
file loader, of which `10.14` is decomposed into fifteen dependency-ordered sub-subphases
(`docs/PHASE-10-SUBPHASES.md:441-504`) and `10.15`/`10.16` are the two rows that close the twelve
exports and two provider rows (`docs/PHASE-10-SUBPHASES.md:547-552`). **Ownership is unchanged by
that landing**: the symbols these slices define are headed `x509.h`/`x509v3.h` (Phase 11's) and
`pkcs7.h`/`ct.h`/`ocsp.h` (Phase 12's) and remain their owning strata's, no Phase-11 or Phase-12
evidence, ledger, plan, seal or state row is created, and phase 11 still derives
`not-started` (`docs/SEAL-CENSUS.md:39`, `forensics/phase-state.json:622`).

**The two planes, and which one this stratum's evidence is.** D201's commitment — every
primitive-bearing subphase carries a differential `RT-*` court *and* a correctness `CT-*` court —
holds here, and the correctness plane is `CT-PKCS12`, registered in
`forensics/tools/phase10_courts.py` and driven by `forensics/tools/correctness_vectors.py` against
`forensics/vectors/pkcs12.json`. The differential plane is five courts, one of which
(`RT-KEYFORMAT-REF`) is the **reference-basis** court D199 requires for a stratum whose exports were
landed by an earlier one: it takes the address of each inherited export, so a symbol covered only by
it is a proof of *reference* and not that any arm of it was driven
(`artifacts/phase10/COURTS.json:6`). §3 is where the two planes are tabulated.

## 2. What has been built

**10.1, the codec rows.** Eleven row-publishing units, not 636 rows and not 318: measurement
(`docs/PHASE-10-SUBPHASES.md:92-105`) resolves the base and default providers' copies of the same
318 dispatch tables to `providers/implementations/encode_decode/`'s `encode_key2any.c` (412 rows
over 206 tables), `decode_der2key.c` (138 over 69), `encode_key2text.c` (58 over 29),
`encode_key2ms.c` (8), `encode_key2blob.c`/`decode_msblob2key.c`/`decode_pvk2key.c` (4 each),
`decode_spki2typespki.c`/`decode_pem2der.c`/`decode_epki2pki.c` (2 each) and
`storemgmt/file_store.c` (2). The shared provider-side unit `endecoder_common.c` is transcribed once
in `src/provider/endecoder_common.rs` (`docs/PHASE-10-SUBPHASES.md:121-124`). The four PQC codec
helpers (`ossl_ml_kem_d2i_PKCS8`/`_PUBKEY` and `ossl_ml_dsa_d2i_PKCS8`/`_PUBKEY`) landed with them
(D436), and `encode_key2any.c` landed whole — 208 expansions, 206 registered rows — under D445.

**10.2 through 10.4, PKCS#12.** The object and its ASN.1 (`p12_asn.c`, `p12_sbag.c`, `p12_attr.c`,
`p12_utl.c`, D440), the container construction (`p12_add.c`, `p12_crt.c`, `p12_mutl.c`,
`p12_init.c`, `p12_npas.c`, D441/D442/D447), and the key derivation and PBE pair (`p12_key.c`,
`p12_crpt.c`, `p12_decr.c`, `p12_p8d.c`, `p12_p8e.c`, `p12_kiss.c`, D443/D444). **Two slices of a
stratum the plan places after this one were pulled forward to make those land**: `crypto/pkcs7/`'s
object and its `data`/`digest`/`encrypted` arms, because the `PFX` structure's `authsafes` column
*is* a `PKCS7` (D442), and thirty `x509.h` exports — the `PBEPARAM`/`PBE2PARAM`/`PBKDF2PARAM`/
`PBMAC1PARAM` items, the `PKCS5_pbe_set*`/`pbe2_set*`/`pbkdf2_set*` family and `EVP_PKEY2PKCS8` —
because `PKCS8_encrypt(_ex)`'s closure is Phase 11's (D444).

**10.5 and 10.16, STORE.** `store_strings.c`, `store_meth.c` and `store_register.c` (D448),
`store_lib.c`'s reachable subset (D449) and its `OSSL_STORE_load` half, plus `store_result.c`
(D473); and `file_store.c`/`file_store_any2obj.c` whole, which publish the two `OSSL_OP_STORE`
rows (D460). The store's library-context slot is built in the authority's `P2` position after
`encoder_store` (`src/context/mod.rs`), which is what makes a registered loader findable by a later
`OSSL_STORE_LOADER_fetch` rather than merely present in a table (D448).

**10.6, the key-format hand-offs.** The 26 symbols phases 5 and 7 handed forward, in
`src/pem/pvkfmt.rs`, `src/pem/pem_pk8.rs`, `src/pem/pem_pkey.rs`, `src/asn1/i2d_evp.rs` and
`src/asn1/d2i_pr.rs`, each transcribed against the authority with its bytes and its error
coordinates (D438). Two of the 26 (`i2d_PKCS8PrivateKey_nid_bio`/`_fp`) landed later, with
`PKCS8_encrypt_ex`, under D445; the ledger now reads `implemented` 298 of `owned` 298
(`forensics/phase10-obligations.json:8,10`).

**The pulled-forward X.509 subset, and the table layer it needed.** 10.8 through 10.13 landed the
certificate object core, the digest substrate, the ASN.1 digest/sign/verify layer, the name and
print layer, the leaf extension items and the policy graph (D451–D456). 10.14 was decomposed into
fifteen dependency-ordered sub-subphases and its reachable frontier landed slice by slice — the
first slices through 10.14.6 (D457–D463), the sixty-three extension tables and the published
dispatch through D464–D472, and the five chain names through D473 — as a function-level cut of one
75-unit strongly-connected component (`docs/PHASE-10-SUBPHASES.md:441-504`): the cut is at the
**call graph**, not the units, and each function whose closure was unlanded was withheld by name
rather than its whole unit (D451). What those slices did **not** reach keeps its blocker: the verify
engine proper, PKCS#7's `signed`/`enveloped`/`signedAndEnveloped` arms, OCSP's and CT's verification
paths, and everything that reads an `X509_STORE_CTX` (`docs/PHASE-10-SUBPHASES.md:1275-1280`,
D468–D473). Its keystone is the extension dispatch, which needs a complete
`standard_exts[]`: **73 entries over 63 distinct `ossl_v3_*` tables** transcribed from
`standard_exts.h:15-95`, with the six `v3_lib.rs` lookup names (`X509V3_EXT_get_nid`, `_get`,
`_add_alias`, `_EXT_d2i`, `_get_d2i`, `_add1_i2d`) published only once all 63 exist, because a
partial array would silently change `OBJ_bsearch_ext`'s answer for every missing NID
(`docs/PHASE-10-SUBPHASES.md:1282-1295`, D456/D472). 10.15 closed ten of the twelve remaining
exports (D459) and 10.16 closed the last provider rows (D460); D473 landed the five names the
published dispatch made reachable — `X509_get_ext_d2i` and its siblings, `ossl_x509v3_cache_extensions`,
`X509_self_signed` and the add-cert family, `PKCS12_parse` and `OSSL_STORE_load` — and with them
the stratum's last two open exports.

**The books that moved with the code.** The implemented surface ended at 4,254 symbols
(`forensics/atlas/implemented-surface.json:4769-4772`, the crate-wide `totals` block), the live
`internal_symbols.c_style` count at 484 (`forensics/atlas/implemented-surface.json:9`, checked
against `docs/CI.md` by `docs_consistency.py`'s `ci_c_style_count`), and the census's
`libcrypto`/`libssl`/total rows read as `docs/SEAL-CENSUS.md` states them (`docs/SEAL-CENSUS.md:20-22`). Three Phase-7 deferrals were discharged as consequences —
`ASN1_item_sign_ex` (D453), `ASN1_item_verify_ex` (D454) and `EVP_add_alg_module` (D461) — moving
Phase 7 from `implemented` 733 / `deferred` 217 to `implemented` 736 / `deferred` 214
(`forensics/phase7-obligations.json`'s `counts`, `docs/SEAL-CENSUS.md:35`). Phase-10's own ledger
reads `298 implemented / 0 open` and its provider rows `636 implemented / 0 open`
(`forensics/phase10-obligations.json:5-12`, `forensics/phase-state.json:476-480`).

## 3. The evidence

Copied from `artifacts/phase10/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. A correctness row has no authority transcript, so it carries its
`vectors_checked` instead, and the census counts it as structural.

| court | plane | observations | probe |
|---|---|---|---|
| `RT-KEYFORMAT-REF` | differential (reference basis) | 87 | `courts/phase10/rt_coverage_ref_probe.c` |
| `RT-CODEC` | differential | 4160 | `courts/phase10/rt_codec_probe.c` |
| `RT-KEYFORMAT` | differential | 370 | `courts/phase10/rt_keyformat_probe.c` |
| `RT-PKCS12` | differential | 353 | `courts/phase10/rt_pkcs12_probe.c` |
| `RT-STORE` | differential | 1038 | `courts/phase10/rt_store_probe.c` |
| `CT-PKCS12` | correctness | 6 vectors | `courts/phase10/ct_pkcs12.c` |

All five differential rows carry `residual_count: 0` and `verdict: "pass"`
(`artifacts/phase10/COURTS.json:14-91`), and the summary reads `pass` 6 of `total` 6 with
`pending_courts` empty (`artifacts/phase10/COURTS.json:154-159`). The totals over the five
transcript courts are `docs/SEAL-CENSUS.md`'s (`docs/SEAL-CENSUS.md:349`), and the per-court rows
there, the correctness row included (`docs/SEAL-CENSUS.md:353-360`), are the same computation.

**`RT-KEYFORMAT-REF` is not a behavioural court, and its meaning is the weaker one.** Its probe
takes the address of each of the stratum's eighty-seven inherited `implemented` exports and prints
whether each is non-NULL, so a symbol covered only by it means the candidate distribution defines
the name — which the link proves — and **not** that any arm of it was driven
(`artifacts/phase10/COURTS.json:6`). The court coverage atlas records those at basis `referenced`,
never `called` (`docs/SEAL-CENSUS.md:368-371`, D199). Four courts are behavioural: `RT-CODEC` drives
the encoder rows through `OSSL_ENCODER_*` and the decoder rows through `OSSL_DECODER_*`,
`RT-KEYFORMAT` drives the `d2i_*`/`i2d_*`/`PEM_*`/`b2i_*`/`i2b_*` hand-offs, `RT-PKCS12` drives the
`PKCS12` item groups, the container and the PBE pair, and `RT-STORE` drives the `OSSL_STORE` loader
object, its registry and the fetched `file:` loader.

**The correctness row, and why its evidence is a different shape.** `CT-PKCS12` is
**candidate-only**: the probe is compiled against the candidate alone and its output is compared
with committed expected bytes, so there is no authority transcript to diff and no
`authority_observations` count (`artifacts/phase10/COURTS.json:96`). It re-reads the pinned
authority's own `test/recipes/30-test_evp_data/evppbe_pkcs12.txt` — its sha256 is
`cabbba1e5e9e3f172d3b1933893e016b12bcf6c8b8daf6189c02c08503614c06`
(`artifacts/phase10/COURTS.json:206`) — and calls `PKCS12_key_gen_uni` exactly as
`test/evp_test.c`'s `pbe_test_run` does, comparing each `Key` against the expected bytes mirrored
in `forensics/vectors/pkcs12.json` (sha256
`c6eff4b618df28c45e2908e14f3dd252701eb3fccfcadfc378da9a11e03f2a93`,
`artifacts/phase10/COURTS.json:201`). All six stanzas pass (`artifacts/phase10/COURTS.json:102-145`).
Two corpora were **declined with reasons** rather than ignored: `evppbe_pbkdf2.txt` is
`PBE = pbkdf2`, which is `PKCS5_PBKDF2_HMAC` and Phase 7's, and `80-test_pkcs12.t` is a
`PKCS7`/`X509` container test, which is Phase 12's and Phase 11's (D443). No corpus was invented to
make a correctness court exist.

**The court coverage join is clean, and its meaning is the weaker one.**
`docs/SEAL-CENSUS.md:382` reads phase 10 as 298 implemented, 298 `directly_courted` (237 of them
`called` and 61 `referenced`), 0 indirect, 0 non-observable, 0 unmatched. `directly_courted` means
*referenced by a staged candidate probe that ran and produced a transcript*
(`docs/SEAL-CENSUS.md:368-371`), a proof of **reference** rather than that every arm of the symbol
was driven — the same reading Phase 8's and Phase 9's seals adopt
(`docs/PHASE-8-CRYPTO-SEAL.md:6-11`, `docs/PHASE-9-RAND-DRBG-SEAL.md:228-232`). The provider-row
join is the same invariant one level down: `forensics/atlas/provider-court-coverage.json` reads
957 implemented rows, 957 directly courted, 0 unmatched (`by_phase["10"]` reads 636 and 0).

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
evidence found real defects, in the candidate and in the instrument.

**`RT-CODEC` drove the 206 `encode_key2any.c` rows and read the join the plan's §3.1 asked for.**
Of the 412 fetches (206 rows in both providers), **144 rows emit the authority's exact bytes** and
**62 return 0 as the row's own refusal** — the 58 `EncryptedPrivateKeyInfo` rows, whose
`cipher_intent` is unset when no cipher is given, and the four `DH`/`DHX` `SubjectPublicKeyInfo`
rows, which raise `PROV_R_NOT_A_PUBLIC_KEY`. **One path is pending with a measured blocker rather
than a silent skip**: the abstract-object refusal cannot be reached from the public
`OSSL_ENCODER_*` surface, because a non-NULL `key_abstract` is only passed when a deeper encoder in
the same chain has produced data whose output type aliases this row's algorithm name, and no
provider encoder publishes such an output type (D446). That is the plan's §3.5 rule: a path that
cannot be driven is named, never counted as passing.

**Making the PEM decoder reachable exposed a real Phase-8 defect.** Publishing the decoder makes a
decoded key provider-backed, which exposed that `src/evp/pkey_ctx.rs`'s `int_ctx_new` refused a
legacy-only `EVP_PKEY` where the authority types it from `pkey->type`. The authority's branch is
now transcribed, and Phase 8's `RT-PUBKEY` is green rather than regressed (D450). The `nm`
measurement could not have found it: it is a behaviour the closure only reaches once the row above
it is real.

**Driving the pulled-forward layers found defects the compiler could not.**
`OBJ_nid2obj` returned NULL **silently** for an unknown NID where the authority raises
`ERR_LIB_OBJ`/`OBJ_R_UNKNOWN_NID`; it now raises, and `RT-STORE`'s `name.access.index.badnid` and
`v3.create.badnid` arms are what observe it (D454, the name/print/`v3` layer). The digest
substrate's engine table caught two more before the green runs: `ENGINE_up_ref` initially failed to
write the incremented count back, which double-frees on `ENGINE_unregister_digests`, and the
layout-resolved `AtomicPtr` cast carried a typo (D452). Both are the kind a fetch-only probe would
have missed.

**A probe defect was found by a court, not a compiler.** The differential transcript matched on its
first run, but the probe's first draft read a **stale** error coordinate: the preceding
`s2i_ASN1_OCTET_STRING("nonsense")` refusal was never popped, so an arm reported the older `15.102`
instead of `34.107`. Every arm now pops its own error queue first, and the `skid.*.err`/`ia5.*.err`
arms observe it (D455). An error-coordinate claim is only as good as the queue state it is read
from.

**The stratum's one unreproduced test failure became a reproduced, named, fixed one.** D458 recorded
one `cargo test --lib` failure with no test name; D459, D460 and D461 could not reproduce it; and
D462 wrote down what would falsify its own leading explanation — *a failure on a committed, clean
tree*. That criterion fired. The failing test was
`evp::algorithm::tests::a_refused_precondition_is_success_and_skips_the_map`, panicking with
`assertion left == right failed left: 2 right: 1`, in the **parallel** run inside `pipeline.sh`,
because five sibling tests in `evp::algorithm` share the process-global `SAW` array and the
`PRE_RESULT`/`PRE_ERRORS`/`POST_RESULT` statics without `test_support::lock_global_state`. The five
now take the crate lock; **no test was skipped, deleted or weakened and no assertion relaxed**
(D466). The mid-edit story D462 favoured was *reasonable* and *wrong*, and only the written
falsification criterion made that visible.

**And a host-environment divergence was recorded rather than smoothed.** One intermediate pipeline
run failed `probe_hygiene.py` with `rt_bio_resolve_probe.c` `UNSTABLE`, because its `getaddrinfo`
failure text differed between `-O0` (`Name or service not known`) and `-O1` (`No address associated
with hostname`). That is a resolver divergence in the container, not a source change: the same probe
read `clean` in the runs either side of it and neither the slice's source nor its evidence touches
`crypto/bio/b_addr.c` (D467). It is the same class of environment dependence the court's stability
plane exists to surface, and §5 records it.

**A pre-existing Phase-8 test flakes, and this seal met it rather than hiding it.** One run of this
seal's own verification failed `cargo test --lib` at
`sm2::crypt::tests::the_ciphertext_size_matches_and_a_round_trip_holds`, panicking at
`src/sm2/crypt.rs:851` with `assertion failed: ctext_len + 1 >= expected_len` (1116 passed, 1
failed). The test performs a **random** SM2 encryption, and its lower bound is wrong: DER trims a
leading zero byte from an `INTEGER`'s content, so the ciphertext length is `61 + cX + cY` where each
coordinate's content is 32 bytes normally but 31 when its top byte is zero and the next byte's high
bit is clear. The assertion holds for the normal `cX + cY` of 64 to 66 and fails when both trim to
63 or fewer, which the random draw reaches occasionally. It is **Phase 8's**, its file is unmodified
by this stratum, and it is **recorded, not fixed**: a seal does not repair another stratum's test,
and the run that failed was re-run green. It is named here rather than smoothed over, exactly as
D462 and D466 required of the stratum's own flake.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an uninitialised field, or **aborts**, the court
does not call it and `docs/SECURITY_DIVERGENCE_POLICY.md` records the divergence with the phase or
condition that would make the behaviour reachable, so the record retires with that phase rather than
with a re-reading of this document. Two register rows name this stratum as their `current_owner`,
and the machine-readable form is `forensics/divergence-obligations.json`:

- **`D-PBE-PKCS12-KEYGEN-1` — the six `PKCS12_PBE_keyivgen` rows of `builtin_pbe[]` carry no
  keygen.** Its trigger was "Phase 10's first commit that lands `crypto/pkcs12/p12_crpt.c`", and it
  fired at D443. **It is discharged.** The six `BUILTIN_PBE` rows now carry both
  `PKCS12_PBE_keyivgen` addresses (`src/pkcs12/p12_crpt.rs`, `src/evp/evp_pbe.rs`), the register's
  heading reads `— **CLOSED**` (`docs/SECURITY_DIVERGENCE_POLICY.md:1231`), and the row is
  `trigger_satisfied: true`, `disposition: "fixed"`, `blocking: false` with its evidence naming
  `RT-PKCS12`'s `pbe.find.04`..`pbe.find.09` arms, which print each row's keygen presence. The
  closure is observed rather than asserted.
- **`D-DECODER-ABSENT-1` — the crate publishes no provider decoder.** Recorded by D369, its trigger
  phrase names Phase 10, and the register entry is still `open`
  (`docs/SECURITY_DIVERGENCE_POLICY.md:1506`). **The trigger condition has been met and the machine
  row still reads otherwise**: D450 measured that the candidate now publishes provider decoders,
  `pem_read_bio_key_decoder` succeeds, and `RT-PUBKEY`'s queue-count observable matches the
  authority, and named the row a **retirement candidate** — "the retirement follows the register's
  own obligation, so it is named here and left for the entry that does it rather than done silently
  in a passing slice". No slice retired it. `forensics/divergence-obligations.json` therefore
  carries it as `trigger_satisfied: false`, `disposition: "open"`, `blocking: false`: it does not
  hold the stratum open, but the register's own text says it should have been removed with the
  boundary it records. **This is recorded, not fixed**, and it is the register's most conspicuous
  live loose end for this stratum.

**The divergence register moved with the evidence five times, and the prerequisite gate forced
four of the edits.** `forensics/prerequisites.json`'s register of
`owned_by_a_later_stratum`/`named_differently`/`modelled_differently` rows went from 18 to **12**
across the table series, because a record that can keep covering a name the crate has since built
can hide the next one: the `v3_bcons.c` table row was retired (D467); the `v3_timespec.c` and
`v3_crld.c` rows were retired and the `v3_skid.c` row narrowed to `ossl_x509_pubkey_hash` (D468);
the `v3_ist.c` row was retired (D469); the `t_x509.rs` row was narrowed to
`ossl_x509_print_ex_brief` (D470); and the `v3_san.rs` and `v3_skid.rs` rows were retired
(D472). Four of the five were reported `divergence_record_does_not_match` on the first pipeline run
of the slice that falsified them; the fifth, D470's narrowing, was made before the run that would
have forced it, because the change that landed `ossl_serial_number_print` is the change that made
the record wrong. This is the gate working in the direction it was built for.

### The defects this stratum's own courts and gates found

These are the phase's *own* findings — candidate transcription defects and evidence-machinery
defects — as distinct from the authority fault boundaries above. Each is marked **fixed** or
**recorded**.

- **The `v3_san.c` raise coordinates were wrong, and the court read them back.** `crypto/x509/
  v3_san.c` is not in `gen_err_raise_sites.py`'s covered set, so D466's predecessor declared its
  `V3_SAN_*` coordinates locally. The differential court reported three as residuals:
  `V2I_GENERAL_NAME_EX`'s missing-value raise read reason `109` where `X509V3_R_MISSING_VALUE` is
  **124**, its unsupported-option raise read `110` where `X509V3_R_UNSUPPORTED_OPTION` is **117**,
  and `ERR_R_ASN1_LIB` was typed `524557` instead of **524301**. All three were re-read from
  `x509v3err.h`/`err.h`, and both reachable sites are now pinned by refusal arms (D466). **Fixed.**
  The allowance to declare coordinates locally is what made the error possible; reading the headers
  back is now part of the write (D467).
- **`ossl_x509_pubkey_hash` was transcribed in the wrong module.** The endgame's first pass put the
  function in `v3_akid.rs`, the module that reaches it, rather than in `crypto/x509/v3_skid.c`, its
  authority unit and its `prerequisites.json` `owner_module`; the intent (avoiding a 72-entry
  partial array) was sound and the result was "one unit's function in another unit's module", which
  is exactly the placement the register's `owner_module` fields exist to make checkable. The
  follow-up moved it to `src/x509/v3_skid.rs`, landed `s2i_skey_id` there, and set the
  `ossl_v3_skey_id` row's `s2i` slot to `s2i_skey_id` rather than the `None` D468 had to publish —
  `crypto/x509/v3_skid.c` now transcribes whole (D472). **Fixed.**
- **`DIST_POINT_set_dpname`'s `set` argument was inverted by a rewrite.** Three modules
  (`v3_crld.rs`, `v3_skid.rs`, `v3_timespec.rs`) already existed as tracked modules, but the slice's
  setup truncated them on the wrong assumption that they were new, so the transcriptions were
  re-derived rather than extended. Two came back whole against the committed text; the `v3_crld.rs`
  re-derivation inverted `DIST_POINT_set_dpname`'s argument, writing `c_int::from(i != 0)` where the
  authority's `X509_NAME_add_entry(dpn->dpname, ne, -1, i ? 0 : 1)` is `i == 0`. No court can name
  the row — it is an internal the admitted DSO does not export — so nothing but reading the
  authority back would have found it, and that is what found it. The file was restored to a
  superset of its committed self with the one inverted bit corrected, and the slice added a
  verification step: a re-derived module is checked against both the authority and its own committed
  self (`git ls-files` would have shown the three were tracked); (D468). **Fixed.**
- **The plan's parsed table rows named `.c` where the authority ships `.c.in`.** The authority ships
  generated sources (`encode_key2any.c.in`, `decode_der2key.c.in`, `file_store.c.in`, …), and
  `plan_reconciliation.py` keys a subphase row's unit by the path it parses, so the rows were
  corrected to the real `.c.in` paths and `forensics/prerequisites.json` gained the unit records
  those corrections need (it now carries 96 unit records). **No plan row was deleted to silence the
  tool** (D473). **Fixed.**
- **The hash-chain lag the pipeline's ordering causes, and this seal's own registration moved it.**
  Several pipeline steps record the sha256 of a file another step writes, so a run in the wrong
  order records the *previous* generation's hash and `evidence_determinism.py` fails on the first
  run and passes on the second (`forensics/tools/pipeline.sh:4-11`). Two instances are live here.
  First, **step order**: `forensics/phase7-obligations.json` records `forensics/phase-state.json`'s
  sha among its inputs (`forensics/phase7-obligations.json:3056-3059`), but `phase_state.py` runs in
  the *phase state* step, after the *ledgers* loop, so the first run after any `phase-state.json`
  change records the previous generation. Second, **glob order**: the ledger loop is
  discovery-driven and lexicographic — `for f in forensics/tools/phase*_obligations.py` expands
  `phase10_…` **before** `phase3_…` through `phase9_…` (`forensics/tools/pipeline.sh:163-166`) — and
  `phase10_obligations.py` records the sha of the phase5 and phase7 ledgers among its inputs
  (`forensics/tools/phase10_obligations.py:338-342`), which are written *later* in the same loop.
  **Registering this seal changed `phase-state.json`'s `seal_sha256`, and the change propagated one
  layer per run** — `phase-state.json` → phase 7/8/9's ledgers (which record it) → phase 10's ledger
  (which records phase 7's) → `court-coverage.json`, `ownership-audit.json` and
  `divergence-obligations.json` (which record the ledgers') — so the tree needed **more than two**
  pipeline runs to reach a fixed point (four for the registration itself), and a later edit to this
  document's line citations moved it again. **Recorded, not fixed**: repairing it would mean ordering
  the loop by phase number and the phase-state step before the ledgers, both changes to
  discovery-driven machinery, and the prescribed remedy is to re-run until the chain settles. This
  document's own verification did exactly that — and one of its later runs was **red**, on the
  pre-existing Phase-8 SM2 test flake §4 records rather than on this stratum's work.
- **The court's own `claim` block carries two clauses later slices falsified.** The `claim` string
  embedded in `forensics/tools/phase10_courts.py` (and so in `artifacts/phase10/COURTS.json:6`)
  still says `OSSL_STORE_load` "remains the one name printed as `pending.`" and that `RT-KEYFORMAT`
  "references the two `i2d_PKCS8PrivateKey_nid_*` writers held pending because `PKCS8_encrypt`
  (10.4) is unlanded". Both were falsified: D473 landed `OSSL_STORE_load` and removed the placeholder
  (`rt_store_probe.c` drives five `store.load.*` arms, and the only remaining `pending.` line is the
  named Phase-13 RSA-verify divergence at `courts/phase10/rt_store_probe.c:852`), and D445 landed
  both `_nid_` writers (the coverage atlas records them `called` by `RT-KEYFORMAT`,
  `forensics/atlas/court-coverage.json:29354,29361`). The row data and the probes are the truth; the
  authored claim prose is stale. **Recorded, not fixed**: the sentence lives in the generator that
  writes the claim, and correcting it is a generator edit this seal does not make.

**Observation counts quoted inside older decision entries are the values current when those entries
were written** and are not this document's counts. `docs/SEAL-CENSUS.md` and
`artifacts/phase10/COURTS.json` are authoritative; a stale count inside a historical record is a
stale sentence, not a missing court. (`docs/DECISIONS.md` cites `RT-STORE` at 60, 159, 181, 716,
774, 806, 865 and 981 across D448–D473 and `RT-PKCS12` at 102, 184, 216, 222, 292 and 317; §3 reads
1038 and 353, and none of the older figures is meant to match.)

**The machine-readable form is what makes the boundaries checkable rather than narrated.**
`forensics/tools/divergence_obligations.py` renders `forensics/divergence-obligations.json` from a
table, and `forensics/tools/phase_state.py` refuses to derive any state while an obligation whose
`current_owner` is the stratum has `trigger_satisfied` true and `disposition` `open`. The register
reads 10 rows and **0 blocking** (`forensics/divergence-obligations.json`'s `counts`), so no live
obligation outran this stratum's derived `complete`; `D-DECODER-ABSENT-1` is `open` but
`trigger_satisfied` false in the machine row, and §9 names it.

**One pipeline failure was observed once and not reproduced.** A batch of four back-to-back
`pipeline.sh` invocations (not the supported one-run-at-a-time path) failed its **first** run at the
provider census, reading 55 of 241 `DEFLT_ENCODERS` rows in `src/provider/encode_key2text.rs`; the
next three runs in that batch failed at later, different checks, and every direct invocation before
and since — and the census tool re-run alone — read all 241, with `cargo fmt --all -- --check` clean
and the file's sha unchanged (`e4309326…`). It is recorded as an **unreproduced instrument
observation** rather than closed, in the shape D458 established: a failure whose cause is unknown
stays open and named, and the supported path was re-run green. It is the same class as the
environment divergence above and is not attributed to this stratum's work.

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with that
   name is defined. `docs/PARITY_MODEL.md` states what each label means; no symbol here is
   `PARITY_VERIFIED`, and `forensics/STATUS.md:311-317` carries the current non-claims. The
   `PARITY_MODEL.md` labels this stratum's evidence reaches are at most `IMPLEMENTED`, plus a
   bounded `SEMANTIC_PASS` over the behaviours its courts exercise — never `PARITY_VERIFIED`.
2. **`libssl` is entirely scaffolded.** All 603 `libssl` exports remain `SCAFFOLDED` and abort when
   called (`docs/SEAL-CENSUS.md:21`, `forensics/STATUS.md:89`); this stratum owns no `libssl`
   export and touches no TLS code.
3. **X.509 verification is Phase 11's, and it is not done.** The pulled-forward subset is the
   certificate *object* graph — the item lifecycles, the codecs, the extension tables, the purpose
   table and enough of `x509_vfy.c` for `X509_self_signed` — and the verify engine proper
   (`x509_vfy.c`'s other names), `X509_STORE_CTX`, `X509_VERIFY_PARAM`, PKCS#7's held-back arms,
   OCSP and CT's verification paths are all withheld with their blockers and remain Phase 11's and
   Phase 12's (D468–D473). **`ossl_x509_check_cert_time` was recorded as a divergence with its
   blocker rather than landed**, because it reads `X509_VERIFY_PARAM`/`X509_STORE_CTX`/
   `X509_cmp_time`, none of which this crate models (D473). Phase 11 derives `not-started`.
4. **A passing court is a differential result over the behaviours its probe exercises, and
   implemented-and-courted is not "is a drop-in replacement".** A symbol recorded `directly_courted`
   is *referenced by a staged candidate probe that ran*; `RT-KEYFORMAT-REF` in particular proves
   only that the candidate distribution defines the inherited names. Nothing here claims stderr
   equivalence, full CLI compatibility, build-profile independence beyond the admitted one, or
   drop-in substitution.
5. **`RT-CODEC` covers rows, not the whole codec surface.** The court drives the rows it names; it
   does not establish that every one of the 318 dispatch symbols behaves as the authority's on every
   arm. `RT-CODEC`'s own claim says so — it is a claim about the rows it drives, "NOT that the other
   572 rows or the remaining decoders are implemented" (`artifacts/phase10/COURTS.json:6`), and the
   abstract-object path is named pending with its blocker.
6. **The correctness plane is not parity, and a `CT-*` pass is not a differential result.**
   `CT-PKCS12` reproduces the pinned corpus's six PKCS#12 KDF stanzas; it says **not** that the
   candidate behaves like the admitted authority, which is `RT-PKCS12`'s question. The corpus is
   mirrored out of the pinned authority's own tree, so it is independent of the implementation
   *code* but **not** independent of the pinned tree, and NIST's own warning applies: using CAVP
   vectors is not itself validation (D201, `artifacts/phase10/COURTS.json:96`).
7. **Nothing about a build profile or platform other than the admitted one.** Linux x86-64 only.
8. **Nothing here is a parity claim about a key's meaning.** A codec that produces the authority's
   bytes for a key this crate can build has not been shown to produce the authority's bytes for
   every key, and the post-quantum encoder rows reach key types whose own strata have their own open
   work (`docs/PHASE-10-SUBPHASES.md:244-248`). A row that cannot be driven is named `pending`
   rather than counted as passing.
9. **The FRF chain entry is a bounded `sensitivity-backed` claim, not parity.** The five
   differential courts' compiled claim (`c39bbb1a…`, §8) binds the authority's first stdout line and
   its exit class for the five courts' fixture families only, with `blockers: []` and
   `excluded_evidence: []`; a `CT-*` pass is construction verification and not OpenSSL parity, and
   the claim's own non-claims are emitted beside it — it does not establish byte-identical stderr,
   full CLI compatibility, or a drop-in replacement for all of the named behaviour (§7, §8, and
   `forensics/frf/README.md` for what the policy means).
10. **Every ledger and coverage count is `docs/SEAL-CENSUS.md`'s.** This document types none of those
    itself; the exceptions are §3's per-court table and the head matter's court and coverage
    figures, each of which names the artefact it was read from.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:38-55`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process (`docs/PHASE-10-SUBPHASES.md:309-317`) — a subphase lands its code, its court and
its regenerated artefacts in **one commit**; every export carries a court edge on the commit that
lands it (D236); every provider row it publishes is named by a probe of a court that covers it
(D245) — and its §4.3 precondition (the reference-basis probe and the runner land **with** the
ledger). Every clause below is checked against a generated artefact rather than asserted.

| criterion | evidence |
|---|---|
| every export is implemented or handed on with the dependency named | `forensics/phase10-obligations.json`: `open_in_this_stratum` 0 and `deferred_to_later_phase` 0; the generator `forensics/tools/phase10_obligations.py` fails closed, so `implemented + deferred + open == owned` |
| every implemented export is observed by a court | `forensics/atlas/court-coverage.json` phase-10 block (`:27251`); `unmatched` 0, enforced for `complete` by `forensics/tools/phase_state.py` |
| both of D201's planes are populated | `artifacts/phase10/COURTS.json`: the differential five and the correctness one are all `pass`, `summary` 6 of 6 and `pending_courts` empty (`:154-159`) |
| every provider row the plan gives this stratum is implemented | `forensics/phase-state.json:476-480` reads `implemented` 636 of `owned` 636; `forensics/atlas/provider-algorithms.json:83` reads `open["10"]` 0; `forensics/atlas/provider-court-coverage.json` reads 0 unmatched |
| no authority fault is reproduced | §5, and `docs/SECURITY_DIVERGENCE_POLICY.md`'s register |
| `ABI-PROTOTYPE`, `ABI-SYMBOL` and `ABI-DYNAMIC` stay clean | `forensics/atlas/ownership-audit.json`: `problems` empty (`:1202`), `implemented_by_two_strata` empty (`:992`) |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 (`:11`) |
| the dispatch plane clean | `forensics/atlas/dispatch-court.json`: `problems` 0 (`:18`) |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` empty (`:602`) |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` empty (`:30`); D473's `.c.in` corrections and their `prerequisites.json` unit records are what got it there |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json:622` |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |

**`docs/RELEASE_GATES.md` §2's ten items, each checked rather than assumed.** The first column is
the authority's own list (`docs/RELEASE_GATES.md:38-55`); the second says what this stratum's
evidence for it is, and, where an item is **not met**, says so plainly rather than leaving the row
empty.

| # | item | this stratum's evidence |
|---|---|---|
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json:39` pins `openssl-3.6.4-production`; `artifacts/phase10/COURTS.json:2` names it |
| 2 | obligation inventory | `forensics/phase10-obligations.json` (`:5-12`), and, for the provider rows, `forensics/atlas/provider-algorithms.json` |
| 3 | court manifests | `artifacts/phase10/COURTS.json` |
| 4 | raw captures | **met in both venues.** The five staged `artifacts/phase10/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (`artifacts/phase10/COURTS.json:19-22`), and `.frf/captures/` carries fifteen Phase-10 runs — the real run and the two challenged runs of each differential court (§8) |
| 5 | residual set | **met.** Every differential court's `residual_count` is 0 (`artifacts/phase10/COURTS.json:14-91`), `CT-PKCS12`'s `vectors_failed` is 0, and every Phase-10 receipt's `residuals` list is empty. The ten Phase-10 records in `.frf/residuals/` are the challenges' seeded-defect observations — two axes on each court, on the mutated candidate hashes rather than the real one — which is what a challenge is for (§8) |
| 6 | mutation / sensitivity evidence | **met.** Ten challenge records — both declared axes on each of the five differential courts — every one adjudicated, and the claim is `sensitivity-backed` (§8); `forensics/frf/README.md:160` counts 86 runtime courts, the Phase-10 five among them |
| 7 | resolution runs | **not applicable, and therefore not met.** No `fixed` disposition attaches to an FRF residual of this stratum (`--resolution-run` is required only for `fixed`); the register's one `fixed` row is a divergence obligation, not an FRF residual |
| 8 | FRF receipts | **met.** Five `.frf/receipts/` records — one per differential court — each with an empty `residuals` list (`receipt-run-openssl-rs-rt-{keyformat-ref,codec,keyformat,pkcs12,store}-…`; §8) |
| 9 | generated parity projection | `forensics/STATUS.md` (`:92-101`), rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s head change is Phase 10's `C95` (`:13`) and its `current:` is `K49` — `checkpoint.c26506bf…` (`:156,163`), the state `C95` leaves; one checkpoint, because this stratum's chain carries no finding, fix or disposition (§8) |

**Nine of the ten items are met — 1, 2, 3, 5, 6, 8, 9 and 10, with item 4 met in both
venues — and item 7 is not applicable rather than wanting: `--resolution-run` is required only for a
`fixed` disposition, and none attaches to a Phase-10 FRF residual, because the ten residual records
the challenges produced are all `open` by design.** The stratum entered the FRF chain and produced
the declarations, captures, receipts, challenges, claim and checkpoint §8 describes, with
`blockers: []` and `excluded_evidence: []`. Item 10's checkpoint, `K49`, is the state this stratum's
head change leaves, and it has landed (§8).

## 8. FRF and Gemel

Phase 9's chain entry shows what one requires, and D424 fixes it: rows added to `forensics/tools/
gen_frf_courts.py`'s `COURTS` table — one per **differential** court, each naming the
`artifacts/phase<N>/probes/<probe>.{authority,candidate}` pair the court stages and the
`courts/phase<N>/<probe>.c` it was compiled from — then the store **added to** rather than recreated,
producing one receipt and two challenge records per court, a compiled `sensitivity-backed` claim, and
a Gemel checkpoint. D413 and D424 are also explicit that the vector-driven `CT-*` courts **cannot**
be declared, because such a court has no authority transcript to diff and no fixture a challenge
could locate (D13, D201). That is why the entry below covers the five differential courts and not
`CT-PKCS12`: the correctness court is §3's other plane, not a chain subject.

**Phase 10's chain entry now exists, and every object it produces is on disk.**

- **Five declarations.** `forensics/tools/gen_frf_courts.py`'s table gained a Phase 10 block —
  `("rt-keyformat-ref", 10, …)` through `("rt-store", 10, …)`
  (`forensics/tools/gen_frf_courts.py:470-484`, the table closing at `:485`; D475 landed this manifest
  half) — and the generated declarations are under
  `forensics/frf/courts/openssl-rs-rt-{keyformat-ref,codec,keyformat,pkcs12,store}`.
  `gen_frf_courts.py --check` reads `ok: 172 file(s) match the table (86 courts)`, and
  `forensics/frf/README.md:162` counts **86 runtime courts** — ten Phase 3, seventeen Phase 4, nine
  Phase 5, seven Phase 6, nineteen Phase 7, fifteen Phase 8, four Phase 9 and the Phase-10 five.
  `CT-PKCS12` carries no row, for the D413 reason above.
- **Five receipts, ten challenges, fifteen captures.** One receipt per court, each with an empty
  `residuals` list; both declared axes challenged and adjudicated on each court; and three runs
  captured per court — the real run and the two challenged runs. They are in `.frf/receipts/`,
  `.frf/challenges/` and `.frf/captures/` under the
  `openssl-rs-rt-{keyformat-ref,codec,keyformat,pkcs12,store}` names.
- **One `sensitivity-backed` claim.**
  `c39bbb1a6f3b95a984f0bbb9b02d61f747d0410c331e9a8dbb21af3a7cd9f69b` binds authority
  `openssl-rt-3.6.4-r2` to candidate `openssl-rs 0.0.23` (`identity_hash e4f60d8b…`) over the five
  differential courts, with `blockers: []` and `excluded_evidence: []`
  (`.frf/claims/c39bbb1a….json`). **The identity moved with the 0.0.23 release.** The store was
  recreated from clean at candidate 0.0.23 — FRF run identities are content-addressed on the
  declaration, which carries the candidate version, so every claim identity moves with a release —
  and the id quoted here supersedes the previous generation's `27857c64…`, the 0.0.19 claim. Every
  one of its five
  premises carries both axes —
  `observable_scope [stdout, exit]`, relation `eq(stdout-first-line), eq(exit-code)` — so no cell is
  narrowed, unlike Phase 8's `rt-ec`.
- **One Gemel checkpoint, `K49`.** `forensics/GEMEL_TRAJECTORY.md`'s head change is `C95` — "Phase 10
  joins the FRF chain, and all five courts' premises are clean on both axes"
  (`forensics/GEMEL_TRAJECTORY.md:13`) — and its `current:` is the state that change leaves,
  `checkpoint.c26506bf0280601d6dda185e0ae98d418f5e3a68b409ac4918ff9256f200ba37`, listed as `K49`
  (`forensics/GEMEL_TRAJECTORY.md:156,163`). **One checkpoint rather than the three Phase 8 needed**,
  because this stratum's chain contains no finding, fix or disposition for the trajectory to carry in
  order: the five courts' real runs raise no residual on a claimed surface, the claim compiles with
  zero blockers and no narrowed cell on the first pass, and the only residuals the chain produces are
  the ten mutant residuals of the challenge records, which are open by design because a mutant's
  divergence is the challenge's evidence.

**What the seal does *not* do is invent any of these objects.** The declarations, the receipts, the
challenges, the captures, the claim and the checkpoint are produced by running the chain in the FRF
tooling container, never on the host, and all six are cited above from disk —
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase10-obligations.json`'s
`deferred` list is empty (`:13`) and its `deferred_by_phase` is empty (`:14`), and the census reads
`deferred to a later stratum with a stated reason: 0` (`docs/SEAL-CENSUS.md:341`). Every export this
stratum owns is implemented, and the 26 it *received* are discharged rather than passed on. The
`handed_on` figure in the provider census — `forensics/phase-state.json:477` reads 39, and
`forensics/atlas/provider-algorithms.json:77` reads `handed_on["10"]` 39 — is provider
*registration* rows the plan gives later strata, not exports this stratum left unwritten; the
projection derives it from `owning_phase` rather than storing it (D295).

**The immediate next actions this seal's own findings point at**, recorded so they are not lost:

- **The FRF chain entry has landed.** §8's subject: five declarations, the five receipts, ten
  challenges and fifteen captures they produced, the compiled `sensitivity-backed` claim
  `c39bbb1a…`, and the `K49` checkpoint the chain leaves. `CT-PKCS12` is recorded as not declarable —
  a vector-driven court has no authority transcript to diff and no fixture a challenge could locate
  (D413) — so the entry covers the five differential courts and names that omission with its reason.
  No object of the entry is still owed.
- **Retire `D-DECODER-ABSENT-1`.** Its trigger condition has been met (D450); the register row
  should be removed with the boundary it records, and the machine table's `trigger_satisfied` set
  true in the transition (§5).
- **Correct the two stale clauses in `phase10_courts.py`'s `claim` string** (§5): the `nid` writers
  and `OSSL_STORE_load` are both landed and the sentence that says otherwise is authored prose the
  generator still emits.
- **Land `X509_check_cert_time`** when Phase 11 models `X509_VERIFY_PARAM`, `X509_STORE_CTX` and
  `X509_cmp_time`; this stratum recorded it as a divergence with its blocker rather than fabricate
  an out-of-unit type to land it (D473).
- **`PKCS7` is now partly built but is still Phase 12's header.** The `data`/`digest`/`encrypted`
  arms landed for PKCS#12 (D442); the `signed`/`enveloped`/`signedAndEnveloped` arms and the rest
  of the `pkcs7.h` exports are Phase 12's, and no Phase-12 evidence, ledger, plan, seal or state
  row was created.
- **`forensics/phase10-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and coverage figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections the phase-10 decision record **D438–D473** made to earlier
statements, the corrections this seal makes to the plan's own account, and the corrections the
evidence forced rather than the ones a reviewer might have preferred.

1. **The plan's §6 ledger line is a dated measurement, and the seal states the drift rather than
   the number.** `docs/PHASE-10-SUBPHASES.md:434-439` reads the D451-era `286 implemented / 12 open`
   exports and `634 implemented / 2 open` provider rows; `forensics/phase10-obligations.json:5-12`
   and `forensics/phase-state.json:476-480` now read `298 / 0` and `636 / 0`. The plan flags its §6
   as a measurement of a moment ("no export, no row … is created, and Phase 11 still derives
   `not-started`") and its §7's closing narrative carries the up-to-date figures; the ledger and
   census are authoritative for the present, and this seal restates none of them here.

2. **The plan's §5 status clauses are activation-time, and the seal cites the ledger instead of
   them.** `docs/PHASE-10-SUBPHASES.md:328-348` reads "Eighty-seven" landed and "Two hundred and
   eleven" open — the state at activation, before Phase 10's own work. `docs_consistency.py`'s
   active-stratum status gate does not judge them because the stratum is `complete`, so they are a
   historical record rather than a live claim; the census's row (`docs/SEAL-CENSUS.md:38`) is the
   current one.

3. **The plan's §2 ordering was wrong twice, and the decision record corrected it.**
   `crypto/pkcs7/`'s object and ASN.1 are a prerequisite of 10.2/10.3, not Phase 12-only work
   (D442), and `encode_key2any.c`'s true prerequisite is Phase 11's `PKCS5_pbe*set*_ex`, not 10.6 and
   10.4 (D443/D444). The plan's §2 now says so
   (`docs/PHASE-10-SUBPHASES.md:187-202`), and §3.2's expectation that the `PFX` structure is
   byte-comparable **in 10.2** cannot hold for the same reason (D440).

4. **The plan's §6 conclusion that 10.14 "cannot be cut at unit granularity" was corrected: the cut
   is at the call graph.** D451 proved a function-level cut of the 75-unit, 30,711-line
   strongly-connected component is possible — each function whose closure is unlanded is withheld by
   name rather than the unit that contains it — renumbered the section `10.8`–`10.15` (it had reused
   `6.1`–`6.8`, colliding with `PHASE-6-SUBPHASES.md`), and kept the old conclusion visible. The
   collision also exposed a real tooling defect: `plan_reconciliation.py` keyed a subphase row's
   state by the bare subphase id, so two plans that both numbered a section `6.1` overwrote each
   other's state; the key is now plan-scoped (`{phase}:{heading}`).

5. **§7's numeric order is not closure-ordered, and the readiness re-measurement moved it three
   times.** D458 recorded that 10.14.3 is not the next ready row; D459's whole-unit cascade found
   **no** `10.14.N` row closure-ready at row granularity and assigned three units the table had
   never named (`x509_ext.c` to 10.14.5, `v3_info.c` to 10.14.6, `v3_pmaps.c` to 10.14.9); and D461
   cut `v3_utl.c` at the function level. **D461's count of `ossl_x509v3_cache_extensions`'s
   remaining names was six; D463 corrected it to seven** (`BASIC_CONSTRAINTS_free` in `v3_bcons.c`
   was omitted). The plan's §7 now records each re-measurement rather than a fixed order.

6. **D462's leading explanation was falsified by D466, and the seal states which was which.** D462
   judged the one unreproduced `cargo test --lib` failure most likely a run against a mid-edit tree
   and wrote down its own falsification criterion: *a failure on a committed, clean tree*. D466's
   failure met it — the parallel-suite panic came from five `evp::algorithm` tests sharing
   `process-global` state without `lock_global_state`, a real parallel-safety defect. The correction
   is stated here rather than left in D466 alone: the mid-edit story was reasonable and wrong, and
   only a written criterion made that visible.

7. **The locally-declared `v3_san.c` raise coordinates were wrong, and reading the headers back is
   now part of the write.** D466 found reason `109` where `X509V3_R_MISSING_VALUE` is 124, reason
   `110` where `X509V3_R_UNSUPPORTED_OPTION` is 117, and `ERR_R_ASN1_LIB` typed `524557` against its
   own `524301`. D467 states the cost of the local-declaration allowance and makes the reading part
   of the write. §5 records the fix.

8. **A rewrite inverted `DIST_POINT_set_dpname`'s argument, and the correction is the file's own
   history.** D468 records that three tracked modules were truncated on the assumption they were
   new and re-derived; two came back whole, the third did not, and the inverted bit was found by
   reading the authority back rather than by any court, because no court can name the row. §5
   records the fix and the added verification step.

9. **`ossl_x509_pubkey_hash` was placed in the wrong module, and the placement is what the
   register's `owner_module` fields exist to check.** D472 records the misplacement in `v3_akid.rs`
   and its correction to `src/x509/v3_skid.rs`, with the `s2i` slot published rather than left
   `None`. §5 records the fix.

10. **The register's `fixed` for `D-PKEY-AMETH-1` was not earned until D439, and it is the first
    time the divergence machinery's own record was contradicted.** D427 classified the row `fixed`
    on the register's "superseded" text; D438's driving of the decoder path measured
    `EVP_PKEY_get_id` answering `EVP_PKEY_KEYMGMT` where the authority answers the real NID, so the
    `fixed` was wrong until D439 corrected the transcription (a crate-local
    `evp_pkey_set_type_by_keymgmt` that passed `str = NULL`) and re-measured. The mechanism caught
    its own record, which is the direction D427 built it to fail in.

11. **The plan's parsed table rows named `.c` where the authority ships `.c.in`, and the correction
    is D473's.** The generated sources are `encode_key2any.c.in`, `decode_der2key.c.in`,
    `file_store.c.in` and their kind; `plan_reconciliation.py` keys a row's unit by the path it
    parses, and `forensics/prerequisites.json` now carries the 96 unit records the corrected rows
    need. **No plan row was deleted to silence the tool** (D473).

12. **The court's authored `claim` prose is stale in two places, and this seal records it rather
    than quoting it as current.** `forensics/tools/phase10_courts.py`'s `claim` string still says the
    `i2d_PKCS8PrivateKey_nid_*` writers are held pending and that `OSSL_STORE_load` remains the one
    name printed `pending.`; both were falsified by D445 and D473 respectively, and the row data and
    probes are the truth (§5). This is the one correction this seal makes to the evidence's own
    prose, and it is a generator edit left for a later session rather than one this document
    performs.

13. **Observation counts inside older decision entries are historical.** §5's closing note. They are
    not restated, they are not corrected in place, and they are not this document's counts.
