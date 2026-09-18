# Phase 7 — the EVP framework: seal

**STATUS: complete.** Every export this stratum owns is either handed to a named later stratum
with the dependency it is waiting on, or **referenced by a differential court that ran**. That
second phrase is deliberately the weaker one. `forensics/atlas/court-coverage.json` -- generated
by `forensics/tools/court_coverage.py` and required for `complete` by `forensics/tools/phase_state.py`
-- partitions every implemented export into `directly_courted`, `indirectly_courted` and
`non_observable` with no unmatched symbol, and defines `directly_courted` as *an undefined
dynamic symbol of a staged candidate probe that ran and produced a transcript*. That is a proof
of **reference**, not a proof that every arm of the symbol was driven; the atlas's own `claim`
says so, and it is the reading this seal adopts. `open_in_this_stratum` in
`forensics/phase7-obligations.json` is **zero**, and `forensics/phase-state.json` derives
`complete` only because every earlier stratum is complete, this one's obligations are closed, and
its coverage join is clean. The coverage counts are `docs/SEAL-CENSUS.md` §Court coverage.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which is generated from the
ledgers and the court results by `forensics/tools/render_seal_census.py`. This seal cites that
document rather than restating its arithmetic, because a number typed here is a number that can
drift from the evidence it summarises (D97). The one table this document *does* carry — §3's court
list — is copied from `artifacts/phase7/COURTS.json`, and it says so.

This is **not** a claim that openssl-rs is a usable OpenSSL, and it is **not a parity claim**.
`docs/PARITY_MODEL.md` is the authority on what the labels mean: `implemented` means a symbol with
that name is defined, and a passing bounded court is a differential result over the behaviours that
court exercises. `PARITY_VERIFIED` is not claimed for any symbol here, and `forensics/STATUS.md`
carries the current figures. All `libssl` exports remain `SCAFFOLDED` and abort when called.

- Authority: `openssl-3.6.4-production` (with `openssl-3.6.3-historical` admitted for the
  oracle-versus-oracle trajectory in `docs/SECURITY_DIVERGENCE_POLICY.md`)
- Court results: `artifacts/phase7/COURTS.json` — nineteen courts, all pass, zero residuals. **The
  totals are `docs/SEAL-CENSUS.md`'s**; the per-court table is §3.
- Obligation ledger: `forensics/phase7-obligations.json` — **0 open in this stratum**
- Court coverage: `forensics/atlas/court-coverage.json` — every implemented export in exactly
  one of `directly_courted` / `indirectly_courted` / `non_observable`; the counts are
  `docs/SEAL-CENSUS.md` §Court coverage, and the weaker meaning of `directly_courted` is stated
  there and above (D199)
- Derived state: `forensics/phase-state.json`
- Deciding record: `docs/DECISIONS.md` **D139–D196** (§4's table), with D132 and D134 being the two
  entries Phase 6 wrote for this stratum's prerequisites; and `docs/PHASE-7-SUBPHASES.md` for the
  subphase plan this seal closes

## 1. What this phase owns, and how that was decided

Phase 7 is the **algorithm-independent** half of `libcrypto`'s public surface: the fetch layer that
turns a name and a property query into a method, the method stores and their caches, the `EVP_*`
object families that hold a method plus its parameters, and the `EVP_PKEY` layer that is those
objects bound to a key. It is not the algorithms — AES, SHA, RSA, the KDFs' derivations, the MACs'
compressions and the signature schemes' arithmetic are Phases 8, 9 and 13's. What this stratum owns
is the machinery every one of them is reached *through*.

The scope was not chosen; it was derived, and each step is a file a reader can check:

- **the export set** is the projection of `forensics/atlas/symbol-ownership.json` for phase 7. The
  atlas assigns every one of the authority's exports to exactly one owner by the header that
  declares it, and `ownership_audit.py` reports `implemented_by_two_strata = 0` and
  `unowned_implemented = 0` over it. Phase 5 handed twenty-six symbols in, and
  `ownership-audit.json`'s `handoff_reconciliation` reads that edge with `mismatched: 0`.
- **the internal surface** is `evp_fetch.c`, `crypto/property/property.c`'s store object,
  `core_algorithm.c`, `core_fetch.c`, `digest.c`, `evp_enc.c`, `evp_lib.c`, the nine method-class
  files, the `EVP_PKEY` layer's ten and the BIO/encoding/PEM bridges. The prerequisite gate answers
  whether each is built or owed to a stratum; `forensics/atlas/prerequisite-gate.json` records
  `findings: 0` and a `blocking_dependencies` list that is now **later strata only**.
- **the declaring headers** are `evp.h` (832 of the 950 owned rows), `kdf.h` (40), `hpke.h` (20),
  `hmac.h` (12), `cmac.h` (9), `pem.h` (34) and `asn1.h` (3), which is `forensics/phase7-
  obligations.json`'s `owned_by_header`. The asymmetry is worth stating: `libcrypto` accounts for
  all of it and Phase 7 adds **nothing** to `libssl`.

Two properties of the set were established rather than assumed, and both are named because a reader
would otherwise take them for conveniences:

- **the stratum owns glue that lives in other directories.** `crypto/asn1/ameth_lib.c`'s twenty-six
  `EVP_PKEY_ASN1_METHOD` accessors, `crypto/asn1/i2d_evp.c`, `d2i_pr.c`, `d2i_param.c`, `d2i_pu.c`
  and `crypto/pem/pem_pkey.c`'s sixteen are declared in `evp.h`/`pem.h`, so ownership follows the
  header that promises the symbol rather than the directory it was written in.
- **the stratum owns wrappers whose primitives are later strata's.** The legacy `EVP_CIPHER` and
  `EVP_MD` statics are `evp.h`'s and their primitives are Phase 13's, so they are recorded here as
  hand-offs with the primitive unit named rather than moved to a stratum that would then own a
  symbol it does not declare.

## 2. What has been built

| subphase | what it is |
|---|---|
| 7.0 | the ledger, and the stratum's wiring: every one of the 950 rows has a disposition, `ownership_audit.py` reads it, `phase_state.py` derives the state from it |
| 7.1 | the fetch core: `crypto/core_algorithm.c`'s walk whole, `crypto/core_fetch.c`'s `ossl_method_construct` and its five callbacks, and the `OSSL_METHOD_STORE` object in `src/property/store.rs` (D140, D141, D142) |
| 7.2 | the fetch surface and the default properties: `evp_generic_fetch` and its `mcm` callbacks, `evp_names_do_all`, `evp_is_a`, and the whole default-property surface (D145, D146, D147) |
| 7.3a–g | the symmetric method objects and their wrappers: `EVP_MD`, `EVP_CIPHER`, the cipher context, `EVP_MAC`/`EVP_KDF`, `EVP_RAND`/`EVP_SKEY`, `names.c` and the adders, and one hundred and sixty-four legitimate hand-offs to Phase 13 with a primitive unit named for each (D148–D162) |
| 7.4 | the `EVP_PKEY` layer: the method, keymgmt, signature, asym-cipher, KEM and exchange classes; `ctrl_params_translate.c` whole; `pmeth_gn.c` whole; the ASN.1 glue; `m_sigver.c` whole; the PBE registry; and the ten names that read no method table (D163–D177, D181, D184, D186–D193) |
| 7.5 | the BIO, encoding and PEM bridges: the twelve `EVP_Encode*`/`EVP_Decode*` names, the four BIO filters, ten `PEM_*` names, and the Phase-5 hand-offs' disposition on both sides (D194) |
| 7.6 | the MAC, KDF and HPKE header surfaces: `crypto/hmac/hmac.c`'s twelve, `crypto/cmac/cmac.c`'s nine plus the internal `ossl_cmac_init`, and nineteen of `crypto/hpke/hpke.c`'s twenty (D195) |
| 7.7 | this seal, and the closure reconciliation (§10) |

Three of those rows are worth a sentence more than the table gives them, because they are the
places where the stratum's shape was decided rather than followed.

**7.3g is not a deferral of convenience.** Its one hundred and sixty-four rows name Phase 13 *and*
the primitive unit each static's callbacks call (`crypto/aes/`, `crypto/sha/`, …), which is the same
standard the twenty-six Phase-5 hand-offs met when they arrived. What can be done there *is* done:
the four `names.c` walkers, the two adders, the two legacy lookups and the two null methods, each of
which needs nothing from Phase 13.

**7.4's dependency set was wrong, and it is the largest inversion the project has found** (D163).
`pmeth_lib.c`'s and `ameth_lib.c`'s `standard_methods[]` tables are the algorithm strata's method
objects, so the part of 7.4 reachable only through them cannot be written before Phase 8. The
measurement that made that actionable rather than blocking is that implementing one export of a unit
owes that unit's **header-declared** internals and not its file-local statics.

**7.4l's deferral is per symbol, and that is the rule this seal inherits** (D165): a name whose
declaring header is this stratum's but whose body needs a later stratum's symbol is recorded as a
deferral *to that stratum*, with a reason that names the callee, the file and the phase — never as a
stub that answers something plausible.

## 3. The evidence

Each court is a C probe in `courts/phase7/` compiled twice — once against the admitted authority's
headers and library, once against the candidate's generated headers and `artifacts/phase2` — run on
the same machine, and diffed line by line on `key=value` so one divergence produces exactly one
residual instead of shifting every following line.

The table below is **copied from `artifacts/phase7/COURTS.json`** (`courts[].court`, `.verdict`,
`.authority_observations`), which is the file the pipeline re-derives on every push. The totals are
`docs/SEAL-CENSUS.md`'s and are not typed here (D97).

| court | one-line subject | verdict | observations |
|---|---|---|---|
| `RT-FETCH` | the fetch core, from the one angle a probe can be asked in 7.1 | pass | 217 |
| `RT-EVP-CIPHER` | the `EVP_CIPHER` method object, from the angle 7.3b can be asked in | pass | 185 |
| `RT-EVP-MAC` | the `EVP_MAC` method object and the context it is run through | pass | 96 |
| `RT-EVP-KDF` | the `EVP_KDF` method object and the context it is run through | pass | 68 |
| `RT-EVP-RAND` | the `EVP_RAND` method object and the context it is run through | pass | 168 |
| `RT-EVP-SKEY` | the `EVP_SKEYMGMT` method object and the `EVP_SKEY` it manages | pass | 97 |
| `RT-EVP-KEYMGMT` | the `EVP_KEYMGMT` method object, and the structural check that admits it | pass | 73 |
| `RT-EVP-NAMES` | `names.c`'s four walkers and the two adders | pass | 25 |
| `RT-EVP-PKEY` | `crypto/evp/signature.c`'s entry-point half and `p_lib.c`'s provider half, differentially | pass | 502 |
| `RT-EVP-PBE` | the PBE registry, the PBKDF2 facade and the three v2 keygens | pass | 442 |
| `RT-EVP-BIO` | `crypto/evp/encode.c`'s four base64 contexts and the four filter BIOs of `crypto/evp/` that 7.5 lands | pass | 154 |
| `RT-EVP-PEM` | the `pem.h` surface 7.5 can build, and the twenty-five names it cannot | pass | 80 |
| `RT-HMAC` | the legacy one-shot interface `crypto/hmac/hmac.c` | pass | 32 |
| `RT-CMAC` | the legacy CMAC interface `crypto/cmac/cmac.c` | pass | 26 |
| `RT-HPKE` | the RFC 9180 `OSSL_HPKE_*` surface, `crypto/hpke/hpke.c` | pass | 65 |
| `RT-EVP-REF` | reference basis for the EVP plane's unexercised entries, and nothing more | pass | 264 |
| `RT-EVP-INTROSPECT` | the method-table and legacy-header surfaces the behavioural probes did not reach | pass | 48 |
| `RT-EVP-CLASS` | the four provider-only method classes the behavioural probes never fetched: `EVP_ASYM_CIPHER`, `EVP_KEM`, `EVP_KEYEXCH` and `EVP_SIGNATURE` | pass | 22 |
| `RT-EVP-PKEY-OPS` | the `EVP_PKEY_CTX` accessor surface and the `EVP_PKEY` operation entry points, driven through a keymgmt this probe publishes | pass | 100 |

Each court's one-line subject is the same line `forensics/tools/phase7_courts.py` carries beside
its probe filename and `forensics/tools/gen_frf_courts.py` carries in its Phase 7 `COURTS` rows
(D200). Before D200 the generator's table named the probe but not the subject, so the sentence that
used to stand here — that what each court covers "in one line" was that table — pointed at a field
that did not exist; the field now exists in all three places and this table carries it. The table
is also the correct count: it was fifteen rows while `artifacts/phase7/COURTS.json` held nineteen
after the four D199 courts landed.

`RT-EVP-PKEY` is also the only probe that drives an export this seal added: `EVP_PKEY_new_mac_key`
(§10). Its arm publishes an `HMAC` key type in the **default** library context, because
`OBJ_nid2sn(EVP_PKEY_HMAC)` is `"HMAC"` and `EVP_PKEY_CTX_new_id` resolves it there, and it observes
the generation callbacks and the arrived `priv` octet string rather than the pointer alone — a
transcription that dropped `EVP_PKEY_CTX_set_mac_key` would still answer non-NULL.

Four other instruments are part of this stratum's evidence, and none of them is a court:

| instrument | its artefact | finding |
|---|---|---|
| the prototype court | `forensics/atlas/prototype-court.json` | `mismatches` 0, `type_mismatches` 0, `unclassified` 0 over the implemented surface; its two `no_prototype_in_atlas` and `implementation_is_c` headings are reported rather than counted as passes |
| the dispatch plane | `forensics/atlas/dispatch-court.json` | `problems` 0 — every `OSSL_FUNC_*` identity the crate declares agrees with the authority's macro value, and every function-pointer alias resolves. D180 built it and D182 made it a seal requirement; it is not a stratum and has no plan row of its own |
| the prerequisite gate | `forensics/atlas/prerequisite-gate.json` | `findings` 0 over the authority-internal names the crate references |
| the plan reconciliation | `forensics/atlas/plan-reconciliation.json` | `findings` 0 — every unit and every internal function a complete stratum's plan names is reached or has a record saying which stratum owns it |

The last of those is where this stratum's closure needed work rather than reading. Fifty-six units
the phase-7 rows name are reached or handed on but invisible to that tool's three mechanical
signals, and the file it reads for exactly that case is `forensics/prerequisites.json`'s `units`
block. §10 records the split; `plan-reconciliation.json`'s `units_named_by_a_row` and
`units_reached` are now equal, and its phase-7 census is the two entries that are records about the
plan itself rather than omissions.

**6. The coverage claim in this seal was not machine-checked, and now it is** (D199). The opening
paragraph used to say every implemented export is "observed by a differential court", but the two
exit criteria that were checked -- `open_in_this_stratum == 0` and `every court passes` -- do not
imply it: nothing joined the 706 implemented exports to the courts that ran. The join now exists.
On its first run it found **264** of this stratum's implemented exports referenced by no staged
candidate probe (and 488 across the completed strata 3-7). The remedy was to make them observable,
in this order:

* `RT-EVP-INTROSPECT` calls the `EVP_PKEY_METHOD`/`EVP_PKEY_ASN1_METHOD` setter-getter pairs, the
  `EVP_MD_meth_*` and `EVP_CIPHER_meth_*` pairs, `EVP_MD_CTX_copy` and the password-prompt pair,
  and moves **75** exports to basis `called`;
* `RT-EVP-CLASS` publishes one `EVP_ASYM_CIPHER`/`EVP_KEM`/`EVP_KEYEXCH`/`EVP_SIGNATURE` method
  from a provider inside the probe and calls each class' accessors, moving **42**;
* `RT-EVP-PKEY-OPS` publishes a keymgmt, generates a key, and drives the `EVP_PKEY_CTX_*` and
  `EVP_PKEY_*` accessors, moving **84**;
* the remaining **63** are recorded at basis `referenced` by `RT-EVP-REF`, which takes their
  address and prints `nonnull` and nothing more. They are listed in the atlas; the largest groups
  are the `EVP_CIPHER_CTX_*` accessors and the legacy `EVP_*Init*` wrappers (which need an armed
  cipher context), the `EVP_PKEY` operation entry points (`EVP_PKEY_encrypt_init` and its siblings,
  which fault the released authority for a provider key with no operation), the `EVP_*_SKEY`
  family, and the `EVP_PKEY_asn1_find`/`get0`/`get_count` readers (Phase 8's `standard_methods[]`).

The atlas records `indirectly_courted` 0 and `non_observable` 0: no symbol was excused. What it
does **not** claim, and this seal does not either, is that the 63 referenced-only names were
driven; `directly_courted` is a reference-level result and the atlas says so in its own `claim`.
The same join runs for strata 3-6, where 224 further exports are covered at basis `referenced` by
`RT-RUNTIME-REF`, `RT-BIO-CONF-REF`, `RT-BN-ASN1-REF` and `RT-PROVIDER-REF`; moving those to
`called` is the follow-up those strata's seals now cite rather than the thing this slice did.

## 4. What the courts found

Every subphase was corrected by its own court or by reading the authority beside the candidate, and
the corrections are the reason the courts exist rather than a by-product of them. The stratum's
deciding record is D139–D196; the table is the register of them, one line each, read from
`docs/DECISIONS.md`'s own headings.

| decision | what it settled |
|---|---|
| D139 | Phase 7 opens: the plan, the ledger, and three registries turned into rules |
| D140 | 7.1's first half: the algorithm walk, and D132's deferral discharged |
| D141 | 7.1's second half: the walk's six callbacks, the error-coordinate surface, and a store a sealed stratum still owed |
| D142 | the method store's object layer, and the checked invariant that fired exactly as designed |
| D143 | the store's query path, and a plan claim the authority's own build record contradicts |
| D145 | 7.2's first half: Phase 7 has exports, and a probe that lied to itself |
| D146 | 7.2's fetch half: the `mcm` interface, and every Phase-7 blocker discharged |
| D147 | 7.2 closes, and its exit criterion is corrected rather than claimed |
| D148 | 7.3a: the `EVP_MD` object, and the first exports Phase 7 can be fetched through |
| D149 | 7.3a's court: the resolver lands, and it finds the fetch's failure reason wrong |
| D151 | 7.3b: the `EVP_CIPHER` method object, and a Phase-6 defect four phases of callers could not see |
| D152 | 7.3c's dependency map, measured before the slice is attempted |
| D153 | 7.3c-i: the context, its parameters and initialisation, and two faults the court met |
| D154 | 7.3c closes: the data path, and 7.3c's twelve exports observed end to end |
| D155 | 7.3d's first half, and the prototype court refusing a macro-generated export |
| D156 | 7.3d-ii: the `EVP_MD_CTX` object, and three NULL callback calls measured rather than guessed |
| D157 | 7.3e-i: the first class with no legacy half, and a fault found by transcribing `EVP_MAC_CTX_dup` |
| D158 | 7.3e closes: the `EVP_KDF` class, and a reference leak in the MAC class that its twin found |
| D159 | 7.3f's first half: `EVP_RAND`, the class whose constructor has three arguments and whose release is a chain |
| D160 | 7.3f closes: `EVP_SKEYMGMT` and `EVP_SKEY`, and the prototype court refusing a signature its own transcription read wrong |
| D161 | `OPENSSL_INIT_ADD_ALL_CIPHERS` is accepted, not refused; found by a court reading the error queue |
| D162 | 7.3g closes: the two walkers, the two adders, the two lookups, and one hundred and sixty-four hand-offs with a primitive named for each |
| D163 | 7.4's dependency set was wrong: its legacy registry half is Phase 8's, and the gate could not have said so |
| D164 | 7.4a's first slice lands `keymgmt_meth.c` whole, and the seven `p_lib.c` names are disposed of one at a time |
| D165 | 7.4l's deferral is per-symbol, and neither the source nor the relocations alone can compute it |
| D166 | 7.4c-i's prerequisite movement is recorded once per compared ref, and the guard needed a row for the push baseline |
| D167 | `ossl_assert` under `NDEBUG` is a live refusal, and six doc comments said the released authority proceeds |
| D168 | 7.4b-iii's first unit: `asymcipher.c`'s operation half, and `evp_pkey_ctx_is_legacy` is a header macro |
| D169 | `pmeth_check.c` lands early, because 7.4b-iii reaches into it |
| D170 | `exchange.c`: two wrong callback types in landed code, and the evidence plane that cannot see them |
| D171 | `signature.c`'s operation half is blocked on `ctrl_params_translate.c`, and three accessors land instead |
| D172 | 7.4c-ii's dependency map, and a divergence between the vendored header source and the built one |
| D173 | `pmeth_gn.c` lands, `evp_pkey_free_legacy` stops being a deferral, and a court's class label cannot tell a typedef from its expansion |
| D174 | the rest of 7.4c-ii's row, scoped: `evp_pbe.c` is gated on Phase 12, and the p5 units on one ASN.1 item |
| D175 | two more gates on 7.4c-ii's row, and the two raw-key getters that have none |
| D176 | the `EVP_PKEY_asn1_*` family is landable inside Phase 7, and the crate's own doc says it is not |
| D177 | `EVP_PKEY_ASN1_METHOD` transcribed: forty-one members, ten types to declare, and two exports that need none of it |
| D178 | the mutators' signatures need named aliases, and the type plane is why |
| D179 | D178's diagnosis was wrong: the reader could not read `cargo fmt`'s trailing comma |
| D180 | the dispatch plane exists, and its first run found the D170 class again |
| D181 | 7.4c-ii closes: the two `find` functions land, and `OPENSSL_NO_ENGINE` is undefined |
| D182 | the seal must require the dispatch plane, and the plane is not a subphase |
| D183 | the canonicaliser dropped pointer depth in `(**)(...)` declarators |
| D184 | the `EVP_PKEY_METHOD` registry lands, and the accessors are where the depth defect hid |
| D185 | the struct-member plane's real obstacle is the atlas's universe, not a missing consumer |
| D186 | `EVP_PKEY_CTX_new` and `_new_id` land, and the engine parameter is read and discarded |
| D187 | `ctrl_params_translate.c` is one atomic unit, and that is measured rather than assumed |
| D188 | the ctrl plane lands whole, and three of its four absences were found by reading the table |
| D189 | the signature entry points land, and the `legacy:` label does not reset the operation |
| D190 | `p_lib.c`'s provider half lands whole, and the one name it cannot reach is `EVP_DigestSignInit_ex`'s |
| D191 | `m_sigver.c` lands whole, and the `reinit` test's assignment is inside a short-circuit |
| D192 | 7.4c's PBE remainder lands whole, the six `PKCS12_PBE_keyivgen` rows are a register entry rather than a deferral, and the `builtin_pbe[]` count is thirty-four |
| D193 | 7.4l lands the ten names that read no method table, withholds thirteen with their blockers named, and courts the `EVP_PKEY_METHOD` registry's application stack for the first time |
| D194 | 7.5 lands the twenty-six names of the BIO, encoding and PEM bridges, withholds twenty-six with their blockers named, and its new court finds a whitespace defect in `PEM_get_EVP_CIPHER_INFO` |
| D195 | 7.6 lands the three legacy MAC/HPKE header surfaces, withholds one export on the random layer, and finds that `EVP_AEAD` does not exist in this authority |
| D196 | this seal: the four deferral readings it corrected, the fifty-six unit records, and the evidence-list entries that named files the stratum never created |

**D144 and D150 do not exist.** The numbering skips them, which is a fact about the register rather
than about this stratum, and it is stated here because a reader who counts the rows in this table
against the range D139–D196 will find two missing.

Four of those entries are the class this project calls a *finding worth more than the deferral*: a
defect in landed code found by an instrument built for a different purpose. D151 found a Phase-6
defect in the cipher's parameter list that four phases of callers could not see; D158 found a
reference leak in `EVP_MAC_CTX_new` through its KDF twin; D170 found two wrong callback types in
`exchange.c` that only the dispatch plane can reach, and D180 found the same class again on its first
run; D161 found that `OpenSSL_add_all_algorithms_noconf()` answered 0 where the authority answers 1,
by reading the error queue after a court's own first statement.

## 5. Fault boundaries — recorded, not reproduced

The stratum's divergences are in `docs/SECURITY_DIVERGENCE_POLICY.md` §6 under their own identifiers.
Ten are live and one was withdrawn; all eleven were registered or first made reachable during this
stratum.

| divergence | what the authority does |
|---|---|
| `D-NAMEMAP-DOALL-1` | `ossl_namemap_doall_names` calls its visitor with no NULL test; 7.3b made the first forwarding caller reachable from a probe, and `EVP_CIPHER_names_do_all` is not claimed compatible with a NULL visitor |
| `D-CIPHERCTX-PARAMS-NULL` | `EVP_CIPHER_CTX_gettable_params`/`_settable_params` dereference `cctx->cipher` on an unarmed context; measured, the authority's probe died at the first call |
| `D-MD-NULL-CALLBACK-1` | `evp_md_init_internal` and `EVP_DigestFinal_ex` call through a NULL method callback |
| `D-MD-DOALL-NULL-1` | `EVP_MD_do_all_provided` calls a NULL visitor |
| `D-MAC-DUPCTX-NULL-1` | `EVP_MAC_CTX_dup` calls through a NULL `dupctx` |
| `D-KEYMGMT-PARAMS-NULL-1` | the four `EVP_KEYMGMT` descriptor accessors dereference the method on their first line; measured as exit 139 |
| `D-PKEY-AMETH-1` | `pkey_set_type`'s legacy-method lookup is Phase 8's, so a provider key's `type` stays `EVP_PKEY_KEYMGMT` where the authority answers a real NID |
| `~~D-PKEYCTX-LEGACY-ALG-1~~` | **withdrawn** — the released authority refuses this too, so there is no divergence to record |
| `D-PKEY-AMETH-2` | the two `EVP_PKEY_asn1_find*` functions answer NULL for the twelve legacy types, because `standard_methods[]` is Phase 8's |
| `D-PBE-PKCS12-KEYGEN-1` | the six `PKCS12_PBE_keyivgen` rows of `builtin_pbe[]` carry no keygen, so the authority's `EVP_PBE_CipherInit_ex` keygen door has no row to find for them |
| `D-EVP-CIPHER-LEGACY-NID-1` | a fetched provider cipher's legacy NID is `NID_undef`, because the legacy `OBJ_NAME` table is Phase 13's contents |

The rule is the one the contract states and has not changed: an observable defined behaviour is a
compatibility target, and an authority memory fault, undefined behaviour or non-termination is
recorded instead of imported. No compatibility claim covers any of them and no probe reaches them,
because a probe cannot compare a crash. Each entry names the phase or condition that would make the
authority's behaviour reachable, so the record retires with that phase rather than with a re-reading
of this document.

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with that
   name is defined. `docs/PARITY_MODEL.md` states what each label means; `forensics/STATUS.md`
   carries the current figures. No symbol here is `PARITY_VERIFIED`.
2. **Nothing about the 244 deferred symbols.** They are unimplemented, no court calls them, and each
   names the stratum and the callee it waits for. The split by phase is
   `forensics/phase7-obligations.json`'s `deferred_by_phase`.
3. **`libssl` is untouched.** Every one of its exports remains `SCAFFOLDED` and aborts when called.
4. **Nothing cryptographic.** The courts compare answers with the authority's; they do not establish
   that any construction is sound, constant-time or side-channel resistant.
5. **Nothing about a build profile other than the admitted one.** `no-deprecated`, the legacy
   provider and FIPS-capable configurations are separate authorities that have not been built.
6. **Nothing about a platform other than Linux x86-64.**
7. **The courts observe the surfaces their probes reach.** A passing court is a differential result
   over the arms that court drives; `forensics/tools/probe_hygiene.py` and each probe's own
   "deliberately not observed" list are what make the gap visible rather than inferred.
8. **The legacy contents are absent, and that is a divergence of *distribution*, not of behaviour.**
   `EVP_get_cipherbyname("DES-CBC")` and its siblings answer NULL where the authority's
   `OPENSSL_init_crypto(ADD_ALL_CIPHERS)` table would find a static, because the statics are Phase
   13's (D162). 7.3g's table names each one.
9. **Phase 8's method tables make three refusal-shaped answers for the twelve legacy types**
   (`D-PKEY-AMETH-1`, `D-PKEY-AMETH-2`), and the names that would answer them are withheld rather
   than stubbed.
10. **Every count is `docs/SEAL-CENSUS.md`'s.** This document types none, except §3's per-court
    table, which names the file it was read from.

## 7. Exit criteria

The plan's 7.7 criterion is quoted from `docs/PHASE-7-SUBPHASES.md`, and every clause is checked
against a generated artefact rather than asserted.

| criterion | evidence |
|---|---|
| zero open obligations | `forensics/phase7-obligations.json`: `counts.open_in_this_stratum` = 0, and `implemented + deferred + open == owned` is asserted by the generator |
| every court passing | `artifacts/phase7/COURTS.json`: `all_pass` true, zero residuals (the per-court table is §3) |
| every implemented export is in a court coverage set | `forensics/atlas/court-coverage.json`: `unmatched` 0 for this stratum, enforced for `complete` by `forensics/tools/phase_state.py` |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 |
| the dispatch plane clean | `forensics/atlas/dispatch-court.json`: `problems` 0 |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` 0 |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` 0 |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json` |
| the stratum's own structure is reconciled against its ledger | `forensics/atlas/ownership-audit.json`: `problems` 0, `implemented_by_two_strata` 0 |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |
| the FRF receipts and the compiled claim | §8: nineteen Phase-7 receipts and the `sensitivity-backed` claim `96750dc60a30653471714fdb2164206dc541333371468238b98ca3d84e8cc7f8`, read from `.frf/` |
| the Gemel checkpoint | §8: the change and checkpoint the store answered |

## 8. FRF and Gemel

### FRF

Phase 7 declares **nineteen** FRF runtime courts — the fifteen of 7.1–7.6 and the four D199
coverage courts — and the chain the Phase 3–6 strata have is now complete for this stratum too:
`court → FRF declaration → challenge/sensitivity → receipt → compiled claim` (D200).

**The declarations.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table is *the* registry of
FRF court declarations (D58), and it now carries a Phase 7 row for every court in §3, each naming
the `artifacts/phase7/probes/<probe>.{authority,candidate}` pair the court executes and the
`courts/phase7/<probe>.c` it was compiled from. `python3 forensics/tools/gen_frf_courts.py
--check` regenerates all 124 declaration files from the table and passes; `--check` runs in CI and
in `court/pipeline.sh`. The declarations live at `forensics/frf/courts/openssl-rs-rt-*`, which is
also where `forensics/frf/run_courts.sh` derives the courts it runs, so a declaration added here is
run by construction rather than by a list someone has to remember.

**The venue.** The courts execute authority binaries, so they ran in the FRF tooling container
(`bash docker/openssl-rs-frf-court.sh up` / `exec`) and never on the host. Because `.frf/` is
committed, already-captured evidence, this stratum's courts were **added** to the existing store
rather than by `run_courts.sh`, whose first act is `rm -rf "$ROOT"`: a release re-observes a
rebuilt candidate from clean, and this was not a release. The `frf` invocations are the same ones
`run_courts.sh` makes (`court run`, `receipt emit`, `court challenge`, `claim compile`), without
the recreation. At the next store recreation the derived `RUNTIME_COURTS` glob picks these courts
up and compiles them into the runtime claim with the Phase 3–6 receipts, as before.

**The receipts.** Nineteen, one per court, each with **0 residuals** and no open residual whose
surface intersects its observables:

```
receipt-run-openssl-rs-rt-fetch-9eb67370588b2404ca8f185cc4e251cd8ccedfaf443085e8d62d47bfee2941c0-66dd6662dba68503a4ed45141cf93b86d15e41283549423169c5c71aa88e73de
receipt-run-openssl-rs-rt-evp-cipher-1672c1098d74206edae1699be5e14b58b57ee4940ed06459372ccf8268e1f612-2897dd09982cc42849b74ac79bb8cd40c4d3fc7ea87a5c170fd0b51b4bb2ac1c
receipt-run-openssl-rs-rt-evp-mac-ce5afa0935ea9ce8d6bee240cc960c7adeb9edf02104d0c8d93f06dda1df0abf-4332281138d3f7bf9b04aca052b42c496f920e605dae826ae0ff7d8b07095559
receipt-run-openssl-rs-rt-evp-kdf-7c0b45f8e93c67e630ce85a8606f12358bb4bc0fb82e05ea3c2f69357e7b8507-d7e8cb75adbd3a3625e460884bc7e29cc4ebf2182275bc9c48a596e8bc6e7a75
receipt-run-openssl-rs-rt-evp-rand-b50cd73fb478dc3cd1cbb1bec799b63cffbb03dbd565de45ae46f59b7cb553b0-38508384bf82143c60b764663492e2cbc84d5d9aab39014844e3abe58b1d1de3
receipt-run-openssl-rs-rt-evp-skey-0203418e986784ae1ae2d1e1627d5458b0cc75dcc37326ab55e38db716f5907f-0c2944c1bab147aec76a0c5a8f0700df902fbf364348ba731a738444aeafaef6
receipt-run-openssl-rs-rt-evp-keymgmt-ed7b626c27dc4e26064ae660e89bd91180494e1c29636c270ec8ad61117948db-a096d2894fa1439bcc0e5d9ee3732cf03fa11bfb599c0f274d5f871a50696793
receipt-run-openssl-rs-rt-evp-names-c2c1024763a6507791e6710e53fb1b522114a7ece1f4ddf23f0318eb51833453-d75d5641ad95507f0c82dda207c44a929d22591ecb72ac4fe39ef171cca61e93
receipt-run-openssl-rs-rt-evp-pkey-631febec3d62260e765aa8a3674e4e8ae0530d62201b420241d20932d42edfbe-ecd9c2c16e1562cdd97b6cffd903344d394c9ecc9fbf1406b3cbbe84bf80936f
receipt-run-openssl-rs-rt-evp-pbe-c178451128d6beff772977f8a5dd55a37a2a692b77dce279ac826dd7d2179626-646bc6e2ffca16f22c698a312a14118c004cfb09be4cd68a805499d748f9db32
receipt-run-openssl-rs-rt-evp-bio-511353fc2843fdb9110bf2efa7b863337a3f08f8ba10ac0a691b18c0d370f7f4-fbb3a5993d6673fdfcb71a2bb7f888e95dc4ca03d02e90caa164b930cdbdd89f
receipt-run-openssl-rs-rt-evp-pem-0fe064683f22b7e336b99095482127a28ef1cbd39ebcd8c3b973becac29cb59c-3a5134ea1e1b3233d01a7026f771ff3a257f33ce966c75bbe93c4ecd238e3b46
receipt-run-openssl-rs-rt-hmac-812c859e3c5cc8249b6c5b319431f6497e9d37999f4e10bac03b2e42e3523476-aec47a38037f604b07af3fa1599016397a743edd1f46ea4ffc914134269350fa
receipt-run-openssl-rs-rt-cmac-d1f1004af6b162761e81082691b0f45712825a3f6460db0b8d1575b0eac7028a-41b9f6e0edf7d8cb4c5c60438d5302f54198bd9339f5759d087b40c3d3e12ba4
receipt-run-openssl-rs-rt-hpke-68e053f22f810a521e89908026a70340a3ca242ee7f5535f86e0542ef0b122f0-d984ada00f651e5a7c78c693bb68f2b079740c123356b1bbeda85cf3d4e24264
receipt-run-openssl-rs-rt-evp-ref-f036186fc277e05265c0d4ca53cfeb4e6885b7538f36b29f71b8d59530d5de05-51d4beb9a232b80ca89d82b4c5a7e7ac2d43d203f1329960cc7335ed3571ee56
receipt-run-openssl-rs-rt-evp-introspect-510c38e180ccd570ac61fb920c146e8f7ce925c49fc64d7493b9a5ff5b312e8f-ecf9fa822af589138a932e586a15825c73ddf966674a3cd7a758b27c93c36e92
receipt-run-openssl-rs-rt-evp-class-42e192c3cfb49eea050a85bc0d9a66e9521b67a4684c148936a7b169dcaffec2-c6c67eb565f1d978e9a96115409ca1588183ff5aac2bcc8360f6544877ddd277
receipt-run-openssl-rs-rt-evp-pkey-ops-eaa7ce42cdf2d17b15cd650107f4b8f5ba457fc1557a53a70a0719aaf70aa1b2-ef111a83558c0e2bd6ebc893806385e45ab3f0e8698f11d5979077181ccfe87f
```

**The compiled claim.** From those nineteen receipts at `--policy sensitivity-backed`, the same
policy `run_courts.sh` uses for the Phase 3–6 runtime receipts:

```
96750dc60a30653471714fdb2164206dc541333371468238b98ca3d84e8cc7f8
```

It binds authority `openssl-rt-3.6.4-r2` and candidate `openssl-rs 0.0.10 (e4f60d8b)`, asserts
`eq(stdout-first-line), eq(exit-code)` per fixture family, and — like every runtime claim — is
explicit that it "does not establish byte-identical stderr, full CLI compatibility, or a drop-in
replacement claim". That narrowness is deliberate and the Phase 3 note above is why it is not the
whole transcript by accident: the harness's first stdout line is a digest of every following line,
so the claimed axis covers the transcript, and the claim's own wording does not say so.

**The sensitivity evidence.** D13 requires a court whose arguments reference the fixture to be
challengeable, and FRF's `court challenge` runs it against a mutant candidate that alters exactly
one observable dimension, requiring the defect to be seen on the targeted axis *and no other*. For
a Phase-7 court the evidence is therefore two adjudicated challenge records per court: the
`stdout-first-line` operator seen on `stdout` only, and the `exit-class` operator seen on `exit`
only. All nineteen courts produced both — 38 challenge records, each with `saw_defect: true` and
`specificity_clean: true` — and none was refused. The pair for `RT-FETCH` is
`297124ba97de0d89471cdaf26ab0d5f3529a55119b8a2e5d9ce04b8ce6acdcb2` (`stdout-first-line`) and
`16ff0fd700c48c182b4d31a82aaa1fe2ad6b164ffe2183d49a68f2cbf237afb5` (`exit-class`); the other
seventeen courts' pairs are in `.frf/challenges/` and are listed in D200. The challenge runs'
mutant residuals are open by design — a mutant's divergence is the evidence — and the compiled
claim is admitted over the real runs' clean surface.

**The store, before and after.** Read from `frf --root .frf evidence status`, this change moved
captures 141 → **198**, residuals 97 → **135**, receipts 47 → **66** and claims 5 → **6**; the
object closure is `complete` and the graph verdict is `graph_verified: yes` afterwards. The 57 new
captures are 19 court runs plus 38 mutant runs; the 38 new residuals are exactly the mutant runs'
divergences, one per challenge; the 19 real runs contributed none. No existing capture, residual,
receipt or claim was rewritten.

### Gemel

The stratum's trajectory — the plan, what the reconnaissance measured, the discards and the
checkpoints — is projected into `forensics/GEMEL_TRAJECTORY.md`, and the native Gemel store's
`exchange/` namespace carries the machine-readable half. As elsewhere, the native store is not
Git-tracked (D17); the projection is, and the checkpoint identities in it are the ones the store
answered, read back through `forensics/tools/render_gemel_trajectory.sh` rather than carried forward.

## 9. What happens next

Phase 7 is the last stratum whose completion is a *precondition* for every algorithm: the fetch
layer, the method stores and the `EVP_*` object families are what an algorithm is reached through.
Phase 8 (`algorithms`) therefore writes *into* a working registry rather than beside a missing one,
and the defers this stratum recorded are its first work items:

- the twenty-seven symbols owed to **Phase 8**: the twelve legacy low-level-key accessors and the
  three `EVP_PKEY_get0_hmac`/`_poly1305`/`_siphash` getters (all behind `evp_pkey_get_legacy` and
  the `RSA`/`DH`/`DSA`/`EC_KEY` types), `EVP_PKEY_assign`, `EVP_PKEY_encrypt_old`/`_decrypt_old`,
  `EVP_PKEY_get_ec_point_conv_form`/`get_field_type`, `EVP_PKEY_type`, the three `d2i` spellings
  that need only the ameth objects (`d2i_PublicKey`, `d2i_KeyParams`, `d2i_KeyParams_bio`), and the
  three `EVP_PKEY_meth_find`/`_get0`/`_get_count` registry readers;
- the fifteen owed to **Phase 10**: the six `EVP_PKEY_print_*` names and their `_fp` twins, which
  reach `OSSL_ENCODER_CTX_new_for_pkey` first, the four `d2i_PrivateKey*`/`d2i_AutoPrivateKey*`
  spellings (decoder first, ameth fallback) and the five `i2d_*` encoders;
- the four owed to **Phase 9** and the five to **Phase 11**, each named in
  `forensics/prerequisites.json` with the callee that blocks it;
- the one hundred and ninety-three owed to **Phase 13**, of which one hundred and sixty-four are
  7.3g's legacy method statics with a primitive unit named for each, and twenty-nine are the PEM
  and engine names;
- `forensics/atlas/prerequisite-gate.json`'s `blocking_dependencies` list, which after this stratum
  is the recorded, phase-tagged census of what later strata owe — the file to read rather than this
  document.

## 10. Corrections this seal records

Appended rather than folded into §2, for the reason the Phase-5 seal's §9 gives: this stratum's
evidence did not change when these were found, but four *readings* of it did, and a reader of the
plan would otherwise still be following them. All four are recorded in
`docs/DECISIONS.md` D196 with their measurements.

**1. Three evidence-list entries named files this stratum never created.**
`forensics/tools/phase_state.py`'s phase-7 module list carried `src/evp/legacy_cipher.rs`,
`src/evp/legacy_digest.rs` and `src/evp/params_translate.rs`. The first two were the destinations
7.3g's ledger labels the legacy `EVP_CIPHER`/`EVP_MD` statics with, and 7.3g handed every one of
them to Phase 13, so no file was written; the third was the expected home of
`ctrl_params_translate.c`, whose work landed in `src/evp/pkey_ctx.rs` (D188). Because `phase_state.py`
treats an absent evidence file as `in-progress`, those three entries are what kept this stratum from
deriving `complete` — and the honest fix is to remove them, not to create empty modules that satisfy
a list. The ledger's `MODULE_PREFIXES` labels for them stay: a label is not a claim about a file,
which is D193's `p_legacy.rs` reading and D194's for the `PKCS5_` half of the `pem_bridge.rs` label.

**2. `evp_cleanup_int` was pinned to this stratum and belongs to Phase 8.** Its
`forensics/prerequisites.json` row said the blocker was `EVP_PBE_cleanup`, "a 7.4 unit that does not
exist yet". That unit landed with 7.4c's PBE remainder (D192). What is left of the function's seven
calls is the seventh, `evp_app_cleanup_int`, which pops the application-supplied `EVP_PKEY_METHOD`
registry and is Phase 8's because `EVP_PKEY_meth_find` searches `standard_methods[]` (D165, D193).
The row is **retargeted** to Phase 8 rather than discharged, `src/evp/legacy_evp.rs`'s module doc
says the same, and this is the shape D173 recorded once already: a deferral that had to move rather
than be built.

**3. `evp_pkey_decrypt_alloc` was owed to this stratum and had never been written.** Its row said
7.4b's operation half would land it "directly beside" `EVP_PKEY_decrypt`, which is exactly where it
belongs and where it now is: `src/evp/asymcipher.rs`, with the two `CRYPTO_malloc`/`CRYPTO_clear_free`
coordinates its `OPENSSL_malloc`/`OPENSSL_clear_free` calls need, and with an
`#[allow(dead_code)]` naming `crypto/pkcs7/pk7_doit.c` as its first caller (Phase 12's). Its
prerequisite row is **retired**, and `forensics/atlas/prerequisite-gate.json`'s `blocking_dependencies`
moves down by one as a result.

**4. `EVP_PKEY_new_mac_key` was not blocked, and it is implemented.** D193's sweep put it in the
twelve-name legacy-accessor group with the reason "*all read a legacy key through
`evp_pkey_get_legacy`*". Its call list contains no such call: `crypto/evp/pmeth_gn.c:313` is
`EVP_PKEY_CTX_new_id`, `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_mac_key`, `EVP_PKEY_keygen` and
`EVP_PKEY_CTX_free`, and D173 had already recorded that the first two of those gated it. Both landed
in 7.4c — `EVP_PKEY_CTX_new_id` in D186 and `ctrl_params_translate.c` in D188 — so the gate D173
named was gone and the name had been swept into a list whose reason does not hold for it. It is
implemented in `src/evp/pmeth_gn.rs`, with its thirteen siblings, and `RT-EVP-PKEY` drives it:
`mac_key.null_engine=nonnull`, the generation vector `init:1,...,gen:1`, and `priv` arriving at the
provider's generation context with a length of six. It is the concrete instance of the principle
this seal's §1 states — every deferral names the callee that blocks it — because a reason that names
a callee can be checked, and this one was not.

**5. Fifty-six units this plan names now have records, split 42/14.** `plan_reconciliation.py`
judges a unit a **complete** stratum's row names, and fifty-six of this plan's were reached or handed
on but invisible to its three mechanical signals: 42 are `deferred_to_later_stratum` (31 to Phase 13
— the legacy wrapper families, `c_allc.c`/`c_alld.c`/`e_old.c` and the three PEM units — 7 to Phase
8, 2 to Phase 10, 1 to Phase 9 and 1 to Phase 11) and 14 are `reached_by_a_named_construct` (units
whose content is exports rather than internals, or whose crate module is attributed to a dominating
sibling: `bio_b64.c`, `bio_md.c`, `e_null.c`, `m_null.c`, `kdf_meth.c`, `mac_meth.c`, `m_sigver.c`,
`evp_err.c`, `p_open.c`, `p_seal.c`, `p_sign.c`, `p_verify.c`, `pem_sign.c` and `evp_pkey.c`).
Each record carries what its class requires to prove — `owner_phase` for a deferral, `crate_module`
and the built `names` for a named construct — so the claim fails if it is wrong rather than reading
plausibly. This is not a relaxation of the check: the mechanism is the one
`forensics/prerequisites.json`'s `units` block documents for exactly these units, and populating it
is what makes the reconciliation read zero *and* stay checkable.

**No change was needed to `plan_reconciliation.py` or to `phase7_obligations.py`'s completion
rule.** The ledger's rule (`complete` iff `open == 0`, with every symbol either implemented or
deferred with a reason) is the one phases 3–6 sealed under and it is unchanged; the only machinery
edits are the three module-list entries removed from `phase_state.py` (item 1) and the seal itself
added to that list, because a stratum may not derive `complete` without a seal.
