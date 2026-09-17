# Phase 7 — the EVP framework: seal

**STATUS: complete.** Every export this stratum owns is either implemented and observed by a
differential court, or handed to a named later stratum with the dependency it is waiting on:
`open_in_this_stratum` in `forensics/phase7-obligations.json` is **zero**, and
`forensics/phase-state.json` derives `complete` only because every earlier stratum is complete and
this one's obligations are closed.

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
- Court results: `artifacts/phase7/COURTS.json` — fifteen courts, all pass, zero residuals. **The
  totals are `docs/SEAL-CENSUS.md`'s**; the per-court table is §3.
- Obligation ledger: `forensics/phase7-obligations.json` — **0 open in this stratum**
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

| court | verdict | observations |
|---|---|---|
| `RT-FETCH` | pass | 217 |
| `RT-EVP-CIPHER` | pass | 185 |
| `RT-EVP-MAC` | pass | 96 |
| `RT-EVP-KDF` | pass | 68 |
| `RT-EVP-RAND` | pass | 168 |
| `RT-EVP-SKEY` | pass | 97 |
| `RT-EVP-KEYMGMT` | pass | 73 |
| `RT-EVP-NAMES` | pass | 25 |
| `RT-EVP-PKEY` | pass | 502 |
| `RT-EVP-PBE` | pass | 442 |
| `RT-EVP-BIO` | pass | 154 |
| `RT-EVP-PEM` | pass | 80 |
| `RT-HMAC` | pass | 32 |
| `RT-CMAC` | pass | 26 |
| `RT-HPKE` | pass | 65 |

What each covers, in one line, is `forensics/tools/phase7_courts.py`'s table: the fetch store's shape
and the property engine; the cipher object and its context; the MAC and KDF classes; `EVP_RAND` and
`EVP_SKEY`; the five asymmetric method classes; the `names.c` walkers and the two lookups; the
`EVP_PKEY` layer, its method registry and its ASN.1 glue; the PBE registry and the ctrl/params
translation; the encode/BIO filters; the PEM framing, headers and wrappers; and the three legacy
header surfaces of 7.6.

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
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 |
| the dispatch plane clean | `forensics/atlas/dispatch-court.json`: `problems` 0 |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` 0 |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` 0 |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json` |
| the stratum's own structure is reconciled against its ledger | `forensics/atlas/ownership-audit.json`: `problems` 0, `implemented_by_two_strata` 0 |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |
| the FRF receipts | §8: vacuous for this stratum by the convention the FRF table records |
| the Gemel checkpoint | §8: the change and checkpoint the store answered |

## 8. FRF and Gemel

### FRF

**Phase 7 declares no FRF courts, and therefore has no FRF receipts.** That is a property of the
landed convention rather than a gap in this stratum's evidence, and the convention is readable in
one place: `forensics/tools/gen_frf_courts.py`'s `COURTS` table is *the* registry of FRF court
declarations (D58: "the FRF court declarations are generated from one table"), and its entries are
the Phase 3–6 runtime courts. There is no `openssl-rs-rt-fetch`, `-rt-evp-cipher`, `-rt-evp-pkey`,
`-rt-hmac`, `-rt-cmac` or `-rt-hpke` directory under `forensics/frf/courts/`, and
`forensics/frf/run_courts.sh` derives the courts it runs from that directory rather than from a
list, so a court with no declaration produces no receipt by construction.

What that costs is stated rather than glossed: the Phase 3–6 strata each have a claim compiled from
their receipts, and this stratum does not. Its claim-bearing evidence is
`artifacts/phase7/COURTS.json` plus `court/pipeline.sh`, which re-derives it on every push, and the
prerequisite/dispatch/prototype courts over the same tree. `gen_frf_courts.py --check` is run by the
pipeline and by CI, and it passes — it verifies the declarations that exist, and this stratum adds
none, so the check is unaffected either way.

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
