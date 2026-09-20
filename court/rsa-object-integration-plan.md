# Integration plan — `court/rsa-object.rs.txt` (8.4 slice A, `crypto/rsa/rsa_lib.c`'s object layer)

This document integrates **one staged file**: `court/rsa-object.rs.txt` (2478 lines), D319's
transcription of `crypto/rsa/rsa_lib.c:32-959` plus the three `rsa_crpt.c` accessors. It is a plan,
not a landing: **nothing under `src/`, `courts/`, `forensics/` or `docs/` is touched by this file**,
and the plan itself is not part of the build.

It is written against what the crate *already* has, read rather than assumed:

* `src/rsa/mod.rs` (1599 lines) holds slice B (D284): `Rsa` (`:142`, 216 bytes, tested at `:1567`),
  `RsaMethod` (`:272`, 120 bytes, tested at `:1539`), `RsaPssParams30`/`RsaPssMaskGen`,
  `RsaPssParams`, `RSA_null_method` (`:782`), the 34 `RSA_meth_*`/`RSA_null_method` exports, and
  slice C's RAND-free padding half. It has **no `mod` declarations at all** — it is the whole of
  `src/rsa/`.
* `src/bn/` supplies `BN_new`/`BN_secure_new`/`BN_free`/`BN_clear_free`/`BN_num_bits`/
  `BN_set_flags`/`BN_get_flags`/`BN_dup`/`BN_mul`/`BN_value_one` (`bignum.rs`), `BN_CTX_new`/
  `BN_CTX_free` (`ctx.rs`), `BN_mod_exp_mont` (`mont.rs:434`) and `BN_BLINDING_free`
  (`blinding.rs:180`).
* `src/runtime/` supplies `CRYPTO_zalloc`/`CRYPTO_free` (`mem.rs`), `CRYPTO_THREAD_lock_new`/
  `_free` (`thread.rs:200`/`:325`), the four `CRYPTO_*_ex_data` plus `CRYPTO_EX_INDEX_RSA = 9`
  (`ex_data.rs:109`), the generic `OPENSSL_sk_*` family (`stack.rs`), `ossl_sa_new`/`_free`/
  `_doall_arg` (`sparse_array.rs:98`/`:209`/`:279`), `raise_site` and the four `RSA_LIB_*`
  `ErrSite`s (`err_sites.rs:20176-20206`).
* `src/evp/pkey_asn1.rs:295` declares `Engine` opaque; `ENGINE_*` is **Phase 13's** (D181).
* `forensics/atlas/implemented-surface.json` does not contain any of the 36 exports.

---

## 1. The order of operations

Each step names the file it edits or creates, and why it must precede the next. Steps 1–6 are one
commit (**phase 8, commit A**); steps 7–9 are the second (**commit B**, §3).

**1. `src/rsa/mod.rs` — two edits, both preconditions of every later file.**

* Define **`RsaPrimeInfo`** once, beside `Rsa`, with a size/offset unit test. The staging declares it
  in the staged file and says in its own note that the integration must "keep **one** copy, beside
  `Rsa` in `src/rsa/mod.rs` … not two"; two files read and write its fields (the object's
  accessors, and `rsa_mp.c`'s five in step 2).
* Retype **`Rsa::references`** from `c_uint` to `AtomicI32`. The staged `RSA_free`/`RSA_up_ref` call
  `(*r).references.fetch_sub(1, Ordering::Release)` / `fetch_add(1, Ordering::Relaxed)` and
  `rsa_new_intern` writes `(*ret).references = 1`: **that does not type-check against `c_uint`**, so
  the field's type is not optional. The precedent is `src/evp/pkey.rs:261` (`references: AtomicI32`,
  set at `:322`). The change is layout-neutral (`AtomicI32` is 4 bytes, align 4), which the existing
  assertions `size_of::<Rsa>() == 216` and `offset_of!(Rsa, references) == 160` (`src/rsa/mod.rs:1568`,
  `:1587`) already pin: keep the staging's `Release`/`Acquire`-fence orderings and do **not** copy
  `pkey.rs`'s stronger `AcqRel`, which is not what `include/internal/refcount.h`'s arm does.

Why first: it is the DAG root. Nothing in steps 2–9 compiles without it, it has no prerequisite
beyond `src/bn/mont.rs::MontCtx`, and it is the only change that *two* new modules both need. Its
transitive fan-out is the whole plan.

**2. `src/rsa/mp.rs` and `src/rsa/ossl.rs` (new) — the seven callees the object's text calls.**
`rsa_mp.c`'s `ossl_rsa_multip_info_new`/`_free`/`_free_ex`, `ossl_rsa_multip_calc_product`,
`ossl_rsa_multip_cap`; `rsa_ossl.c`'s `ossl_rsa_alloc_blinding`/`ossl_rsa_free_blinding`; and the
two `OPENSSL_sk_freefunc` adapters the crate needs for `DEFINE_STACK_OF(RSA_PRIME_INFO)`. These are
the only seven of the thirteen missing names that are **internal** (so
`forensics/tools/prerequisite_gate.py` demands them the moment the object's transcription edge
exists — see §5), that no published slice claims, and that cannot be reduced away. Defined once each,
in the file named for the authority's translation unit.

Why before step 3: `mod object;` fails at *name resolution* on all thirteen names, and this step
removes seven of them; leaving them to step 3 would make one commit that both adds a module and
cannot compile, whereas these two files are landable and unit-testable on their own.

**3. `src/rsa/object.rs` (new) + `mod object;` in `src/rsa/mod.rs` — the 34 non-deferred exports and
twelve of the sixteen internals** (the two `OPENSSL_sk_freefunc` thunks live in `mp.rs`, and
`rsa_new_intern`/`ossl_rsa_new_with_ctx` are commit B's), with the two reductions of step 4/5 written
in. Nothing here is redeclared: `Rsa`, `RsaMethod`, `RsaPssParams`, `RsaPssParams30` are imported
from `crate::rsa`, exactly as the staging's own `use` block does.

Why before step 4: the probe cannot link a symbol the crate does not define, and
`forensics/tools/court_coverage.py` reads the *candidate probe binary's* undefined dynamic symbols,
so an export landed without an arm fails coverage in the same commit.

**4. In the same file: reduce the four `ENGINE_*` call sites, and record why.** `rsa_new_intern`'s
`ENGINE_init`/`ENGINE_get_default_RSA`/`ENGINE_get_RSA` block, `RSA_set_method`'s and `RSA_free`'s
`ENGINE_finish`, are written as the *reachable* answer: with no engine registry in the crate, no
engine can be registered (Phase 13's), so `ENGINE_get_default_RSA()` selects from an empty table
and answers NULL (`tb_rsa.c:59`, `engine_table_select` with nothing registered), and
`ENGINE_finish(NULL)` returns 1 without touching anything (`eng_init.c:108-111`). This is
`src/evp/pkey_asn1.rs:54-60`'s
established reduction and D313's argument. It is **not** a `forensics/prerequisites.json`
`divergences` row: the gate resolves internal symbols only, so a divergence row covering the four
exports is rejected with `divergence_record_does_not_match` (D313 measured exactly this). The record
is the transcribed site, this paragraph, and the commit's decision entry.

**5. In the same file: reduce `RSA_PSS_PARAMS_free`.** (a) Where it is called — `RSA_free` and
`ossl_rsa_set0_pss_params` — the call is omitted, because no state this crate can reach has a
non-NULL `r->pss`: the only writer is `ossl_rsa_set0_pss_params` (internal), its only authority
caller is `crypto/rsa/rsa_backend.c:669` (Phase 9's), and every `RSA_PSS_PARAMS *` comes from
slice F's `d2i_RSA_PSS_PARAMS`, which needs 8.8's `ASN1_ITEM` machinery and is not landed. (b) The
symbol is **not** defined as an export: a fabricated `RSA_PSS_PARAMS_free` would put a wrong body on
the ABI surface, which a consumer could link and call. The two omitted call sites are both
`free(NULL)` on every reachable path, which `ossl_asn1_item_embed_free` answers by returning
(`tasn_fre.c:36-39`).

**6. `court/` — this plan, and nothing else.** (The contract for this pass.)

**7. Commit B — `src/rsa/ossl.rs` gains the default-method front**: the `rsa_pkcs1_ossl_meth` static
(`rsa_ossl.c:60-79`, whose fifteen members are the seven `rsa_ossl_*`/`BN_mod_exp_mont` entry points
of step 8 plus `RSA_FLAG_FIPS_METHOD`, `app_data = NULL`, the integers `0` at `rsa_sign`/`rsa_verify`
and NULL at both keygen members), `default_RSA_meth`, `RSA_get_default_method` (`:91-94`),
`RSA_set_default_method` (`:86-89`) and `RSA_PKCS1_OpenSSL` (`:96-99`). This is the first step that
can only be taken *because* steps 1–3 exist (§3), and it must precede step 9 because
`rsa_new_intern` reads `RSA_get_default_method()`.

**8. Commit B — the seven `rsa_ossl_*` entry points the table's initialiser names**
(`rsa_ossl_public_encrypt`/`_public_decrypt`/`_private_encrypt`/`_private_decrypt`/`_mod_exp`/
`_init`/`_finish`), and the `ossl_rsa_padding_add_PKCS1_type_2_ex` that `rsa_ossl_public_encrypt`
reaches at `rsa_ossl.c:144`. A static initialiser names *addresses*, so the table of step 7 cannot be
written before these exist; `BN_mod_exp_mont` is reused from `src/bn/mont.rs:434`.

**9. Commit B — the constructor quartet moves out of the staging and into
`src/rsa/object.rs`**: `rsa_new_intern`, `RSA_new`, `RSA_new_method`, `ossl_rsa_new_with_ctx`, plus
`ossl_rsa_alloc_blinding`'s caller. In the same commit, `forensics/tools/phase8_obligations.py`'s
`BLOCKED_HANDOFFS` row (5) is **retired** (its own check at `:384` refuses to let the row outlive the
first of its four names being defined), and the probe gains the two arms of §4.

**10. Regenerate the evidence, in `forensics/tools/pipeline.sh`'s order** (§5), in both commits.

---

## 2. Every new crate symbol the integration needs

One line each: symbol — authority coordinate — file that must define it — what to reuse instead.
"reuse" is read out of `src/rsa/mod.rs` and `src/bn/`, not assumed.

### 2a. The shape (step 1)

| symbol | coordinate | file | reuse |
|---|---|---|---|
| `RsaPrimeInfo` | `crypto/rsa/rsa_local.h:18-25` | `src/rsa/mod.rs` (beside `Rsa`) | none; 40 bytes, 5 pointers, align 8. `Rsa.prime_infos` (`mod.rs:174`) is already `*mut OpenSslStack`, so the stack handle exists and the element type is the only gap. |

### 2b. The seven callees (`src/rsa/mp.rs`, `src/rsa/ossl.rs`)

| symbol | coordinate | file | reuse |
|---|---|---|---|
| `ossl_rsa_multip_info_new` | `rsa_mp.c:31-56` | `src/rsa/mp.rs` | `BN_secure_new`, `CRYPTO_zalloc`, `BN_free`, `CRYPTO_free` |
| `ossl_rsa_multip_info_free` | `rsa_mp.c:21-29` | `src/rsa/mp.rs` | `BN_clear_free`; call `_free_ex` rather than repeating it |
| `ossl_rsa_multip_info_free_ex` | `rsa_mp.c:15-19` | `src/rsa/mp.rs` | `BN_clear_free`, `CRYPTO_free` |
| `ossl_rsa_multip_calc_product` | `rsa_mp.c:59-96` | `src/rsa/mp.rs` | `BN_CTX_new`/`BN_CTX_free`, `BN_mul`, `BN_secure_new`, `OPENSSL_sk_num`/`_value` |
| `ossl_rsa_multip_cap` | `rsa_mp.c:98-113` | `src/rsa/mp.rs` | none (clamps to `RSA_MAX_PRIME_NUM` = 5) |
| `ossl_rsa_alloc_blinding` | `rsa_ossl.c:258-261` | `src/rsa/ossl.rs` | **`ossl_sa_new()`** (`sparse_array.rs:98`) — do not write a second sparse array |
| `ossl_rsa_free_blinding` | `rsa_ossl.c:250-256` | `src/rsa/ossl.rs` | `ossl_sa_doall_arg` + `ossl_sa_free` + `BN_BLINDING_free`; the leaf thunk `free_bn_blinding` is new but is three lines |
| `multip_info_free_thunk`, `multip_info_free_ex_thunk` | `rsa_local.h:28`'s `DEFINE_STACK_OF(RSA_PRIME_INFO)` (crate adapters for `OPENSSL_sk_freefunc`) | `src/rsa/mp.rs` | `OPENSSL_sk_pop_free`; the crate has no generated typed stacks, which is why the adapters are written out |

### 2c. The object module's own definitions (`src/rsa/object.rs`)

36 exports. "none: authority export" means the body is a transcription with no reusable crate
symbol beyond the shared imports in 2e.

| symbol | coordinate | reuse |
|---|---|---|
| `RSA_new` | `rsa_lib.c:35-38` | `rsa_new_intern` (write in commit B, §3) |
| `RSA_get_method` | `rsa_lib.c:40-43` | none: authority export |
| `RSA_set_method` | `rsa_lib.c:45-63` | `RsaMethod::finish`/`init` as `Option` (already modelled) |
| `RSA_new_method` | `rsa_lib.c:65-68` | `rsa_new_intern` (commit B) |
| `RSA_free` | `rsa_lib.c:141-191` | `BN_free` (n, e), `BN_clear_free` (six secrets), `CRYPTO_free_ex_data`, `CRYPTO_THREAD_lock_free`, `OPENSSL_sk_pop_free`, `ossl_rsa_free_blinding` |
| `RSA_up_ref` | `rsa_lib.c:193-203` | the retyped `references` (step 1); no shared refcount helper exists — `src/asn1/utl.rs:92-127` keeps its own three private helpers, and `src/evp/pkey.rs:372` inlines the atomics, so inline is the precedent |
| `RSA_set_ex_data` | `rsa_lib.c:216-219` | `CRYPTO_set_ex_data` |
| `RSA_get_ex_data` | `rsa_lib.c:221-224` | `CRYPTO_get_ex_data` |
| `RSA_security_bits` | `rsa_lib.c:387-401` | `BN_num_bits`, `OPENSSL_sk_num`, `ossl_rsa_multip_cap` |
| `RSA_set0_key` | `rsa_lib.c:403-429` | `BN_free`, `BN_clear_free`, `BN_set_flags` |
| `RSA_set0_factors` | `rsa_lib.c:431-453` | as above |
| `RSA_set0_crt_params` | `rsa_lib.c:455-483` | as above |
| `RSA_set0_multi_prime_params` | `rsa_lib.c:490-553` | `OPENSSL_sk_new_reserve`/`_push`/`_pop_free`, the two thunks, `ossl_rsa_multip_info_new`, `ossl_rsa_multip_calc_product` |
| `RSA_get0_key` | `rsa_lib.c:556-565` | none: authority export |
| `RSA_get0_factors` | `rsa_lib.c:567-573` | none |
| `RSA_get_multi_prime_extra_count` | `rsa_lib.c:576-584` | `OPENSSL_sk_num` |
| `RSA_get0_multi_prime_factors` | `rsa_lib.c:586-604` | `OPENSSL_sk_value` |
| `RSA_get0_crt_params` | `rsa_lib.c:607-617` | none |
| `RSA_get0_multi_prime_crt_params` | `rsa_lib.c:620-644` | `OPENSSL_sk_value` |
| `RSA_get0_n` … `RSA_get0_iqmp` (8) | `rsa_lib.c:647-685` | none: bare field reads |
| `RSA_get0_pss_params` | `rsa_lib.c:687-694` | none |
| `RSA_clear_flags` | `rsa_lib.c:714-717` | none |
| `RSA_test_flags` | `rsa_lib.c:719-722` | none |
| `RSA_set_flags` | `rsa_lib.c:724-727` | none |
| `RSA_get_version` | `rsa_lib.c:729-733` | none |
| `RSA_get0_engine` | `rsa_lib.c:736-739` | `Engine` (import from `evp::pkey_asn1`) |
| `RSA_bits` | `rsa_crpt.c:23-26` | `BN_num_bits` |
| `RSA_size` | `rsa_crpt.c:28-31` | `BN_num_bits`; the header's `BN_num_bytes` macro is written out, as `court/bn-rand.rs` did for `BN_zero` |
| `RSA_flags` | `rsa_crpt.c:57-60` | none; reads `meth->flags`, **not** `r->flags` |

Sixteen internals, of which twelve land here (the two thunks are in `mp.rs`; `rsa_new_intern` and
`ossl_rsa_new_with_ctx` are commit B's):

| symbol | coordinate | reuse |
|---|---|---|
| `rsa_new_intern` (static in the authority) | `rsa_lib.c:76-139` | `CRYPTO_zalloc`, `CRYPTO_THREAD_lock_new`, `raise_site`+`err_sites::RSA_LIB_85/106/116/130`, `CRYPTO_new_ex_data`, `RSA_free` |
| `safe_bn_num_bits` | `rsa_lib.c:911`'s macro | `BN_num_bits` |
| `mul2`, `icbrt64`, `ilog_e` | `rsa_lib.c:247-250`, `:259-274`, `:283-307` | none; private `fn`s, not `pub(crate)` |
| `ossl_ifc_ffc_compute_security_bits` | `rsa_lib.c:326-385` | **do not reuse `BN_security_bits`** (`src/bn/bignum.rs:1613`): it is the L/N rule and it answers **128** at 4096 where this answers **152**. Declared in `include/crypto/security_bits.h`, shared with `dh_gen.c`/`dh_key.c`, so DH's slice imports it from here — `pub(crate)` |
| `ossl_rsa_new_with_ctx` | `rsa_lib.c:71-74` | `rsa_new_intern` (commit B) |
| `ossl_rsa_get0_libctx`, `ossl_rsa_set0_libctx` | `rsa_lib.c:205-213` | none |
| `ossl_rsa_set0_pss_params` | `rsa_lib.c:697-706` | the step-5 reduction |
| `ossl_rsa_get0_pss_params_30` | `rsa_lib.c:709-712` | `addr_of_mut!((*r).pss_params)` |
| `ossl_rsa_set0_all_params` | `rsa_lib.c:752-872` | `OPENSSL_sk_delete`/`_num`/`_value`, `ossl_rsa_multip_info_new/_free_ex`, `BN_clear_free`, `BN_set_flags` |
| `ossl_rsa_get0_all_params` | `rsa_lib.c:876-909` | `OPENSSL_sk_push` |
| `ossl_rsa_check_factors` | `rsa_lib.c:912-959` | `OPENSSL_sk_new_null`/`_free`, `safe_bn_num_bits`, `ossl_rsa_get0_all_params` |

### 2d. Commit B's symbols (`src/rsa/ossl.rs`, unless noted)

| symbol | coordinate | reuse |
|---|---|---|
| `rsa_pkcs1_ossl_meth` (static table) | `rsa_ossl.c:60-79` | `RsaMethod` (import); every member is `Option`, and the six nulls are `None`, per D284 |
| `default_RSA_meth` (static) | `rsa_ossl.c:84` | none |
| `RSA_get_default_method` | `rsa_ossl.c:91-94` | none |
| `RSA_set_default_method` | `rsa_ossl.c:86-89` | none |
| `RSA_PKCS1_OpenSSL` | `rsa_ossl.c:96-99` | none |
| `rsa_ossl_public_encrypt`/`_public_decrypt`/`_private_encrypt`/`_private_decrypt`/`_mod_exp`/`_init`/`_finish` | `rsa_ossl.c` (slice D) | `RSA_padding_add_PKCS1_type_1` etc. are landed (`src/rsa/mod.rs:810+`); `BN_mod_exp_mont` from `src/bn/mont.rs:434` |

### 2e. Reused, not written

`Rsa`, `RsaMethod`, `RsaPssParams`, `RsaPssParams30` (`src/rsa/mod.rs`); `BigNum`, `BN_*`,
`BnCtx`/`BnGencb`, `MontCtx` (`src/bn/`); `OpenSslStack`/`OPENSSL_sk_*`; `CryptoExData`/`CRYPTO_*_ex_data`/
`CRYPTO_EX_INDEX_RSA`; `CryptoRwlock`/`CRYPTO_THREAD_lock_*`; `CRYPTO_zalloc`/`CRYPTO_free`/`cleanse`;
`raise_site`/`err_sites::RSA_LIB_*`; `OpenSslSa`/`ossl_sa_*`; `Engine`. `crash!`/`guard_ffi` are **not**
used by this slice: every function here takes pointers the authority dereferences without a guard.

---

## 3. The cycle, and how to break it

**The claim, as measured.** `rsa_new_intern` (`rsa_lib.c:101`) reads `RSA_get_default_method()`, whose
`default_RSA_meth` is `&rsa_pkcs1_ossl_meth` (`rsa_ossl.c:84`), whose first member is
`rsa_ossl_public_encrypt`, which reaches `ossl_rsa_padding_add_PKCS1_type_2_ex`. Phase 8's
`BLOCKED_HANDOFFS` row (5) therefore withholds **`RSA_new`, `RSA_new_method`, `RSA_get_default_method`,
`RSA_PKCS1_OpenSSL`** to Phase 9, and `forensics/phase9-obligations.json` lists all four as
`received_from_phase: 8` in its `open` list. So Phase 8 cannot define the constructor without Phase
9's getter, and Phase 9's row says the static cannot be built.

**Two facts that dissolve the deadlock, both already on disk.** (i) The precondition Phase 9's row
names — "the static cannot be built until 8.4's object exists to name" — is the *struct*, and slice B
landed it (`src/rsa/mod.rs:142`, D284); the seven symbols the table's initialiser needs are `rsa_ossl.c`
entry points, which are **8.4's own slice D**, not another stratum's. (ii) Row (5)'s named blocker,
`RAND_bytes_ex`, **landed at D313**, so the reason the row gives is stale — and it did not go stale
loudly, because `forensics/tools/phase8_obligations.py`'s table has no structured `blocked_by` list and
is therefore invisible to `forensics/tools/blocker_liveness.py` (which runs only over Phase 7's and
`prerequisites.json`'s rows). That asymmetry is why the cycle survived to D319, which read it by hand.

**The minimal sequence that breaks it — which stratum commits first, and what each commit contains.**

* **Phase 8 commits first (commit A = §1's steps 1–6).** Not one symbol in it reads the default
  method: the 34 non-deferred exports and their internals touch only the object's own fields,
  `src/bn/`, the runtime, the seven callees of step 2, and the two reductions of steps 4–5. It ends
  with the object's *functions* existing, which is the only thing the static ever needed from this
  stratum, and with `BLOCKED_HANDOFFS` row (5) untouched.
* **Phase 9 commits second (commit B = steps 7–9).** `src/rsa/ossl.rs` gains the static and the
  four-name family, then the seven member symbols, then the constructor quartet moves out of the
  staging into the crate. In the *same* commit, row (5) is retired from
  `forensics/tools/phase8_obligations.py` — its check at `:384` refuses to let the row survive the
  first of its four names being defined, so the retirement is not a separate decision but a
  consequence of landing the code.
* **Who owns the four afterwards.** Retiring the row removes them from Phase 8's `deferred` and from
  Phase 9's `received` set at once, and they fall back to their **atlas owner, Phase 8**, to whose
  `implemented` list `phase8_obligations.py` moves them by construction (`implemented_here` is
  `owned ∩ done ∩ ¬deferred`). So the honest sentence is: *the hand-off was Phase 9's instruction to
  build the static; committing the static against 8.4's object returns the four names to Phase 8's
  ledger*, and `src/rsa/ossl.rs` declares `//! Phase 8` because the dominant ownership of the exports
  it defines is Phase 8's — the shape `src/runtime/thread_events.rs` already has.
* **Predicted arithmetic** (read off the regenerated ledgers, not asserted):
  `phase8` implemented 238 → **272** (commit A) → **277** (commit B); open 524 → **490** → **489**;
  deferred 24 → 24 → **20**. `phase9` owned 93 → **89**, open 54 → **50**, implemented 39 (unchanged:
  the four leave `owned`, and none was implemented), `handoffs_discharged["8"]` 24 → 20,
  `received_by_handoff` 68 → 64.
* **The alternative reading, stated so a reviewer can choose it.** Row (5) could instead be
  **retargeted** (D313's precedent, and `main`'s row (4) is already corrected this way by D296):
  every blocker it names has either landed (`RAND_bytes_ex`) or is same-stratum, and "a stratum cannot
  hand a symbol to itself". Under that reading all nine steps are Phase 8's. It changes no code and no
  ordering — only which commit's prose claims the static. **This plan takes the retarget to be the
  truer ledger statement and the two-commit arc to be the truer chronology**; the two are compatible,
  and a reviewer who disagrees with the ledger half loses nothing but the paragraph.

---

## 4. The court arms to add, and the ones that stay owed

`RT-RSA` (`courts/phase8/rt_rsa_probe.c`, registered in `forensics/tools/phase8_courts.py`'s `COURTS`
as `("RT-RSA", "rt_rsa_probe.c")`, passing at **282** observations, `docs/SEAL-CENSUS.md:293`) has
**no arm for any of the 36**. Its header already says why (":17-23"). The arms below are added to that
probe — same court, same registration, so `phase8_courts.py` needs no edit.

### 4a. The three things the arms need

1. **The fabrication block.** `RSA` is opaque in the installed header on **both** sides, and no
   constructor exists on the candidate side until commit B, so the probe owns the object's shape,
   transcribed from `courts/layout/measure-rsa-ctx.c` (D283's measurement) with every offset pinned
   by a `_Static_assert`. 27 pointers is exactly 216 bytes and is eight-aligned:

   ```c
   union rt_rsa_object { void *p[27]; unsigned char b[216]; };
   _Static_assert(sizeof(union rt_rsa_object) == 216, "RSA is 216 bytes");
   /* offsets, from courts/layout/measure-rsa-ctx.c:
      version 16, meth 24, engine 32, n 40, e 48, d 56, p 64, q 72, dmp1 80, dmq1 88, iqmp 96,
      pss 128, prime_infos 136, ex_data 144, references 160, flags 164, lock 200, dirty_cnt 208;
      RSA_METHOD::flags is 72. */
   #define RT_OFF(o, n) ((unsigned char *)(o) + (n))
   #define RT_METH(o)   (*(RSA_METHOD **)RT_OFF(o, 24))
   #define RT_N(o)      (*(BIGNUM **)RT_OFF(o, 40))
   /* … one macro per field. */
   ```

   `rt_blank()` allocates with plain `malloc` — the library's own `CRYPTO_free` reaches the same
   `free`, since the probe's installed `my_free` calls it — and **memsets all 216 bytes**:
   `forensics/tools/probe_hygiene.py` recompiles this probe at several optimisation levels and
   requires an identical transcript, and a partially-initialised object is exactly the bug class
   that tool exists for (§6).

   This is legitimate on both sides: both binaries are handed the same bytes, the same genuine
   `BIGNUM`s and the same genuine `RSA_METHOD` from `RSA_meth_new`, and the observation is the
   *library's* answer. What the probe's own offsets cannot catch is a wrong offset in the
   *candidate*; that is what `src/rsa/mod.rs:1539-1599`'s layout tests pin, and the two together
   close the pair.

2. **The `drain()`/`begin()`/`end()` machinery the probe already has.** Refusal arms are
   return-value arms whose `drain` transcript is an **empty queue**: the staging measured that the
   three `set0_*` refusals and the three multi-prime refusals raise *nothing* (`rsa_lib.c` has no
   `ERR_raise` in any accessor — the whole 2478-line file has four `raise_site` calls, all inside
   `rsa_new_intern`).

3. **`RSA_meth_*` as the table source.** `RSA_meth_new`/`_set_init`/`_set_finish`/`_set_flags` are
   landed, so the probe can build a table with sentinel `init`/`finish` and a chosen `flags` word
   without any `RSA *`.

### 4b. The 36 exports

| # | export | RT-RSA arm | what it observes |
|---|---|---|---|
| 1 | `RSA_new` | **OWED** | Cannot link until `RSA_get_default_method` exists (`BLOCKED_HANDOFFS` row 5). Its arm lands in the commit that lands the constructor (§3, step 9): `begin(); r = RSA_new(); end("obj_new")` — the window is `M:216` + the lock, then `RSA_bits`/`RSA_size` on the result. |
| 2 | `RSA_get_method` | `rsa.obj_get_method.*` | `meth` sentinel returned unchanged; a blank object answers NULL |
| 3 | `RSA_set_method` | `rsa.obj_set_method.*` | the outgoing table's `finish` fires **before** the incoming table's `init`, the store happens, the answer is 1; `engine` must be left 0 (a non-NULL engine would make the authority call `ENGINE_finish`) |
| 4 | `RSA_new_method` | **OWED** | as `RSA_new`, and `RSA_new_method(NULL)` is the `RSA_new` arm |
| 5 | `RSA_free` | `rsa.obj_free_null`, `rsa.obj_free_refs2`, `rsa.obj_free_last` | NULL is a no-op with an empty window; `references == 2` returns **without touching anything** (empty window — the release order's first rule); `references == 1` on a fabricated heap object walks the whole order, attributed to `rsa_lib.c`, ending in the object's own `F` |
| 6 | `RSA_up_ref` | `rsa.obj_upref.*` | `references` 1 → answers 1 and the field is 2; `references` 0 → answers **0** (the `i > 1` test, which is not a failure mode) |
| 7 | `RSA_set_ex_data` | `rsa.obj_ex_data.*` | stores at index 0 and at a gap index (the pad loop), answers 1 |
| 8 | `RSA_get_ex_data` | `rsa.obj_ex_data.*` | returns the sentinel; out-of-range index answers NULL |
| 9 | `RSA_security_bits` | `rsa.obj_security.*` | the canonical ladder (2048→112, 3072→128, 4096→**152**, 6144→176, 7680→192, 8192→200, 15360→256), the `n < 8` zero, 687737→1200, and the multi-prime **refusal** (`version = 1` plus a pushed stack exceeds `ossl_rsa_multip_cap`) |
| 10 | `RSA_set0_key` | `rsa.obj_set0_key.*` | three refusals (each NULL when the field is empty); the replacement window (`F` of the old `n`/`e`, `F` of the old `d`); `dirty_cnt` bumps even when nothing is stored |
| 11 | `RSA_set0_factors` | `rsa.obj_set0_factors.*` | refusals; **`BN_get_flags(p, BN_FLG_CONSTTIME)` is set** on the stored `p`/`q` |
| 12 | `RSA_set0_crt_params` | `rsa.obj_set0_crt.*` | refusals; the three consttime marks |
| 13 | `RSA_set0_multi_prime_params` | `rsa.obj_set0_mp.*` | three refusals (NULL arrays, `pnum == 0`) with empty drains; the success path (needs step 2) — `version` → 1, `dirty_cnt` bump, `pp` computed, the arrays read back through arm 17/19. **Ordering constraint inside the probe**: the object's `p`/`q` must be set *before* the success arm, because `ossl_rsa_multip_calc_product` multiplies them |
| 14 | `RSA_get0_key` | `rsa.obj_get0.*` | every out-parameter optional, each written only when non-NULL |
| 15 | `RSA_get0_factors` | `rsa.obj_get0.*` | as above |
| 16 | `RSA_get_multi_prime_extra_count` | `rsa.obj_mp_count.*` | NULL stack answers **0**, not −1 — the `pnum <= 0` fold |
| 17 | `RSA_get0_multi_prime_factors` | `rsa.obj_get0_mp.*` | 0 with no extra primes (all-NULL out array left untouched); 1 with them, one pointer per record |
| 18 | `RSA_get0_crt_params` | `rsa.obj_get0.*` | as above |
| 19 | `RSA_get0_multi_prime_crt_params` | `rsa.obj_get0_mp.*` | the two arrays independently optional |
| 20–27 | `RSA_get0_n`/`_e`/`_d`/`_p`/`_q`/`_dmp1`/`_dmq1`/`_iqmp` | `rsa.obj_components.*` | each answers the pointer the setter stored — the identity arm that ties the fabricated offsets to the library's |
| 28 | `RSA_get0_pss_params` | `rsa.obj_pss.*` | NULL on a blank object; a sentinel address at 128 comes back unchanged |
| 29 | `RSA_clear_flags` | `rsa.obj_flags.*` | AND-NOT of the word |
| 30 | `RSA_test_flags` | `rsa.obj_flags.*` | **the masked word, not 0/1**: one flag set, two asked for, answers the flag |
| 31 | `RSA_set_flags` | `rsa.obj_flags.*` | OR of the word |
| 32 | `RSA_get_version` | `rsa.obj_version.*` | 0 on a blank object, 1 after `RSA_set0_multi_prime_params` succeeds |
| 33 | `RSA_get0_engine` | `rsa.obj_engine.*` | NULL on every object the crate can build (the step-4 reduction's observable consequence) |
| 34 | `RSA_bits` | `rsa.obj_bits_size.*` | 0 → 0; 1 → 1; 255 → 8; 256 → **9** |
| 35 | `RSA_size` | `rsa.obj_bits_size.*` | 0 → 0; 255 → 1; **256 → 2**, which is where `(bits + 7) / 8` differs from `bits / 8` |
| 36 | `RSA_flags` | `rsa.obj_null_flags`, `rsa.obj_flags_table` | `RSA_flags(NULL)` answers **0** — the only accessor in the slice with a NULL guard; otherwise `meth->flags` (offset 72), which is **not** `r->flags` |

**Observable with no `RSA *` from a constructor:** `RSA_flags` (its NULL guard) and `RSA_free` (its
NULL no-op) need no object at all. The other 32 need only the fabrication block of §4a — *not* a
constructor. **Genuinely OWED: 2** (`RSA_new`, `RSA_new_method`), and their arms cannot be deferred
past commit B, because `forensics/tools/court_coverage.py`'s invariant applies to every ledger on
disk, not only sealed strata ("the moment to require evidence for an export is the commit that lands
it"), reading the *candidate probe binary's* `.dynsym` via `forensics/tools/elf_symbols.py`.

**If a reviewer rejects the fabrication block**, the fallback is not "OWED": it is 34 rows in
`forensics/atlas/court-coverage-rows.json`'s `non_observable` set, each with a reason and an authority
citation, validated by `court_coverage.py`. That is a much larger authored diff and a weaker claim,
which is the argument for §4a.

---

## 5. The evidence bookkeeping

Answers checked against the files, not assumed. **`forensics/tools/prerequisites.json` does not
exist**; the file is `forensics/prerequisites.json` (authored, not generated — it is in neither
`evidence_determinism.py`'s `GENERATORS` nor its `COMPARED`).

1. **Regenerated in the same commit as the code, in `forensics/tools/pipeline.sh`'s order** (the
   order is evidence: several generators record the sha256 of a file another writes):
   `forensics/atlas/implemented-surface.json` (after `cargo build`); then, after the courts,
   `forensics/atlas/transcription-edges.json` and `internal-symbols.json` via
   `gen_prerequisite_atlas.py` — **before** the ledgers, which record its hash;
   `forensics/phase8-obligations.json` and `forensics/phase9-obligations.json` (the ledgers glob);
   `forensics/atlas/court-coverage.json` (and it reads [`forensics/atlas/court-coverage-rows.json`],
   which this plan does not change); `forensics/atlas/ownership-audit.json`;
   `forensics/atlas/prototype-court.json` and `forensics/atlas/dispatch-court.json` (they scan
   `src/`); `forensics/phase-state.json`/`phase-state.md`; `forensics/atlas/prerequisite-gate.json`
   and `forensics/atlas/plan-reconciliation.json` (both read the phase states, so they come after);
   `docs/SEAL-CENSUS.md` and `forensics/STATUS.md`; `forensics/regression-baseline.json` via
   `regression_guard.py --update`; and `artifacts/phase8/COURTS.json`, written by
   `phase8_courts.py` under `run_courts.py` and consumed by `court_coverage.py` (it is deliberately
   **not** in `evidence_determinism.py`'s `COMPARED`: it is a court venue product).
   `docs/DECISIONS.md` (append-only) and `docs/PHASE-8-SUBPHASES.md` are hand-written and must be
   final before `docs_consistency.py` runs; the entry is D319's successor.
2. **Optional and cheap:** `docs/PHASE-8-SUBPHASES.md` should name `crypto/rsa/rsa_mp.c` in 8.4's
   slice list. The staging's own finding is that no published slice claims it; naming it is what
   entitles step 2's file to exist, and `plan_reconciliation.py` judges plan rows against the crate.
3. **`forensics/prerequisites.json` — `units`:** there is **no row for `crypto/rsa/rsa_lib.c`**, none
   for `crypto/rsa/rsa_mp.c`, and none for `crypto/rsa/rsa_crpt.c`. The only RSA row in the whole file
   is `crypto/rsa/rsa_ossl.c` (`class: deferred_to_later_stratum`, `owner_phase: 8`), and **commit A
   does not discharge it**: an edge is derived from a module's *dominant* authority translation unit
   (`gen_prerequisite_atlas.py`'s `build_edges`), and `src/rsa/object.rs`'s dominant unit is
   `rsa_lib.c`. It is discharged by commit B's `src/rsa/ossl.rs`, on the commit that first makes
   `rsa_ossl.c` a module's dominant unit.
4. **`forensics/prerequisites.json` — `deferrals`:** nothing goes stale. The 17 rows are
   `ossl_get_*`, `OSSL_provider_init`, the seven `evp_*`/`ossl_rsa_*` names, the two `OSSL_*CODER_CTX`
   names, the three Phase-11 ASN.1 names and `UI_new`; the only two RSA rows are
   `ossl_rsa_asn1_meths` and `ossl_rsa_pkey_method` (both `owner_phase: 8`, both with an **empty**
   `blocked_by`), and both are 8.8's, untouched here. **No `RSA_new`/`RSA_get_default_method` row
   exists** — their bookkeeping lives in the two obligation ledgers, which is where a same-stratum
   blocker belongs ("a stratum cannot hand a symbol to itself", D296).
5. **`forensics/prerequisites.json` — `divergences`:** nothing is added. The ENGINE reduction of
   step 4 must *not* be recorded here: the gate's observed set resolves **internal** symbols only
   (`symbol_tu.get` answers None for an export), so a divergence row covering `ENGINE_init` et al. is
   refused with `divergence_record_does_not_match` (D313 measured this exactly). `RSA_PSS_PARAMS_free`
   is an export for the same reason. The reduction's record is the transcribed site, §1 steps 4–5, and
   the decision entry.
6. **What the gate *does* see, and why steps 1–3 must land together.** The new edge
   `src/rsa/object.rs -> crypto/rsa/rsa_lib.c` makes the unit's whole identifier set live, and the
   crate does not build seven of them: `ossl_rsa_alloc_blinding`, `ossl_rsa_free_blinding`,
   `ossl_rsa_multip_info_new`/`_free`/`_free_ex`, `ossl_rsa_multip_calc_product`, `ossl_rsa_multip_cap`
   — class C, `unwired_function_in_the_current_stratum`. Landing the module without them turns
   `prerequisite-gate.json`'s `findings` from `[]` into seven rows. The other six missing names
   (`ENGINE_*`, `RSA_get_default_method`, `RSA_PSS_PARAMS_free`) are exports and land in
   `census.language_surface_not_modelled_by_name` (currently 3201), which is a census and not a
   failure. The three `evp_*` internals the unit's *untranscribed tail* calls
   (`evp_pkey_ctx_get_params_strict`, `evp_pkey_ctx_set_params_strict`, `evp_pkey_type2name`) are
   already built (`src/evp/pkey_ctx.rs:8088`, `:8125`; `src/evp/pkey.rs:193`), so the tail is not a
   blocker — a fact worth checking rather than discovering.
7. **`phase8-obligations.json` counts that move.** Commit A: `implemented` 238 → **272**,
   `open_in_this_stratum` 524 → **490**, `deferred_to_later_phase` 24 unchanged, `owned` 786
   unchanged. Commit B: `implemented` → **277** (`RSA_new`, `RSA_new_method`,
   `RSA_get_default_method`, `RSA_PKCS1_OpenSSL`, `RSA_set_default_method`),
   `deferred_to_later_phase` 24 → **20** (row 5 retired), `open` **489**. The identity
   `owned = implemented + deferred + open` holds on all three readings (786 = 272 + 24 + 490;
   786 = 277 + 20 + 489). `phase9-obligations.json`: `owned` 93 → **89**, `open` 54 → **50**,
   `implemented` 39 unchanged, `received_by_handoff` 68 → **64**,
   `handoffs_discharged["8"]` 24 → 20 — and `forensics/tools/ownership_audit.py` must report the
   phase 8 → 9 edge as 20 discharged with **zero mismatched edges**, because the retirement moves
   both sides of the edge together.
8. **`docs/SEAL-CENSUS.md`'s `RT-RSA` row (currently 282 at `:293`)** and
   `forensics/phase-state.json`'s observation totals both move in step 10; the new figure is read off
   the regenerated artefact rather than predicted here — each `printf` is one `key=value` line, and
   each `drain` adds one `err.count` plus one line per queued record. Note that an arm whose drain is
   empty still contributes its `err.count` line, which is how "the refusal raises nothing" becomes an
   observation rather than an absence.
9. **`forensics/regression-baseline.json`** is refreshed by `regression_guard.py --update` and then
   required against `origin/main`; the new export count and the coverage atlas move together with it.

---

## 6. The falsification tests

Each new fail-closed check, and how to defeat it so that it is seen to fire.

1. **`RsaPrimeInfo`'s shape test** (`src/rsa/mod.rs`, new): `size_of == 40`, `align_of == 8`, the five
   offsets. *Defeat:* reorder the fields (put `m` second) — the offsets test fails while the size
   assert still passes, which is the point of asserting offsets and not only the size.
2. **`Rsa::references`'s layout-neutrality** (the existing tests at `src/rsa/mod.rs:1568` and `:1587`,
   which must keep passing unchanged after step 1). *Defeat:* make the field `AtomicI64` — both
   `size_of::<Rsa>() == 216` and `offset_of!(Rsa, lock) == 200` fire. This is the check that the
   retype did not move the object a caller's allocator sees.
3. **`ossl_rsa_multip_cap`'s ladder** (`src/rsa/mp.rs`, new): 1023→2, 1024→3, 4095→3, 4096→4,
   8191→4, 8192→5. *Defeat:* change `bits < 4096` to `bits <= 4096` — 4096 answers 4, not 3.
4. **The security-bits ladder and the reuse trap** (`ossl_ifc_ffc_compute_security_bits`, new): the
   seven canonical values, `n < 8` → 0, `n >= 687737` → 1200, and the 192/256/1200 cap rule.
   *Defeat:* substitute `BN_security_bits(bits, 0)` — 4096 answers **128** where the authority answers
   **152**, and 6144/8192/7680 have no counterpart at all. This is the check that makes an obvious
   and wrong reuse impossible rather than merely discouraged.
5. **`RSA_test_flags` answers the masked word** (`object.rs`'s tests, transcribed from the staging's
   `the_flag_accessors_round_trip_and_rsa_flags_reads_the_table`). *Defeat:* write `!= 0` — asking for
   `RSA_FLAG_BLINDING | RSA_FLAG_CACHE_PRIVATE` with one flag set answers 1 instead of the flag.
6. **`RSA_flags` is the table's word and has the only NULL guard**. *Defeat:* read `(*r).flags`
   instead of `(*(*r).meth).flags` — the test's table has `0x002a` while the object's word is 0, so
   the two arms swap answers; remove the guard and the NULL arm faults.
7. **The `set0_*` refusals raise nothing** (court arms, not unit tests). *Defeat:* add an
   `ERR_raise` to a refusal in `src/rsa/object.rs` — `drain("obj_set0_key")`'s `err.count` moves from
   0 to 1 and `err.0` appears, which is the residual. A Rust unit test cannot see this; the court is
   the check.
8. **The multi-prime `err:` label's destructor choice** (court arm, step 2 landed). *Defeat:* swap
   `multip_info_free_ex_thunk` for `multip_info_free_thunk` on the failure path — the window gains
   three `BN_clear_free`/`F` events that the authority does not produce, because `r`/`d`/`t` belong to
   the caller's key. This is the arm the staging's own note calls out as the `err:` labels' reason for
   existing.
9. **The `RSA_free` release order and attribution** (court arm on a fabricated heap object).
   *Defeat:* free the object before the key material, or use `BN_clear_free` for `n`/`e` — the
   ordered `(kind, size, file)` sequence and the final event's `file` string change; and
   `references == 2` returning early is a separate arm, so a transcription that freed anyway shows a
   non-empty window where the authority shows none.
10. **The ENGINE reduction is absent, not approximated** (source check). *Defeat:* write
    `ENGINE_finish(...)` back into `RSA_set_method` or `RSA_free` — the crate fails to build at name
    resolution, and the recorded grep over `src/rsa/` for `ENGINE_init|ENGINE_finish|ENGINE_get_RSA|
    ENGINE_get_default_RSA` going 0 → 1 is the fail-closed signal while Phase 13 has not landed. The
    observable half is court arm 33: `RSA_get0_engine` is NULL for every object the crate can build.
11. **The PSS reduction** (same shape). *Defeat:* name `RSA_PSS_PARAMS_free` in `src/rsa/` — it is not
    defined, so the build fails, and the recorded grep going 0 → 1 fires. The day slice F lands, the
    check is replaced by the call.
12. **`probe_hygiene.py`'s determinism across optimisation levels** on the new arms. *Defeat:* drop the
    `memset` from `rt_blank()` — the fabricated object then carries whatever the allocator left, the
    -O0 and -O1 transcripts differ, and the tool reports it as the probe reading memory the optimizer
    changed. This is the check that makes the fabrication design safe rather than merely convenient.
13. **The probe's own `_Static_assert` offset block.** *Defeat:* set `RT_OFF(o, 40)` to 32 in the
    probe — the compile fails on that side; set it to a value the *authority* also tolerates and the
    `rsa.obj_components`/`rsa.obj_bits_size` arms diverge, which is how a wrong measurement becomes a
    residual instead of a silent wrong read.
14. **`phase8_obligations.py`'s stale-row check** (already exists, at `:384`). *Defeat:* define
    `RSA_new` in commit B and leave row (5) in `BLOCKED_HANDOFFS` — the tool exits with
    "`BLOCKED_HANDOFFS` records `RSA_new` as blocked on phase 9, but the crate defines it; retire the
    row", before it writes anything.
15. **`court_coverage.py`'s per-export invariant** (already exists; the universe is every ledger on
    disk). *Defeat:* land one of the 34 exports without an arm that references it — the atlas reports
    it uncovered, because set 1 is read from the staged **candidate binary's** `.dynsym` and not from
    the probe's text. This is why §4's arms and §1 step 3 are the same commit.
16. **`evidence_determinism.py`'s committed-artefact comparison.** *Defeat:* land the code and skip
    step 10 — the committed `forensics/phase8-obligations.json` (or `implemented-surface.json`, or
    `docs/SEAL-CENSUS.md`) no longer reproduces, and the gate fails. The one artefact it does *not*
    cover is `artifacts/phase8/COURTS.json`, which is exactly why `court_coverage.py` must be re-run
    in the same commit rather than being assumed fresh.

**Nothing here was compiled, run or integrated.** No file under `src/`, `courts/`, `forensics/` or
`docs/` was created, modified or deleted by this pass.
