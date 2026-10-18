# RC-1 caller-precondition audit

**Source identity:** `integrate/safe-c33` at `3a3ad9094` (working tree read-only
for `src/`). **Boundary:** `RC-1`, `runtime::refcount::{up_ref, down_ref}`.
**Purpose:** per-caller precondition inventory for the adjudicator. This
document does **not** change `REFCOUNT-BOUNDARY.md`, does not claim any
graduation state, and is **not a proof**. The adjudicator decides.

## 0. Method and verdict semantics

An exhaustive source search was run over `src/` for calls to
`runtime::refcount::{up_ref, down_ref}`, both fully qualified and through the
bare imports in `asn1/utl.rs`, `ssl/{ssl_lib,ssl_sess,ssl_cert_comp}.rs` and
`x509/x509_lu.rs`, plus every call through `engine::eng_lib::{up_ref,down_ref}`
(importers `engine/{eng_init,eng_list,tb_asnmth}.rs` and `eng_lib.rs` itself).
Multiline `refcount::` qualifications were checked separately.

Excluded from the RC-1 inventory because they are **not** the shared protocol:

- `src/property/store.rs:1642` — a test-only `extern "C" fn up_ref` callback
  implementation for a method-store fixture.
- `src/provider/child.rs:639` — `(*gbl).c_prov_up_ref`, a provider
  up-ref function pointer from the child-provider globals.
- `src/context/core_bio.rs:378` — `OSSL_FUNC_BIO_UP_REF` core-BIO callback.
- `src/dso/mod.rs:1001` — a string in a test assertion.

**Verdict rule used.** `ESTABLISHED` requires either (a) a concrete witness in
the caller frame that it owns (or acts for a named owner of) the reference, or
(b) for an exported wrapper, a `# Safety` statement that documents the C-ABI
ownership obligation *and* an authority API contract that supports it. A bare
restatement of the protocol, an unnamed external owner, or a dead path is
`UNATTRIBUTED`. `ESTABLISHED (forwarded)` marks the two `eng_lib` delegation
bodies: they carry no independent witness; they only transfer the obligation.

## 1. Production call sites

Totals: **76 direct call expressions** = **74 caller sites** (61 direct to
`runtime::refcount` plus 13 via `engine::eng_lib`) **plus 2 `eng_lib`
delegation bodies**. `REFCOUNT-BOUNDARY.md` §2 states 62 direct + 12 wrapper
calls; the totals agree at 74 caller sites but the split differs by one (this
audit counts `tb_asnmth.rs:414` as the 13th wrapper caller and the two
delegation bodies separately). Descriptive drift only; no safety claim moves.

### 1.1 Exported `*_up_ref` wrappers (30)

| ID | file:line | enclosing fn | op | class | owned/acted-for reference (witness quote) | verdict |
|---|---|---|---|---|---|---|
| P01 | `src/decoder_meth.rs:253` | `OSSL_DECODER_up_ref` | up | EXPORT-UP | `decoder` "must be live"; "acts for the C-API caller's existing reference, acquiring exactly one new reference" | ESTABLISHED |
| P02 | `src/dh/object.rs:419` | `DH_up_ref` | up | EXPORT-UP | `r` "is a live object"; "acts for the caller's existing reference" | ESTABLISHED |
| P03 | `src/dsa/object.rs:357` | `DSA_up_ref` | up | EXPORT-UP | `r` "is a live object"; "acts for the caller's existing reference" | ESTABLISHED |
| P04 | `src/dso/mod.rs:382` | `DSO_up_ref` | up | EXPORT-UP | `dso` "must be NULL or live"; "acts for the caller's existing reference" | ESTABLISHED |
| P05 | `src/ec/key.rs:438` | `EC_KEY_up_ref` | up | EXPORT-UP | `r` "is a live object"; "acts for the caller's existing reference" | ESTABLISHED |
| P06 | `src/encoder_meth.rs:298` | `OSSL_ENCODER_up_ref` | up | EXPORT-UP | `encoder` "must be live"; "acts for the caller's existing reference" | ESTABLISHED |
| P07 | `src/evp/asymcipher.rs:488` | `EVP_ASYM_CIPHER_up_ref` | up | EXPORT-UP | `cipher` "must be live"; "acts for the caller's existing reference" | ESTABLISHED |
| P08 | `src/evp/cipher.rs:1011` | `EVP_CIPHER_up_ref` | up | EXPORT-UP | `EVP_ORIG_DYNAMIC` arm; "the C-ABI caller holds the reference this call acts for" (legacy arm does not touch the count) | ESTABLISHED |
| P09 | `src/evp/digest.rs:869` | `EVP_MD_up_ref` | up | EXPORT-UP | `EVP_ORIG_DYNAMIC` arm; "the C-ABI caller holds the reference this call acts for" (legacy arm does not touch the count) | ESTABLISHED |
| P10 | `src/evp/exchange.rs:518` | `EVP_KEYEXCH_up_ref` | up | EXPORT-UP | `exchange` "must be live"; "acts for the caller's existing reference" | ESTABLISHED |
| P11 | `src/evp/kdf.rs:472` | `EVP_KDF_up_ref` | up | EXPORT-UP | `kdf` "must be a live `EvpKdf`"; "acts for the caller's existing reference" | ESTABLISHED |
| P12 | `src/evp/kem.rs:421` | `EVP_KEM_up_ref` | up | EXPORT-UP | `kem` "must be live"; "acts for the caller's existing reference" | ESTABLISHED |
| P13 | `src/evp/keymgmt.rs:748` | `EVP_KEYMGMT_up_ref` | up | EXPORT-UP | `keymgmt` "must be a live `EvpKeyMgmt`"; "acts for the caller's existing reference" | ESTABLISHED |
| P14 | `src/evp/mac.rs:506` | `EVP_MAC_up_ref` | up | EXPORT-UP | `mac` "must be a live `EvpMac`"; "acts for the caller's existing reference" | ESTABLISHED |
| P15 | `src/evp/pkey.rs:531` | `EVP_PKEY_up_ref` | up | EXPORT-UP | `pkey` "must be live"; "acts for the caller's existing reference" | ESTABLISHED |
| P16 | `src/evp/rand.rs:689` | `EVP_RAND_up_ref` | up | EXPORT-UP | `rand` "must be NULL or a live `EvpRand`"; non-NULL arm "acts for the caller's existing reference" | ESTABLISHED |
| P17 | `src/evp/rand.rs:944` | `EVP_RAND_CTX_up_ref` | up | EXPORT-UP | `ctx` "must be a live context"; "acts for the caller's existing reference" | ESTABLISHED |
| P18 | `src/evp/signature.rs:942` | `EVP_SIGNATURE_up_ref` | up | EXPORT-UP | `signature` "must be live"; "acts for the caller's existing reference" | ESTABLISHED |
| P19 | `src/evp/skeymgmt.rs:554` | `EVP_SKEYMGMT_up_ref` | up | EXPORT-UP | `keymgmt` "must be a live `EvpSkeyMgmt`"; "acts for the caller's existing reference" | ESTABLISHED |
| P20 | `src/evp/skeymgmt.rs:1216` | `EVP_SKEY_up_ref` | up | EXPORT-UP | `skey` "must be a live `EvpSkey`"; "acts for the caller's existing reference" | ESTABLISHED |
| P21 | `src/rsa/object.rs:725` | `RSA_up_ref` | up | EXPORT-UP | `r` "is a live object"; "acts for the caller's existing reference" | ESTABLISHED |
| P22 | `src/runtime/bio/mod.rs:1053` | `BIO_up_ref` | up | EXPORT-UP | `bio` live "for which the caller holds an outstanding reference"; "acts for the caller's outstanding reference" | ESTABLISHED |
| P23 | `src/ssl/ssl_lib.rs:3059` | `SSL_CTX_up_ref` | up | EXPORT-UP | "the C-ABI caller guarantees `ctx` is live and holds the reference this call acts for" | ESTABLISHED |
| P24 | `src/ssl/ssl_lib.rs:3436` | `SSL_up_ref` | up | EXPORT-UP | "the C-ABI caller guarantees `s` is live and holds the reference this call acts for" | ESTABLISHED |
| P25 | `src/ssl/ssl_sess.rs:516` | `SSL_SESSION_up_ref` | up | EXPORT-UP | `ss` "must be a live session"; "the C-ABI caller ... holds the reference this call acts for" | ESTABLISHED |
| P26 | `src/store/store_meth.rs:194` | `OSSL_STORE_LOADER_up_ref` | up | EXPORT-UP | provider-loader arm (`prov != NULL`); "the C-ABI caller holds the reference this call acts for" (legacy arm does not touch the count) | ESTABLISHED |
| P27 | `src/x509/x509_lu.rs:1877` | `X509_STORE_up_ref` | up | EXPORT-UP | "the C-ABI caller guarantees `xs` is live and holds the reference this call acts for (a caller obligation)" | ESTABLISHED |
| P28 | `src/x509/x509_set.rs:268` | `X509_up_ref` | up | EXPORT-UP | "the caller owns the existing reference this call acts for" | ESTABLISHED |
| P29 | `src/x509/x_crl.rs:1355` | `X509_CRL_up_ref` | up | EXPORT-UP | "the caller owns the existing reference this call acts for" | ESTABLISHED |
| P30 | `src/engine/eng_list.rs:595` | `ENGINE_up_ref` | up | EXPORT-UP | "This call acts for the C-API caller's existing reference" | ESTABLISHED |

### 1.2 Exported `*_free` wrappers (27)

| ID | file:line | enclosing fn | op | class | owned/acted-for reference (witness quote) | verdict |
|---|---|---|---|---|---|---|
| P31 | `src/decoder_meth.rs:273` | `OSSL_DECODER_free` | down | EXPORT-FREE | "releases the one reference the C-API caller owns" | ESTABLISHED |
| P32 | `src/dh/object.rs:390` | `DH_free` | down | EXPORT-FREE | `r` live; "this frame owns the reference it releases" | ESTABLISHED |
| P33 | `src/dsa/object.rs:328` | `DSA_free` | down | EXPORT-FREE | `r` live; "this frame owns the reference it releases" | ESTABLISHED |
| P34 | `src/dso/mod.rs:314` | `DSO_free` | down | EXPORT-FREE | `dso` live; "This frame owns the reference being released" (failure path caveat §3.4) | ESTABLISHED |
| P35 | `src/ec/key.rs:238` | `EC_KEY_free` | down | EXPORT-FREE | `r` live; "this frame owns the reference it releases" | ESTABLISHED |
| P36 | `src/encoder_meth.rs:342` | `OSSL_ENCODER_free` | down | EXPORT-FREE | `encoder` live; "this frame owns the reference it releases" | ESTABLISHED |
| P37 | `src/evp/asymcipher.rs:466` | `EVP_ASYM_CIPHER_free` | down | EXPORT-FREE | `cipher` live; "this frame owns the reference it releases" | ESTABLISHED |
| P38 | `src/evp/cipher.rs:1036` | `EVP_CIPHER_free` | down | EXPORT-FREE | `EVP_ORIG_DYNAMIC`; "this frame owns the reference it releases" | ESTABLISHED |
| P39 | `src/evp/digest.rs:894` | `EVP_MD_free` | down | EXPORT-FREE | `EVP_ORIG_DYNAMIC`; "this frame owns the reference it releases" | ESTABLISHED |
| P40 | `src/evp/exchange.rs:496` | `EVP_KEYEXCH_free` | down | EXPORT-FREE | `exchange` live; "this frame owns the reference it releases" | ESTABLISHED |
| P41 | `src/evp/kdf.rs:488` | `EVP_KDF_free` | down | EXPORT-FREE | `kdf` live; "this frame owns the reference it releases" | ESTABLISHED |
| P42 | `src/evp/kem.rs:399` | `EVP_KEM_free` | down | EXPORT-FREE | `kem` live; "this frame owns the reference it releases" | ESTABLISHED |
| P43 | `src/evp/keymgmt.rs:762` | `EVP_KEYMGMT_free` | down | EXPORT-FREE | `keymgmt` live; "this frame owns the reference it releases" | ESTABLISHED |
| P44 | `src/evp/mac.rs:525` | `EVP_MAC_free` | down | EXPORT-FREE | `mac` live; "this frame owns the reference it releases" | ESTABLISHED |
| P45 | `src/evp/pkey.rs:626` | `EVP_PKEY_free` | down | EXPORT-FREE | `x` live; "this frame owns the reference it releases" | ESTABLISHED |
| P46 | `src/evp/rand.rs:703` | `EVP_RAND_free` | down | EXPORT-FREE | `rand` live; "this frame owns the reference it releases" | ESTABLISHED |
| P47 | `src/evp/rand.rs:1070` | `EVP_RAND_CTX_free` | down | EXPORT-FREE | `ctx` live; "this frame owns the reference it releases" | ESTABLISHED |
| P48 | `src/evp/signature.rs:915` | `EVP_SIGNATURE_free` | down | EXPORT-FREE | `signature` live; "this frame owns the reference it releases" | ESTABLISHED |
| P49 | `src/evp/skeymgmt.rs:570` | `EVP_SKEYMGMT_free` | down | EXPORT-FREE | `keymgmt` live; "this frame owns the reference it releases" | ESTABLISHED |
| P50 | `src/evp/skeymgmt.rs:1235` | `EVP_SKEY_free` | down | EXPORT-FREE | `skey` live; "this frame owns the reference it releases" | ESTABLISHED |
| P51 | `src/rsa/object.rs:696` | `RSA_free` | down | EXPORT-FREE | `r` live; "this frame owns the reference it releases" | ESTABLISHED |
| P52 | `src/runtime/bio/mod.rs:1085` | `BIO_free` | down | EXPORT-FREE | "this frame owns the caller's one reference, which it releases here" (veto caveat §3.5) | ESTABLISHED |
| P53 | `src/ssl/ssl_lib.rs:3085` | `SSL_CTX_free` | down | EXPORT-FREE | "the C-ABI caller ... owns the one reference this free releases (the caller's obligation)" | ESTABLISHED |
| P54 | `src/ssl/ssl_lib.rs:3453` | `SSL_free` | down | EXPORT-FREE | "the C-ABI caller ... owns the one reference this free releases (the caller's obligation)" | ESTABLISHED |
| P55 | `src/ssl/ssl_sess.rs:452` | `SSL_SESSION_free` | down | EXPORT-FREE | "the C-ABI caller ... owns the one reference this free releases (the caller's obligation)" | ESTABLISHED |
| P56 | `src/store/store_meth.rs:220` | `OSSL_STORE_LOADER_free` | down | EXPORT-FREE | provider-loader arm; "this frame owns the reference it releases" (legacy arm skips the count) | ESTABLISHED |
| P57 | `src/x509/x509_lu.rs:1812` | `X509_STORE_free` | down | EXPORT-FREE | "the C-ABI caller guarantees `xs` is live and owns the one reference this free releases" | ESTABLISHED |

### 1.3 Internal object bodies and helpers (4)

| ID | file:line | enclosing fn | op | class | owned/acted-for reference (witness quote) | verdict |
|---|---|---|---|---|---|---|
| P58 | `src/ssl/ssl_cert_comp.rs:228` | `OSSL_COMP_CERT_up_ref` | up | INTERNAL-UP | internal wrapper; `ssl_lib.rs:1075` non-NULL-checks the source slot ("`cpk.comp_cert[j]` owned by the live source cert") and acts for that owner. **Return value is discarded** (§3.2) | ESTABLISHED |
| P59 | `src/ssl/ssl_cert_comp.rs:201` | `OSSL_COMP_CERT_free` | down | INTERNAL-FREE | callers own the slot: `ssl_lib.rs:930` clears `comp_cert[j]`, `ssl_cert_comp.rs:318/350/421` free or replace an owned slot | ESTABLISHED |
| P60 | `src/engine/eng_init.rs:68` | `engine_unlocked_init` | up | ENGINE-HELPER-UP | `ENGINE_init` / `ENGINE_register_*` callers hold the engine; a `engine_table_select` `sk` entry borrows the global list's reference (`engine_list_add`), which `engine_list_remove` now retires only after `engine_unregister_from_all_tables` — see §2.1 | ESTABLISHED |
| P61 | `src/engine/eng_lib.rs:507` | `engine_free_util` | down | ENGINE-HELPER-FREE | callers: `ENGINE_free` (C-ABI), `engine_list_remove` ("this releases the list's own structural reference", matching `engine_list_add`'s up), `engine_unlocked_finish` (structural ref acquired by `engine_unlocked_init`) | ESTABLISHED |

### 1.4 `eng_lib` delegation bodies (2)

| ID | file:line | enclosing fn | op | class | owned/acted-for reference (witness quote) | verdict |
|---|---|---|---|---|---|---|
| P62 | `src/engine/eng_lib.rs:413` | `up_ref` | up | ENGINE-WRAP | `# Safety` forwards "the caller must hold the structural reference it acts for"; no independent witness in this frame | ESTABLISHED (forwarded) |
| P63 | `src/engine/eng_lib.rs:425` | `down_ref` | down | ENGINE-WRAP | `# Safety` forwards "the caller owns exactly one reference ... and on `Last` is the unique destructor runner"; no independent witness | ESTABLISHED (forwarded) |

### 1.5 List / registry (10)

| ID | file:line | enclosing fn | op | class | owned/acted-for reference (witness quote) | verdict |
|---|---|---|---|---|---|---|
| P64 | `src/engine/eng_list.rs:138` | `engine_list_add` | up | LIST/REGISTRY | "acts for the existing owner of `e` (the caller's structural reference) and the list takes that one new reference" | ESTABLISHED |
| P65 | `src/engine/eng_list.rs:154` | `engine_list_add` | down | LIST/REGISTRY | "drops the one structural reference acquired by the `up_ref` above" (matching acquire is P64) | ESTABLISHED |
| P66 | `src/engine/eng_list.rs:165` | `engine_list_add` | down | LIST/REGISTRY | same matching acquire (P64) on the cleanup-registration refusal | ESTABLISHED |
| P67 | `src/engine/eng_list.rs:184` | `engine_list_add` | down | LIST/REGISTRY | same matching acquire (P64) on the bad-tail refusal | ESTABLISHED |
| P68 | `src/engine/eng_list.rs:382` | `ENGINE_get_first` | up | LIST/REGISTRY | "The list owns the existing reference this call acts for; the caller receives exactly one new reference" | ESTABLISHED |
| P69 | `src/engine/eng_list.rs:410` | `ENGINE_get_last` | up | LIST/REGISTRY | same list-owned witness | ESTABLISHED |
| P70 | `src/engine/eng_list.rs:442` | `ENGINE_get_next` | up | LIST/REGISTRY | "The list owns the existing reference this call acts for; the iteration receives exactly one new reference" | ESTABLISHED |
| P71 | `src/engine/eng_list.rs:476` | `ENGINE_get_prev` | up | LIST/REGISTRY | same list-owned witness | ESTABLISHED |
| P72 | `src/engine/eng_list.rs:657` | `ENGINE_by_id` | up | LIST/REGISTRY | "The list owns the existing reference this call acts for" (lock held across the walk) | ESTABLISHED |
| P73 | `src/engine/tb_asnmth.rs:414` | `ENGINE_pkey_asn1_find_str` | up | LIST/REGISTRY | comment names the global list's reference (`engine_list_add`); the entry is retired by `engine_unregister_from_all_tables` under the write lock before the list reference is dropped, and the walk holds the read lock — see §2.2 | ESTABLISHED |

### 1.6 Dup-on-behalf and ASN.1 aux (3)

| ID | file:line | enclosing fn | op | class | owned/acted-for reference (witness quote) | verdict |
|---|---|---|---|---|---|---|
| P74 | `src/ssl/ssl_lib.rs:12118` | `SSL_dup` | up | DUP | "the C-ABI caller's outstanding `SSL *` reference passed in as `s`; the caller keeps that reference and must still `SSL_free` it, and it is not released during this call" | ESTABLISHED |
| P75 | `src/asn1/utl.rs:218` | `do_lock` (op `1`) | up | AUX | "The reference acted for belongs to the item's owner, who does not release it during this call" — restatement; **no production caller** (only the test at `x509_set.rs:812`) | **N/A** (no production path) |
| P76 | `src/asn1/utl.rs:230` | `do_lock` (op `-1`) | down | AUX | `asn1/fre.rs:305` is the item's free path and owns the value it releases ("Single release: no other owner holds it") | ESTABLISHED |

## 2. Formerly `UNATTRIBUTED` sites (now witnessed) and remaining evidence

1. **Resolved: `eng_init.rs:68` (P60), via `engine_table_select`.** The piles
   still store *borrowed* `ENGINE *` values and `engine_table_register` still
   takes no reference (both match the authority). The missing witness was the
   retirement of that borrow: `engine_list_remove` now calls
   `eng_fat.rs::engine_unregister_from_all_tables` under the engine write lock,
   **before** `engine_free_util` drops the list's structural reference. Every
   entry therefore borrows a reference that is live for the whole time the
   write-lock-protected `ossl_engine_table_select` can see it, and
   `engine_unlocked_init`'s up-ref acts for that owner. The unregistration is a
   deliberate memory-safety improvement over the authority (whose
   `ENGINE_remove` does not unregister and can leave dangling entries); it is
   recorded as a §17 divergence, not attributed to the authority. The select
   path's separate unowned-cached-default arm on init refusal (§3.1) is
   unchanged and remains a recorded hazard; it is not this up-ref.
2. **Resolved: `tb_asnmth.rs:414` (P73).** Same witness: the walk holds the
   engine read lock, and `engine_list_remove`'s unregistration takes the write
   lock before releasing the list reference, so a found entry's `struct_ref` is
   live when `up_ref` acts for it. The in-code comment now names the global
   engine list's reference (`engine_list_add`, P64) and the unregistration that
   retires it.
3. **`asn1/utl.rs:218` (P75), op `1` — N/A.** No production call site exists;
   the only caller is the unit test at `x509_set.rs:812`. The frame's comment is a
   restatement of the aux-callback contract, not a concrete witness, but the
   operation has no production path to attribute, so it is recorded N/A rather
   than UNATTRIBUTED. The `op 0` path (`asn1/new.rs:297`) does establish the
   initial count of 1, and the `op -1` path (P76) has a concrete free-path witness.

## 3. Caller/postcondition defects observed (not soundness proofs)

These are ownership-contract defects at callers of RC-1 wrappers, not failures
of `runtime::refcount` itself. None is demonstrated to cause UB on an ordinary
path; the adjudicator should weigh them as residuals.

1. **`engine_table_select` returns an unowned engine on refusal.**
   `eng_table.rs:460-472`: when `engine_unlocked_init` answers `0`, the
   `uptodate` arm returns the cached `funct` anyway. The authority does the
   same for a failed `init` callback; the crate adds a refcount-refusal trigger
   (`i32::MAX`, zero/destroying). The caller receives a pointer without an
   acquired reference.
2. **`ssl_lib.rs:1075` discards `OSSL_COMP_CERT_up_ref`'s result.** It then
   stores the source pointer into the duplicate at line 1076. On refusal (only
   `i32::MAX` on the source) the duplicate holds a pointer without a reference
   and a later `cert_pkey_clear` releases it. The neighbouring
   `X509_up_ref(cpk.x509)` is also unchecked; `EVP_PKEY_up_ref` is checked.
   The authority's unchecked call could not observe `0`; the crate's checked
   protocol makes the unchecked postcondition newly expressible.
3. **`engine_table_select`/`engine_table_register` borrow table entries**
   (see §2.1-2.2). This is an authority-level ownership assumption that the
   crate does not encode; it should be recorded as a divergence/known
   authority hazard rather than treated as discharged.
4. **`DSO_free` failure path (`dso/mod.rs:314-342`) contradicts its doc.**
   The down-ref has already consumed the caller's last reference and installed
   `REF_DESTROYING`; a failing `unload`/`finish` returns 0 without freeing.
   The doc says "the object is still owned by the caller at that point"; a
   retry sees `Retired`, returns 0, and the object leaks. The authority also
   fails to free on this path, so behaviour is compatible, but the ownership
   statement is false and the retry is a permanent leak.
5. **`BIO_free` veto (`runtime/bio/mod.rs:1085-1100`) contradicts its doc.**
   The reference is consumed before `BIO_CB_FREE` runs; a `<= 0` callback
   returns 0 without destruction. The doc says the veto leaves "ownership
   unchanged". A retry after the veto is not a second release of an owned
   reference; it observes `Retired` (last-ref case) and leaks. Authority
   ordering is the same.
6. **`X509_STORE_free`'s `# Safety` over-restricts** ("this call must retire
   the last reference") while the body correctly supports `Remaining`. Wording
   only; the wrapper's actual C-ABI obligation is the normal one.
7. **`ENGINE_get_next`/`_get_prev` do not state that the caller owns (and this
   call releases) the passed `e`.** The code calls `ENGINE_free(e)`. The
   authority's API contract carries that obligation, but the crate's `# Safety`
   says only "live". Documentation gap.

## 4. Tests (cfg(test)) — 38 direct calls in 12 test functions

These are **protocol-level** calls. The module's own comment is explicit:

> "each test owns the `AtomicI32` it passes ... These are protocol-level tests,
> not conforming-C-caller evidence." (`refcount.rs:429-433`)

| ID | file:lines | enclosing test | calls | verdict |
|---|---|---|---|---|
| T01 | `runtime/refcount.rs:447,448,451` | `down_ref_claims_last_reference_then_retires` | down x3 | ESTABLISHED (test harness) |
| T02 | `runtime/refcount.rs:462,469` | `up_ref_refuses_zero_and_destroying` | up x2 | ESTABLISHED (test harness) |
| T03 | `runtime/refcount.rs:480` | `up_ref_refuses_overflow_without_changing_count` | up | ESTABLISHED (test harness) |
| T04 | `runtime/refcount.rs:491,496` | `up_ref_preserves_positive_count_answer` | up x2 | ESTABLISHED (test harness) |
| T05 | `runtime/refcount.rs:524,559` | `many_threads_last_release_is_unique` | down x2 | ESTABLISHED (test harness) |
| T06 | `runtime/refcount.rs:588,592,605,607` | `concurrent_increments_and_decrements_conserve_ownership` | up, down x3 | ESTABLISHED (test harness) |
| T07 | `runtime/refcount.rs:638,650,675,679,691,693` | `up_ref_racing_last_release_never_resurrects` | down/up x6 | ESTABLISHED (test harness) |
| T08 | `runtime/refcount.rs:716,718,720,722,723` | `up_ref_down_ref_outcome_classes_are_reachable` | up/down x5 | ESTABLISHED (test harness) |
| T09 | `runtime/refcount.rs:777,779,788,790` | `loom_base_reference_yields_one_last` | up, down x3 | ESTABLISHED (test harness) |
| T10 | `runtime/refcount.rs:805,811,827,828,836,838` | `loom_last_release_race_never_resurrects` | down/up x6 | ESTABLISHED (test harness) |
| T11 | `runtime/refcount.rs:853,858` | `loom_sentinel_absorbs_a_second_release` | down x2 | ESTABLISHED (test harness) |
| T12 | `runtime/refcount.rs:875` | `loom_up_ref_refuses_i32_max` | up | ESTABLISHED (test harness) |

Two test-only notes: T06 and T07 deliberately call `up_ref` **without** a
worker-held reference; their own comments call this "protocol-level evidence ...
not conforming-caller evidence". `refcount.rs`'s `exhaustive_model_tests`
(`:891-1376`) does not call the real functions at all; it models them over
integers. `family_reentrancy_tests` (`:188-420`) reaches the protocol only
indirectly through the object `*_free` wrappers (DH, DSA, RSA, EC_KEY,
EVP_PKEY, BIO) and is not a direct RC-1 call site.

## 5. Summary

| class | sites |
|---|---|
| EXPORT-UP | 30 |
| EXPORT-FREE | 27 |
| INTERNAL-UP | 1 |
| INTERNAL-FREE | 1 |
| ENGINE-HELPER-UP | 1 |
| ENGINE-HELPER-FREE | 1 |
| ENGINE-WRAP (forwarded, not independent) | 2 |
| LIST/REGISTRY | 10 |
| DUP | 1 |
| AUX | 2 |
| **production total** | **76** |
| TEST (12 functions, not caller evidence) | 38 |
| **grand total** | **114** |

**Verdicts (production):** ESTABLISHED **75**, of which 2 are
forwarded-only (`eng_lib` delegation); independent ESTABLISHED **73**.
UNATTRIBUTED **0**. The two former UNATTRIBUTED sites now have a source
witness: `engine_list_remove` retires every operation-table entry
(`engine_unregister_from_all_tables`) under the write lock before it drops the
global list's structural reference, which is the reference each borrowed entry
acts for (§2.1-2.2). N/A **1** — `asn1/utl.rs:218`
(op `1`, no production caller). Test calls: 38, all harness-owned and explicitly
non-conforming.

## 6. Limits of this audit

- **This is not a proof.** It is a source-level precondition inventory with
  quoted witnesses. It does not prove that any witness is sufficient, that a
  numeric count is correct at runtime, or that the C-ABI callers obey their
  contracts.
- The loom model checks and the exhaustive bounded model in
  `REFCOUNT-CHECKS.md` cover the **protocol state machine** (`up_ref`/`down_ref`
  transitions, sentinel, races). They do **not** cover caller ownership,
  provenance, liveness of the object storage, duplicate releases across
  different call sites, or the engine table's borrowed-entry invariant.
- The 38 test calls establish protocol behaviour only; the module itself says
  they are not conforming-C-caller evidence.
- No dynamic evidence was collected for this audit (no Miri, sanitizer,
  differential court, or fuzz run). Compatibility of the observed divergence
  candidates was not executed.
- `REFCOUNT-BOUNDARY.md` and `REFCOUNT-CHECKS.md` were read, not modified. No
  graduation state is claimed here; the adjudicator decides.
