# Member-buffer model — object-owned C buffers in `#[repr(C)]` structs

**Status:** proven on `PKCS7.ctx.propq` (`stage/p25/memberbuf-propq`); CMS/X.509 are
follow-up applications (see §5). Living document — re-read at the point of use.

## 1. The problem

Many `#[repr(C)]` objects model a C-owned buffer as a **field** whose owner, setter,
reader and destructor live in *different functions and modules*. `PKCS7_CTX::propq` is
the archetype: it is set in `ossl_pkcs7_set1_propq` (`pk7_lib.c:494`, spliced in
`pk7_lib.rs`) and `PKCS7_new_ex` (`pk7_asn1.c:93`), read in
`ossl_pkcs7_ctx_get0_propq`/`ctx_propagate`/`d2i_PKCS7`, and released in `PKCS7_free`
(`pk7_asn1.c:115`) and again, for a nested `authsafes`, in `PKCS12_free`
(`pkcs12/p12_asn.c:35`). The ownership invariant is real but *implicit and scattered*:
nothing in the code states "this field is always NULL or one `CRYPTO_strdup` block this
object owns", so each site must re-derive it, and a wrong re-derivation is a leak or a
double free.

## 2. The model

Keep the exact C `#[repr(C)]` representation and the field's type; move the ownership
invariant into **validated Rust operations** so it is stated once and funnelled through
one place.

### 2.1 The invariant (per member field)

> A `char *` member of an object-owned `#[repr(C)]` struct is, at every observation,
> **either NULL or a single NUL-terminated block produced by the crate's `CRYPTO_strdup`
> seam and owned by the enclosing object**. The enclosing object is that block's only
> owner: the block is released **exactly once**, by the object destructor or by the next
> setter that replaces it. Nothing else frees it, aliases it, or writes the field.

The empty state is NULL (not a zero-length block); a setter that is given a NULL input
leaves the field NULL.

### 2.2 The operations

One small handle type per member (or a module-local pair of operations), in the module
that **defines the struct**:

| operation | kind | contract |
|-----------|------|----------|
| `PropqSlot::of(&mut ctx) -> PropqSlot` | `unsafe fn` | `ctx` is a live object's context; its field currently obeys the invariant |
| `PropqSlot::clear(file, line)` | safe | release the incumbent (if any) at the authority's own `file`/`line`, leaving the field NULL |
| `PropqSlot::store(new)` | `unsafe fn` | `new` is NULL or a fresh exclusive `CRYPTO_strdup` block whose ownership transfers to the object; the field is empty |
| `Pkcs7Ctx::propq()` (reader) | safe | return the current pointer (NULL when unset) |

* **set / replace** = `clear` then, if the duplicate succeeded, `store`. This preserves
  the authority's *free-old-then-allocate-new* order and its failure path (a failed
  duplicate leaves the field NULL, exactly as `pk7_lib.c:494`).
* **take-for-release** = `clear` at the destructor's own coordinates. This is the
  `OwnedStr::adopt` shape: the block is adopted from the field and released by a single
  path, so the "release once" obligation is discharged by construction.
* **reads** go through the reader. A raw read cannot free or alias, but funnelling it
  keeps the field's *writers* enumerable.

`unsafe` appears only at the proof boundaries — obtaining the borrow (`of`) and accepting
an externally-allocated block (`store`). `clear` is **safe**: given a handle built by
`of`, the incumbent is by definition the object's own single block, so freeing it is
sound. (Same asymmetry as §1 of `AGENTS.md`: release of owned state is safe; *adoption*
of raw state is the obligation.)

### 2.3 Allocator / ABI / failure-path / compatibility rules

* **Allocator coordinates preserved.** The caller still performs `CRYPTO_strdup` with the
  authority's exact `file`/`line` (e.g. `pk7_asn1.c:102`, `pk7_lib.c:501`), and the handle
  frees with the authority's exact release coordinates (`pk7_asn1.c:115`,
  `pk7_lib.c:497`). The handle takes `file`/`line` as arguments rather than baking them in,
  because one member is released from several authority sites.
* **NULL-free is a no-op.** The seam's `CRYPTO_free` returns early on NULL
  (`runtime/mem.rs` `dealloc`), so an unconditional `clear` is observationally identical to
  the authority's `if (p) free(p); p = NULL;` *and* to its unguarded `OPENSSL_free(p)`.
* **The `CRYPTO_*` seam is untouched**, so a caller-installed `CRYPTO_set_mem_functions`
  hook observes the same allocation/release sequence and high-water mark.
* **ABI unchanged.** No `#[repr(C)]` layout, field type, offset, exported symbol or
  signature changes; the field stays `*mut c_char` so the C object is byte-identical.
* **Fixed order.** `clear` before `CRYPTO_strdup` — never allocate the replacement before
  releasing the incumbent — so allocation-failure and hook-observable behaviour match.

### 2.4 Why the field stays raw (and visibility)

The field must keep its exact type and offset to reproduce the authority's C layout, so it
cannot *be* a Rust owner type. The handle is therefore a transient **view/borrow** over
the field, not a resident owner. Full compile-time enforcement would require making the
field private to a module that owns it; that is only possible once **every** accessor site
is converted (CMS/X.509/`pkcs12` still read some fields directly — see §5), so the model
is adopted site-by-site and the field's remaining direct accesses are enumerated rather
than silently trusted.

### 2.5 Relationship to the existing owned-handle pattern

It is the **resident-member** counterpart of the per-module `OwnedStr` handle
(`cmp/cmp_ctx.rs`, `ct/ct_log.rs`, `ct/ct_sct_ctx.rs`) already used across the campaign:

* `OwnedStr` (a *local* owner) = `CRYPTO_strdup` block held in a Rust local, freed by
  `Drop`; used for setter locals and constructor temporaries.
* `PropqSlot` (a *member* owner) = the same block, but *resident in a C object*, so there
  is no Rust value to `Drop` — the object destructor is the `Drop`. The handle supplies the
  single sanctioned release/store operations; `clear`/`store` are the member analogue of
  dropping/adopting an `OwnedStr`.

Both express the identical invariant — "NULL, or one seam block, released once" — and both
keep the block at the authority's `file`/`line`.

## 3. Applying the model to `PKCS7.ctx.propq`

* `src/pkcs7/pk7_asn1.rs` — defines `PropqSlot` and `Pkcs7Ctx::propq()`; the writer sites
  `PKCS7_new_ex` and the release site `PKCS7_free` now go through the handle; `d2i_PKCS7`
  reads through the reader.
* `src/pkcs7/pk7_lib.rs` — `ossl_pkcs7_set1_propq` is now `clear` → `strdup` → `store`;
  `ossl_pkcs7_ctx_propagate` and `ossl_pkcs7_ctx_get0_propq` read through the reader.

Every read/write/release of the member *within these two modules* now passes through the
handle/reader, so the free-then-store logic and the "release exactly once" argument exist
in exactly one place.

## 4. Recorded divergence / limitations

* No behavioural divergence: coordinates, order, NULL semantics and the seam are preserved
  (see §2.3). No deliberate safety improvement over the authority was required here.
* The field is now **private** to `pkcs7/pk7_asn1.rs`: every read of `PKCS7.ctx.propq` goes
  through [`Pkcs7Ctx::propq`] and every write through [`PropqSlot`], so the C ABI
  `#[repr(C)]` representation is unchanged while the field's accesses are compile-time-confined
  to the module that owns it. The former cross-module readers (§5.1) are converted and the
  retained raw boundary is now only `PropqSlot::of`/`store` (the two proof edges) — a
  *retained*, not hidden, boundary.

## 5. Follow-up applications (same model, not yet converted)

Adopt the model next, in this order:

1. ~~**`pkcs7/pk7_mime.rs`** (read: `SMIME_read_PKCS7_ex`) and **`pkcs12/p12_add.rs`**
   (read: `PKCS12_unpack_p7encdata_ex`) — readers of `PKCS7.ctx.propq`.~~ **Done** (along with
   the `pkcs12/{p12_kiss,p12_mutl,p12_npas}.rs` and `x509/x_all.rs` readers of
   `PKCS7.ctx.propq`); this is what let the `Pkcs7Ctx::propq` field go private.
2. ~~**`pkcs12/p12_asn.rs`** (`PKCS12_free`, `p12_asn.c:35`) — a *second release site* for a
   `PKCS7.ctx.propq` (the nested `authsafes`); it must adopt `PropqSlot::clear`.~~ **Done**
   (uses `PropqSlot::clear(FILE, 35)`).
3. **CMS**: `cms/cms_lib.rs` and the `CmsCtx` in `cms/cms_asn1.rs` (`CMS_ContentInfo`'s
   `propq`) — a different struct, same invariant.
4. **X.509 family**: `x509/x_x509.rs` (`X509.propq`), `x509/x_crl.rs` (`X509_CRL.propq`),
   `x509/x509_req.rs` (`X509_REQ.propq`), `x509/x_pubkey.rs` (`X509_PUBKEY.propq`), and
   `x509/x509_lu.rs` (`X509_STORE_CTX.propq`) / `x509/by_store.rs`.
5. A shared crate-level `MemberCStr` may be warranted once three or more families use it;
   until then each owner module keeps a module-local handle, consistent with `OwnedStr`.
