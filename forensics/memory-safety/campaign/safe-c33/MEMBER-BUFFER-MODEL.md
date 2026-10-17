# Member-buffer model — object-owned C buffers in `#[repr(C)]` structs

**Status:** proven on `PKCS7.ctx.propq` (`stage/p25/memberbuf-propq`); CMS and the X.509 family
are follow-up applications, and `SSL_SESSION` (`stage/p25/memberbuf-sslsess`) is the first
application of the `(ptr, len)` **blob** variant (§2.6). Living document — re-read at the point of
use.

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

### 2.6 The `(ptr, len)` **blob** variant

Some members are not C strings but `(pointer, length)` pairs the object owns as a unit:
`SSL_SESSION`'s `ext_tick`/`ext_ticklen`, `ext_alpn_selected`/`ext_alpn_selected_len` and
`ticket_appdata`/`ticket_appdata_len`. The model applies with one extra obligation: the length is
part of the member, so the invariant and every operation must keep the pair consistent.

> A `(unsigned char *p, size_t n)` member of an object-owned `#[repr(C)]` struct is, at every
> observation, **either `(NULL, 0)` or a single owned block of exactly `n` bytes produced by the
> crate's allocator seam and owned by the enclosing object** — a `CRYPTO_memdup`/`CRYPTO_malloc`
> block, or a block adopted from the ASN.1 item layer whose ownership the object takes over. The
> enclosing object is that block's only owner; nothing else frees it, aliases it, or writes `p` and
> `n` independently.

The handle borrows **both** fields, so a caller cannot move one without the other:

| operation | kind | contract |
|-----------|------|----------|
| `MemberBufSlot::of(&mut p, &mut n)` | `unsafe fn` | the pair currently obeys the invariant |
| `MemberBufSlot::clear(file, line)` | safe | release the incumbent (if any) at the authority's own `file`/`line`, leaving `(NULL, 0)` |
| `MemberBufSlot::store(p, n)` | `unsafe fn` | `p` is NULL or a fresh exclusive block whose allocation is exactly `n`; the member is empty |
| the object's reader (e.g. `SslSession::ext_tick`) | safe | return the current `(p, n)` — `(NULL, 0)` when unset |

`clear` sets the companion length to 0 as well as the pointer — exactly the authority's "release,
unconditionally, then set the length to zero" (e.g. `SSL_SESSION_set1_alpn_selected`,
`ssl_sess.c:1131-1148`) — so the two fields never disagree. `store`'s `debug_assert!` requires the
member empty, so a caller cannot leak an incumbent by storing over it. The `file`/`line` are, as in
§2.3, the authority's own free site, and `CRYPTO_free`'s NULL no-op makes an unconditional `clear`
observationally identical to the authority's guarded free.

The C-string variant (`MemberCStrSlot`) is the `propq` shape of §2.2 — one pointer, NUL-terminated,
no companion; both variants share the §2.3 rules and are defined in the module that owns the struct.

### 2.7 The in-place **regrow** (`realloc`) operation

`clear`+`store` expresses "release the incumbent, then take a fresh block", but some members are
regrown **in place**: the authority replaces the block with `CRYPTO_realloc`, and a refused regrow
must **keep** the old block (standard `realloc` semantics) rather than free it. `CertKey::serverinfo`
is set this way by `SSL_CTX_use_serverinfo_ex` (`ssl_rsa.c:839`). The model adds one operation for
that shape:

| operation | kind | contract |
|-----------|------|----------|
| `MemberBufSlot::realloc(new_len, file, line) -> *mut u8` | `unsafe fn` | the member currently obeys the invariant; `new_len > 0`. Regrows the block through the authority's own `CRYPTO_realloc` site, returns the (possibly moved) block on success (member becomes `(new, new_len)`), and on NULL leaves the member **unchanged** — the old block is kept and still owned. |

The failure semantics are exactly `realloc`'s: a NULL return means the old allocation was **not**
freed and the member still owns it, so the object destructor's later `clear` remains the single
release. `realloc` is defined only for the byte-extent variant (`N = usize`), because the request is
a byte count; element-counted lists (`supportedgroups`) are a retained raw boundary (§5.6), not a
blob. The caller owns the returned pointer and must initialise the first `new_len` bytes before any
of them are read.

The operation publishes the pointer and the length together. The authority sets the pointer one
statement before the length (after its `memcpy`); no allocator event or observer runs between them,
so the allocator transcript and the observable final state are identical. Use `realloc` when the
authority regrows in place; use `clear`+`store` only when it frees the old block first.

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
* **`SSL_SESSION` (§5.6) carries one recorded safety improvement, on a failure path only.** The four
  handshake writers (`statem_clnt.rs`'s `tls12`/`tls13_process_new_session_ticket`,
  `statem_srvr.rs`'s `tls12`/`tls13_construct_new_session_ticket`) freed `sess->ext.tick` and then
  allocated a replacement; if the allocation was refused, the pre-conversion code left the
  *just-freed* pointer in the field — a latent double free once the session was released. The
  handle's `clear` leaves `(NULL, 0)` instead, so the refused-allocation path is memory-safe. The
  allocator-event transcript is unchanged (the same free, then the same refused allocation); only
  the in-memory field on the refused path differs, and that path is reachable only through the
  function's error return. This is the §17 "do not reproduce UB" treatment, recorded rather than
  hidden.
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
6. **`SSL_SESSION`** (`ssl/ssl_lib.rs`, lifecycle in `ssl/ssl_sess.rs`) — the C-string
   `ext_hostname` and the `(ptr, len)` blobs `ext_tick`/`ext_ticklen`,
   `ext_alpn_selected`/`ext_alpn_selected_len` and `ticket_appdata`/`ticket_appdata_len`. Handled
   by module-local `MemberCStrSlot`/`MemberBufSlot` and the `SslSession` readers; the four fields
   are **private** in `ssl_lib.rs` and every reader/writer across `src/ssl/**` (the codec
   `ssl_asn1.rs`, the printer `ssl_txt.rs`, the handshake `statem_*.rs`) was converted. This is
   the first application of the §2.6 **blob** variant. The remaining C-string members
   `psk_identity_hint`, `psk_identity`, `srp_username` were converted in a later batch
   (all **private**, via `MemberCStrSlot`), as was `Cert.psk_identity_hint` (the
   `SSL_CTX`/`SSL` cert). The `SslCtx`/`Ssl` blob and C-string members were completed in a further
   batch: `SslCtx::propq`, `CertKey::serverinfo` (through the §2.7 `realloc`), and
   `Ssl::ext_hostname`/`s3_alpn_selected`/`s3_alpn_proposed`/`pha_context` are now converted and
   **private**. `SslCtx`/`Ssl::supportedgroups` is a **retained raw boundary** (not a
   `MemberBufSlot`): its length is an *element count*, not the allocation's byte extent, and its
   writer `t1_lib::tls1_set_groups` takes the raw `*mut *mut u16`/`*mut usize` pair; it stays
   `pub(crate)` with its three accesses (the `tls1_set_groups` regrow, `tls1_get_supported_groups`'s
   slice, and the `SSL_new` copy) and two destructor frees enumerated in the batch report.
