# S22 — census of the "typed accessor over uninitialised storage" class

Source identity: `integrate/safe-c33`, HEAD `7e2de368d` plus this subphase's uncommitted
working tree. The census was produced by searching for `OPENSSL_malloc_array`,
`CRYPTO_malloc`, `CRYPTO_malloc_array`, `CRYPTO_secure_malloc_array`, `alloc`,
`alloc_zeroed`, `MaybeUninit`, `set_len`, `from_raw_parts(_mut)`, and every
`as_slice`/`as_mut_slice`/`Deref`/`Index`/`AsRef`/`AsMut` implementation on a type that
wraps freshly allocated storage, then reading each hit.

## Classification

| Class | Meaning |
|---|---|
| **SAFE-BY-CONSTRUCTION** | The storage is zeroed or fully written before the owning type is constructed, so every typed view is over initialised memory. |
| **MISUSE-RESISTANT** | The owner either exposes only a raw pointer (no `&T`/`&mut [T]`), or the typed transition requires an `unsafe` token/constructor whose contract names initialisation. A safe caller cannot reach a typed view of uninitialised storage. |
| **UNSOUND** | A safe caller (or an in-crate caller following the documented contract) can form a reference over uninitialised storage. |

The class is *not* "every allocation that is not zeroed": an owner that only hands out
`*mut T` is not in it, because forming a reference from a raw pointer is an explicit
`unsafe` act at the caller. The defect is a **typed borrow whose validity the owner has not
established**.

## Tally

| Class | Sites | Disposition |
|---|---:|---|
| **UNSOUND (owner-shaped)** | **4** | all repaired in S22 |
| **UNSOUND (frame-local, same shape)** | **1** | repaired in S22 |
| SAFE-BY-CONSTRUCTION | 16 | none |
| MISUSE-RESISTANT | 12 | none |

Total owner-shaped entries examined: 32.

## UNSOUND entries

### U1 — `src/ml_dsa/poly.rs` `Vector::alloc` / `Vector::secure_alloc` → `as_slice` / `as_mut_slice`

- Sites: `PolyBlock::malloc` / `secure_malloc` (current `src/ml_dsa/poly.rs:148`, `:176`);
  `Vector::alloc` (`:383`), `Vector::secure_alloc` (`:410`), `as_slice` (`:462`),
  `as_mut_slice` (`:472`). This is S21-O1.
- Defect: `OPENSSL_malloc_array` does not zero. The owner published the raw block as
  `Vector { poly, num_poly }`, and the accessor contract required "initialised polynomials"
  that no constructor established. Callers therefore formed `&mut [Poly]` over uninitialised
  storage merely to initialise it — `ossl_ml_dsa_key_dup` (`vector_copy(t1.as_mut_slice(), …)`),
  `ntt::ossl_ml_dsa_matrix_mult_vector` (`Vector::zero(t.as_mut_slice())`), and
  `key::public_from_private`. Forming the reference is UB even when every element is written
  immediately afterwards.
- Authority: `crypto/ml_dsa/ml_dsa_vector.h:33-49` (`vector_alloc`, `vector_secure_alloc`) uses
  `OPENSSL_malloc_array` / `OPENSSL_secure_malloc_array` and leaves the block uninitialised;
  `vector_zero` (`:66-70`) and `poly_zero` (`ml_dsa_poly.h:18-22`) write the all-zero value
  before any read. The allocation seam is unchanged.
- Repair: `PolyBlock` now holds `NonNull<MaybeUninit<Poly>>` and zero-initialises the whole
  extent (`:204`) inside both constructors, before `into_raw` (`:213`) can publish a
  `*mut Poly`. Zero is a valid `Poly`: `#[repr(C)] { coeff: [u32; 256] }` has no invalid bit
  patterns, and all-zero is exactly `poly_zero`'s value. The accessors' preconditions now hold
  by construction. Release arms unchanged (plain `CRYPTO_free`; secure
  `CRYPTO_secure_clear_free`).

### U2 — `src/ml_dsa/sign.rs` `Scratch::new` → `take_bytes` / `take_polys`

- Site: `Scratch::new` (`src/ml_dsa/sign.rs:206`).
- Defect: the constructor formed `&mut [u8]` over a fresh `CRYPTO_malloc` scratch blob whose
  contract said only "writable", not "initialised"; `take_bytes`/`take_polys` then partitioned
  it into typed views (`from_raw_parts_mut`). Callers: `ml_dsa_sign_internal`,
  `ml_dsa_verify_internal`, `key::public_from_private`, `key::pairwise_check`.
- Authority: `ml_dsa_sign.c` / `ml_dsa_key.c` treat the blob as uninitialised scratch.
- Repair: the constructor zero-initialises `len` bytes through the raw pointer before forming
  the slice. The blob is washed/cleansed by its `OwnedBuf` on every exit, unchanged.

### U3 — `src/pkcs12/p12_utl.rs` `OwnedBuf::new` → safe `as_mut_slice`

- Sites: `src/pkcs12/p12_utl.rs:79` (`new`), `:104` (`as_mut_slice`, a **safe** method).
- Defect: a safe caller could obtain `&mut [u8]` over the `CRYPTO_malloc` block before any
  writer ran. `OPENSSL_asc2uni`/`OPENSSL_utf82uni` happen to fill every byte, but the type did
  not enforce it.
- Repair: `new` zero-initialises `len` bytes; the accessor's soundness no longer depends on
  caller discipline. Allocation size/`file`/`line` and the plain `CRYPTO_free` release are
  unchanged.

### U4 — `src/bn/rand.rs` `OwnedBuf::new` → safe `as_mut_slice`

- Sites: `src/bn/rand.rs:163` (`new`), `:185` (`as_mut_slice`, safe).
- Defect: same shape; `bnrand`/`dsa_nonce` hand the slice to `RAND_*_bytes_ex` as a pure write
  destination, but the safe accessor itself admitted a read of uninitialised bytes.
- Repair: `new` zeroes `len` bytes. The cleansing release (`CRYPTO_clear_free`) is unchanged.

### U5 — `src/ssl/t1_lib.rs` `tls1_save_peer_sigalgs_raw` / `tls1_save_peer_sigalgs_default`

- Sites: `src/ssl/t1_lib.rs:846` and `:873` (post-fix line numbers).
- Defect (frame-local, not an owner type): a fresh `CRYPTO_malloc` block was viewed as
  `&mut [u16]` before any element was written. The loop/copy filled it immediately, but the
  reference was formed over uninitialised storage.
- Repair: write each slot through `p.add(i).write(..)` / `ptr::copy_nonoverlapping` without
  forming a typed view. Same bytes, same allocation and release.

## SAFE-BY-CONSTRUCTION (16)

| Site | Why |
|---|---|
| `src/runtime/owned_str.rs:67,256` `OwnedStr`/`OwnedCStr`, `:350` `as_c_str` | adoption requires a live NUL-terminated C string; `CStr::from_ptr` validates before the reference exists. |
| `src/runtime/sparse_array.rs:156` `OwnedNode`, `:180` `Deref` | `CRYPTO_zalloc` then `write(value)`: the value is fully initialised before `Deref`. |
| `src/runtime/mem.rs:1149` `CleansedScratch` | `[0u8; N]`; every accessor sees initialised bytes. |
| `src/hpke/mod.rs:936` `CleansedScratch` | `[c_uchar; N]`; same. |
| `src/ssl/t1_enc.rs:70` `CleansedBlock` | `[0u8; N]`; same. |
| `src/ssl/tls13_enc.rs:146` `CleansedBlock` | `[0u8; N]`; same. |
| `src/x509/pcy_lib.rs:202` `tree_levels` | the level array is one `CRYPTO_calloc` block (zeroed). Retained aliasing/lifetime obligation (owner-derived borrow, AGENTS §2). |
| `src/ec/mult.rs:690-707` WNAF arrays | raw `.add()` writes before reads; `wnaf[0]` is pre-set for the error path. |
| `src/modes/ocb.rs:236,318` OCB L-table | raw writes to all slots before the first read (`l_index` bounds the read). |
| `src/ec/curve.rs:640` `param_bytes` | `BN_bn2binpad` fills each slot before the comparison loop. |
| `src/encoder_pkey.rs:488` `id_names` | the loop writes every slot before the array is read or released. |
| `src/txt_db/txt_db.rs:264,281` `index`/`qual` | both arrays are zero-filled in a loop immediately after allocation. |
| `src/apps/ecparam.rs:69` `curves.set_len` | only the `filled` rows the C call initialised are published. |
| `src/asn1/i2d.rs:1048` `derlst` | `count` initialised entries. |
| `src/asn1/a_print.rs:124` | the existing `ASN1_STRING` data, already initialised. |
| `src/provider/ml_common_codecs.rs:343` | the first `NUM_PKCS8_FORMATS` slots are initialised. |

## MISUSE-RESISTANT (12)

| Site | Why |
|---|---|
| `src/asn1/owned.rs:53` `OwnedBlock::malloc` | allocation may be uninitialised, but the only accessor is `as_ptr() -> *mut T`; no typed reference. |
| `src/runtime/bio/owned.rs:115` `OwnedCtx`, `:130` `zalloc` | constructed only from a `CRYPTO_zalloc` block under the `CtxDestroy` zero-validity obligation (unsafe trait). |
| `src/runtime/bio/owned.rs:227` `RawCtx`, `:326` `assume_init` | holds `NonNull<MaybeUninit<T>>`; the typed transition is `unsafe fn assume_init` with an initialisation contract. |
| `src/runtime/bio/owned.rs` `OwnedBlock::take` | raw block, raw accessor. |
| `src/runtime/owned_buf.rs:657` `as_ptr` | raw pointer only. |
| `src/ml_dsa/key.rs:319` `as_ptr` | raw pointer only. |
| `src/ml_dsa/sign.rs:148` `as_ptr` | raw pointer only. |
| `src/ml_dsa/encoders.rs:161` `as_ptr` | raw pointer only. |
| `src/ml_dsa/key.rs` `PrivBlock::{s1,s2,t0,s1_mut}` | safe slice accessors, but the handle exists only after the unsafe `alloc`/`of` constructor; after U1 the block is initialised at publication. |
| `src/pem/pvkfmt.rs:170` `as_ptr` | raw pointer only. |
| `src/ec/print.rs:93` `as_ptr` | raw pointer only. |
| `src/ml_kem/key.rs` `OwnedBuf` | raw pointer only; no typed accessor found. |

## Out-of-class observations (not repaired, retained with blocker)

1. `src/ml_dsa/poly.rs:364` `Vector::init` and `:696` `matrix_init` are **safe** constructors
   that store a caller-supplied raw pointer. They cannot cause UB alone (they never
   dereference), but they publish an owner whose accessors assume initialised storage. Every
   in-crate use is inside an `unsafe fn` with a documented precondition. Making them
   `unsafe fn` would be the §1-consistent end state; it is a signature change across ~20 call
   sites and is deferred to its own batch (blocker: call-site churn, not a design question).
2. `src/provider/cipher_gcm.rs:857` and `:1448` form `&mut [u8]` over a **caller-provided FFI
   out-buffer**. The C contract says "writable", not "initialised". Resolving this is a
   cross-cutting decision about how the crate models C output buffers (not an owner defect);
   retained with every other FFI out-buffer site.
3. `src/evp/*`, `src/ui/ui_lib.rs`, `src/store/store_lib.rs`, `src/hpke/mod.rs` adoption
   constructors were checked: they either hold `MaybeUninit` or expose only raw pointers.
   No new typed-accessor defect found.

## Retained obligations

- `Vector::init`/`matrix_init`: caller-established initialisation (see 1 above).
- `x509::pcy_lib::tree_levels`: the level block is zeroed, but the borrow is still
  owner-derived-plus-pointer; the aliasing obligation is retained (§2 audit item).
- The secure-heap cleansing path is observed by the existing
  `runtime::owned_buf::secure_cleansed_*` tests; S22's new probe covers the documented
  no-heap fallback used by the ML-DSA test.
