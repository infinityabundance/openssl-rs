//! `crypto/dh/` — the `DH` object and its method table, Phase 8.5's first slice.
//!
//! This module is Phase 8.5's, and like Phase 8.4's `src/rsa/mod.rs` it is being built in the
//! slices the ledger's labels separate rather than all at once, because the block is ninety-four
//! labels and its parts have different prerequisites. What is here now is the **method table**
//! (`crypto/dh/dh_meth.c`, the twenty-one `DH_meth_*` labels) — the one part of the block whose
//! bodies allocate a table, store a pointer in it, or read one back, and therefore the one part
//! with no cryptographic callee at all.
//!
//! **Why the method table is first, and why it is not the plan's first item.** `docs/PHASE-8-
//! SUBPHASES.md` orders 8.5's landing as the FFC primitives, then the object layer, then the key
//! generation and agreement, then the parameter generation, then the controls. The method table
//! is *reachable from none of those* and blocks none of them: `dh_meth.c` is twenty-one
//! allocation-and-store entry points that read only `DH_METHOD`'s own shape. It is landed first
//! because it is the only slice whose prerequisites are already in, which is the same reading —
//! and the same precedent — as 8.4's slice B (D284): the object's shape had to be transcribed
//! there anyway, and the method table was the one slice that did not also need the crypt layer.
//!
//! **What is not here, named rather than implied.** The order above is the *dependency* order and
//! this commit does not disturb it. `crypto/ffc/`'s primitives (`ossl_ffc_generate_private_key`,
//! `ossl_ffc_params_simple_validate` and the `ffc_params_generate.c` generators behind it) are
//! 8.5's own row and the largest single piece of it; `crypto/dh/dh_lib.c`'s object layer, the
//! `miller`-free half of `dh_key.c`, `dh_gen.c` and `dh_check.c` follow it. None of those bodies
//! is transcribed here, and none is stubbed or approximated: every one of the seventy-three
//! remaining `src/dh/mod.rs` labels stays `open` in `forensics/phase8-obligations.json`, which is
//! the only list that says what a stratum has still to do.
//!
//! ## `DH_METHOD` is 72 bytes with nine members, and the shape is the whole contract
//!
//! `struct dh_method` (`crypto/dh/dh_local.h:47-64`) is declared in `dh_local.h` and is opaque in
//! `crypto/dh/dh_local.h:47-64`) is declared in `dh_local.h` and is opaque in
//! the installed header, so nothing a consumer can compile names its fields. It is still a real
//! layout: `DH_meth_dup` copies it with one `memcpy` of `sizeof(*dhm)`, `DH_meth_free` releases
//! `name` **before** the table, and each of the twenty-one entry points reads or writes exactly
//! one member. The numbers below are `courts/layout/measure-dh-method.c`'s, and the offsets are
//! asserted in the unit tests rather than only the size, because the two spellings of a wrong
//! order are different bugs — a swap of `init` and `finish` keeps the size and moves two calls.
//!
//! ```text
//! name              0     char *name
//! generate_key      8     int (*generate_key)(DH *)
//! compute_key      16     int (*compute_key)(unsigned char *, const BIGNUM *, DH *)
//! bn_mod_exp       24     int (*bn_mod_exp)(const DH *, BIGNUM *, const BIGNUM *, const BIGNUM *,
//!                                              const BIGNUM *, BN_CTX *, BN_MONT_CTX *)
//! init             32     int (*init)(DH *)
//! finish           40     int (*finish)(DH *)
//! flags            48     int flags
//! (padding)        52
//! app_data         56     char *app_data
//! generate_params  64     int (*generate_params)(DH *, int, int, BN_GENCB *)
//! ```
//!
//! `flags` is a four-byte `int` at 48 and `app_data` is a pointer at 56, so the four bytes at
//! 52..56 are padding and the two are **not** adjacent in the way the declaration order suggests.
//! A transcription that made `flags` pointer-sized would be eight bytes too wide and would move
//! `generate_params` to 72.
//!
//! ## The three function-pointer member pairs are `Option`s, and the two lifecycle ones are the
//! reason
//!
//! `DH_meth_new` zero-allocates the table, so every member starts NULL, and `DH_meth_get_*`
//! answers exactly what was stored. Five of the six function-pointer members are nullable by the
//! authority's own construction: `dh_ossl` (`dh_key.c:180-190`) leaves `app_data` and
//! `generate_params` NULL, and the header's own comment marks `bn_mod_exp` "Can be null". So each
//! is an `Option` and the null is expressed as `None` rather than by a fabricated address. That
//! is observable rather than cosmetic: `DH_meth_get0_app_data` and `DH_meth_get_generate_params`
//! on a fresh table must answer `None`, and `DH_meth_set0_app_data(m, NULL)` must answer 1 while
//! leaving the getter NULL.
//!
//! ## The allocation the arms observe, and the `file` they carry
//!
//! `crypto/dh/dh_meth.c` is a source-tree file, so its `OPENSSL_FILE` is
//! `../../src/openssl-3.6.4/crypto/dh/dh_meth.c` — measured the same way D280's cipher units
//! were, by reading the string out of the authority's own object file. `RT-DH` installs an
//! allocator and records the ordered `(kind, size, file)` sequence of each arm's window, which is
//! how "this unit's allocation is attributed to this unit's translation unit" becomes a diff
//! rather than a constant here. `DH_meth_new` allocates a 72-byte table and then a name;
//! `DH_meth_dup` allocates a 72-byte table, copies, and then a name; `DH_meth_free` releases the
//! name and then the table, in that order.
//!
//! The line number is `__LINE__`, which is inert under `OPENSSL_NO_CRYPTO_MDEBUG` and is passed
//! as zero, exactly as `src/rsa/mod.rs`'s `LINE` is. It is the *file* that a caller's allocator
//! observes.
//!
//! ## Scope: what is transcribed, and what is left
//!
//! Transcribed here, in authority order: [`DH_meth_new`] (`:20-35`), [`DH_meth_free`] (`:37-43`),
//! [`DH_meth_dup`] (`:45-60`), [`DH_meth_get0_name`] (`:62-65`), [`DH_meth_set1_name`]
//! (`:67-78`), [`DH_meth_get_flags`] (`:80-83`), [`DH_meth_set_flags`] (`:85-89`),
//! [`DH_meth_get0_app_data`] (`:91-94`), [`DH_meth_set0_app_data`] (`:96-100`),
//! [`DH_meth_get_generate_key`] (`:102-105`), [`DH_meth_set_generate_key`] (`:107-111`),
//! [`DH_meth_get_compute_key`] (`:113-117`), [`DH_meth_set_compute_key`] (`:118-124`),
//! [`DH_meth_get_bn_mod_exp`] (`:125-130`), [`DH_meth_set_bn_mod_exp`] (`:131-138`),
//! [`DH_meth_get_init`] (`:139-143`), [`DH_meth_set_init`] (`:144-149`),
//! [`DH_meth_get_finish`] (`:150-154`), [`DH_meth_set_finish`] (`:155-160`),
//! [`DH_meth_get_generate_params`] (`:161-165`) and [`DH_meth_set_generate_params`]
//! (`:166-171`). That is all twenty-one labels, and `DH_meth.c` defines nothing else — every
//! other definition in the file is one of these. So this unit has **no internals**, which is why
//! it adds no name the prerequisite gate has to count (the unit-module rule D327 records).
//!
//! Left for the rest of 8.5, each named rather than silently dropped:
//!
//! * **The `DH` object itself.** [`Dh`] is the forward declaration `struct dh_st;` and nothing
//!   more. `dh_lib.c`'s lifetime and accessors need `dh_new_intern`, and that constructor reads
//!   `DH_get_default_method()` whose table's `generate_key` member reaches `dh_key.c:336`'s
//!   `BN_priv_rand_ex` — so the object cannot be built without the key layer, and the key layer
//!   cannot be built without the FFC primitives. That is the dependency this commit leaves in
//!   place rather than inverts.
//! * **`DH_get_default_method` / `DH_set_default_method` / `DH_OpenSSL`.** Their one table,
//!   `dh_ossl` (`dh_key.c:180-190`), is a *reference* to `generate_key`, `ossl_dh_compute_key` and
//!   `dh_bn_mod_exp`; a table with those members set to anything but the authority's own bodies
//!   would be a fabricated value, so the three labels wait for `dh_key.c` rather than landing
//!   here with an empty table.
//! * **`crypto/ffc/`.** The seven translation units the FFC primitives live in are 8.5's own row
//!   and are not touched here.
//!
//! ## The court that drives it: `RT-DH`
//!
//! `courts/phase8/rt_dh_probe.c` **calls all twenty-one exports** and prints only return codes,
//! names, flags, the *result* of pointer comparisons and the allocator windows. No address is
//! ever printed and no function-pointer sentinel is ever called: each sentinel returns a constant
//! so that a transcription which *did* call one would be visible in the transcript rather than
//! merely wrong. `docs/PHASE-8-SUBPHASES.md`'s two anchored clauses and `docs/DECISIONS.md` D329
//! record what the court observed.

use core::ffi::{c_char, c_int, c_uchar, c_void};

use crate::bn::bignum::BigNum;
use crate::bn::ctx::{BnCtx, BnGencb};
use crate::bn::mont::MontCtx;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};

/// `DH` — `crypto/dh/dh_local.h:18-45`'s `struct dh_st`.
///
/// **This is the C forward declaration `typedef struct dh_st DH;` and nothing more.** The object's
/// shape and lifetime are the rest of 8.5's work and are not declared here, because a layout
/// written now and changed when `dh_lib.c` lands would be two shapes for one object. Every
/// signature below takes it behind a pointer and none dereferences it, which is exactly what the
/// installed header permits.
#[repr(C)]
pub struct Dh {
    /// Zero bytes: the object is opaque at this slice. The field exists so the type is
    /// `repr(C)` and non-empty at the ABI level without claiming a layout.
    _opaque: [u8; 0],
}

/// `int (*generate_key)(DH *dh)` — `crypto/dh/dh_local.h:50`.
pub type DhGenerateKeyFn = unsafe extern "C" fn(dh: *mut Dh) -> c_int;

/// `int (*compute_key)(unsigned char *key, const BIGNUM *pub_key, DH *dh)` —
/// `crypto/dh/dh_local.h:52`.
pub type DhComputeKeyFn =
    unsafe extern "C" fn(key: *mut c_uchar, pub_key: *const BigNum, dh: *mut Dh) -> c_int;

/// `int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,`
/// `const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)` — `crypto/dh/dh_local.h:56-58`.
pub type DhBnModExpFn = unsafe extern "C" fn(
    dh: *const Dh,
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
    m_ctx: *mut MontCtx,
) -> c_int;

/// `int (*init)(DH *dh)` / `int (*finish)(DH *dh)` — `crypto/dh/dh_local.h:59-60`. One type
/// because the authority spells both with the same signature.
pub type DhLifecycleFn = unsafe extern "C" fn(dh: *mut Dh) -> c_int;

/// `int (*generate_params)(DH *dh, int prime_len, int generator, BN_GENCB *cb)` —
/// `crypto/dh/dh_local.h:62-63`.
pub type DhGenerateParamsFn = unsafe extern "C" fn(
    dh: *mut Dh,
    prime_len: c_int,
    generator: c_int,
    cb: *mut BnGencb,
) -> c_int;

/// `struct dh_method` — `crypto/dh/dh_local.h:47-64`.
///
/// Measured **72** bytes with the nine members at the offsets the module documentation lists.
/// `flags` is a four-byte `int` at 48 and `app_data` is a pointer at 56, so the four bytes at
/// 52..56 are padding; a transcription that made `flags` pointer-sized would be eight bytes too
/// wide and would move `generate_params` to 72. The unit tests assert every offset.
#[repr(C)]
pub struct DhMethod {
    /// `char *name` — the string `DH_meth_get0_name` returns and `DH_meth_free` releases.
    pub name: *mut c_char,
    /// `int (*generate_key)(DH *dh)` — NULL for a hand-built table.
    pub generate_key: Option<DhGenerateKeyFn>,
    /// `int (*compute_key)(unsigned char *key, const BIGNUM *pub_key, DH *dh)`.
    pub compute_key: Option<DhComputeKeyFn>,
    /// `int (*bn_mod_exp)(...)` — the header's own comment marks it "Can be null".
    pub bn_mod_exp: Option<DhBnModExpFn>,
    /// `int (*init)(DH *dh)` — called at new.
    pub init: Option<DhLifecycleFn>,
    /// `int (*finish)(DH *dh)` — called at free.
    pub finish: Option<DhLifecycleFn>,
    /// `int flags` — `DH_FLAG_*`.
    pub flags: c_int,
    /// `char *app_data`.
    pub app_data: *mut c_void,
    /// `int (*generate_params)(...)` — NULL in the authority's own table.
    pub generate_params: Option<DhGenerateParamsFn>,
}

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/dh/dh_meth.c` is a source-tree file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — read out of the authority's own
/// `build/.../crypto/dh/libcrypto-lib-dh_meth.o`, the check D280 applied to the cipher units. It
/// reaches an application through `CRYPTO_set_mem_functions`, so it is part of the contract and
/// `RT-DH` compares it.
const FILE_DH_METH: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_meth.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `DH_METHOD *DH_meth_new(const char *name, int flags)` — `crypto/dh/dh_meth.c:20-35`.
///
/// A zero-allocated table with `flags` stored and `name` duplicated. **A failed `OPENSSL_strdup`
/// releases the whole object**, so a caller that gets NULL never holds a half-built table;
/// `flags` is stored *before* the name is duplicated, which is what makes that release safe.
///
/// # Safety
///
/// `name` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_new(name: *const c_char, flags: c_int) -> *mut DhMethod {
    // SAFETY: the caller's contract.
    unsafe {
        let dhm =
            CRYPTO_zalloc(core::mem::size_of::<DhMethod>(), FILE_DH_METH, LINE).cast::<DhMethod>();

        if !dhm.is_null() {
            (*dhm).flags = flags;
            (*dhm).name = CRYPTO_strdup(name, FILE_DH_METH, LINE);
            if !(*dhm).name.is_null() {
                return dhm;
            }
            CRYPTO_free(dhm.cast(), FILE_DH_METH, LINE);
        }
        core::ptr::null_mut()
    }
}

/// `void DH_meth_free(DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:37-43`. NULL is a no-op, and the
/// name is released **before** the table so that a caller's allocator sees them in that order.
///
/// # Safety
///
/// `dhm` is NULL or a table [`DH_meth_new`] or [`DH_meth_dup`] returned.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_free(dhm: *mut DhMethod) {
    // SAFETY: the caller's contract.
    unsafe {
        if !dhm.is_null() {
            CRYPTO_free((*dhm).name.cast(), FILE_DH_METH, LINE);
            CRYPTO_free(dhm.cast(), FILE_DH_METH, LINE);
        }
    }
}

/// `DH_METHOD *DH_meth_dup(const DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:45-60`.
///
/// **A whole-struct `memcpy` followed by one deep field.** Everything but `name` is shared with
/// the original — including `app_data`, which is why the header warns that a method's application
/// data must outlive every duplicate of it. A NULL `dhm->name` makes `OPENSSL_strdup` answer NULL
/// and therefore makes the *duplicate* fail, because this crate's `CRYPTO_strdup` mirrors the
/// authority's and refuses NULL rather than inventing an empty string.
///
/// The allocation is `OPENSSL_malloc`, not `OPENSSL_zalloc`: the `memcpy` overwrites all 72
/// bytes, so zeroing first would only be visible to an allocator as the same two requests.
///
/// # Safety
///
/// `dhm` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_dup(dhm: *const DhMethod) -> *mut DhMethod {
    // SAFETY: the caller's contract.
    unsafe {
        let ret =
            CRYPTO_malloc(core::mem::size_of::<DhMethod>(), FILE_DH_METH, LINE).cast::<DhMethod>();

        if !ret.is_null() {
            core::ptr::copy_nonoverlapping(dhm, ret, 1);
            (*ret).name = CRYPTO_strdup((*dhm).name, FILE_DH_METH, LINE);
            if !(*ret).name.is_null() {
                return ret;
            }
            CRYPTO_free(ret.cast(), FILE_DH_METH, LINE);
        }
        core::ptr::null_mut()
    }
}

/// `const char *DH_meth_get0_name(const DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:62-65`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get0_name(dhm: *const DhMethod) -> *const c_char {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).name }
}

/// `int DH_meth_set1_name(DH_METHOD *dhm, const char *name)` — `crypto/dh/dh_meth.c:67-78`.
///
/// **The duplicate happens first and the old name is released second**, so a failed `strdup`
/// leaves the table's name untouched rather than freeing it and storing NULL.
///
/// # Safety
///
/// `dhm` is a live table; `name` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set1_name(dhm: *mut DhMethod, name: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tmpname = CRYPTO_strdup(name, FILE_DH_METH, LINE);

        if tmpname.is_null() {
            return 0;
        }
        CRYPTO_free((*dhm).name.cast(), FILE_DH_METH, LINE);
        (*dhm).name = tmpname;
        1
    }
}

/// `int DH_meth_get_flags(const DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:80-83`.
///
/// # Safety
///
/// `dhm` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_flags(dhm: *const DhMethod) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).flags }
}

/// `int DH_meth_set_flags(DH_METHOD *dhm, int flags)` — `crypto/dh/dh_meth.c:85-89`. Stores the
/// word and answers 1 unconditionally.
///
/// # Safety
///
/// `dhm` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_flags(dhm: *mut DhMethod, flags: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).flags = flags;
    }
    1
}

/// `void *DH_meth_get0_app_data(const DH_METHOD *dhm)` — `crypto/dh/dh_meth.c:91-94`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get0_app_data(dhm: *const DhMethod) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).app_data }
}

/// `int DH_meth_set0_app_data(DH_METHOD *dhm, void *app_data)` — `crypto/dh/dh_meth.c:96-100`.
/// Stores the pointer and answers 1; NULL is a legal value and is what a fresh table holds.
///
/// # Safety
///
/// `dhm` is a live table.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set0_app_data(dhm: *mut DhMethod, app_data: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).app_data = app_data;
    }
    1
}

/// `int (*DH_meth_get_generate_key(const DH_METHOD *dhm))(DH *)` — `crypto/dh/dh_meth.c:102-105`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_generate_key(dhm: *const DhMethod) -> Option<DhGenerateKeyFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).generate_key }
}

/// `int DH_meth_set_generate_key(DH_METHOD *dhm, int (*generate_key)(DH *))` —
/// `crypto/dh/dh_meth.c:107-111`.
///
/// # Safety
///
/// `dhm` is a live table; `generate_key` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_generate_key(
    dhm: *mut DhMethod,
    generate_key: Option<DhGenerateKeyFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).generate_key = generate_key;
    }
    1
}

/// `int (*DH_meth_get_compute_key(const DH_METHOD *dhm))(unsigned char *, const BIGNUM *, DH *)`
/// — `crypto/dh/dh_meth.c:113-117`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_compute_key(dhm: *const DhMethod) -> Option<DhComputeKeyFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).compute_key }
}

/// `int DH_meth_set_compute_key(DH_METHOD *dhm, int (*compute_key)(unsigned char *,`
/// `const BIGNUM *, DH *))` — `crypto/dh/dh_meth.c:118-124`.
///
/// # Safety
///
/// `dhm` is a live table; `compute_key` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_compute_key(
    dhm: *mut DhMethod,
    compute_key: Option<DhComputeKeyFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).compute_key = compute_key;
    }
    1
}

/// `int (*DH_meth_get_bn_mod_exp(const DH_METHOD *dhm))(const DH *, BIGNUM *, const BIGNUM *,`
/// `const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *)` — `crypto/dh/dh_meth.c:125-130`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_bn_mod_exp(dhm: *const DhMethod) -> Option<DhBnModExpFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).bn_mod_exp }
}

/// `int DH_meth_set_bn_mod_exp(DH_METHOD *dhm, int (*bn_mod_exp)(const DH *, BIGNUM *,`
/// `const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *))` —
/// `crypto/dh/dh_meth.c:131-138`.
///
/// # Safety
///
/// `dhm` is a live table; `bn_mod_exp` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_bn_mod_exp(
    dhm: *mut DhMethod,
    bn_mod_exp: Option<DhBnModExpFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).bn_mod_exp = bn_mod_exp;
    }
    1
}

/// `int (*DH_meth_get_init(const DH_METHOD *dhm))(DH *)` — `crypto/dh/dh_meth.c:139-143`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_init(dhm: *const DhMethod) -> Option<DhLifecycleFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).init }
}

/// `int DH_meth_set_init(DH_METHOD *dhm, int (*init)(DH *))` — `crypto/dh/dh_meth.c:144-149`.
///
/// # Safety
///
/// `dhm` is a live table; `init` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_init(
    dhm: *mut DhMethod,
    init: Option<DhLifecycleFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).init = init;
    }
    1
}

/// `int (*DH_meth_get_finish(const DH_METHOD *dhm))(DH *)` — `crypto/dh/dh_meth.c:150-154`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_finish(dhm: *const DhMethod) -> Option<DhLifecycleFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).finish }
}

/// `int DH_meth_set_finish(DH_METHOD *dhm, int (*finish)(DH *))` — `crypto/dh/dh_meth.c:155-160`.
///
/// # Safety
///
/// `dhm` is a live table; `finish` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_finish(
    dhm: *mut DhMethod,
    finish: Option<DhLifecycleFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).finish = finish;
    }
    1
}

/// `int (*DH_meth_get_generate_params(const DH_METHOD *dhm))(DH *, int, int, BN_GENCB *)` —
/// `crypto/dh/dh_meth.c:161-165`.
///
/// # Safety
///
/// `dhm` is a live table. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_get_generate_params(
    dhm: *const DhMethod,
) -> Option<DhGenerateParamsFn> {
    // SAFETY: the caller's contract.
    unsafe { (*dhm).generate_params }
}

/// `int DH_meth_set_generate_params(DH_METHOD *dhm, int (*generate_params)(DH *, int, int,`
/// `BN_GENCB *))` — `crypto/dh/dh_meth.c:166-171`.
///
/// # Safety
///
/// `dhm` is a live table; `generate_params` is NULL or a function whose calls the caller permits.
#[no_mangle]
pub unsafe extern "C" fn DH_meth_set_generate_params(
    dhm: *mut DhMethod,
    generate_params: Option<DhGenerateParamsFn>,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dhm).generate_params = generate_params;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five sentinels as *function pointers*, so `Some(const)` is an `Option<fn>` and
    /// compares with `assert_eq!` (a bare fn item is a distinct type and implements no `Debug`).
    const SENT_GK: DhGenerateKeyFn = sentinel_generate_key;
    /// The compute-key sentinel.
    const SENT_CK: DhComputeKeyFn = sentinel_compute_key;
    /// The modular-exponentiation sentinel.
    const SENT_BM: DhBnModExpFn = sentinel_bn_mod_exp;
    /// The lifecycle (`init`/`finish`) sentinel.
    const SENT_LF: DhLifecycleFn = sentinel_life;
    /// The parameter-generation sentinel.
    const SENT_GP: DhGenerateParamsFn = sentinel_generate_params;

    /// **`DH_METHOD`, field for field.** 72 bytes with `name` 0, `generate_key` 8, `compute_key`
    /// 16, `bn_mod_exp` 24, `init` 32, `finish` 40, `flags` **48**, `app_data` 56 and
    /// `generate_params` 64.
    ///
    /// The offset that matters most is 56: `flags` is a four-byte `int` at 48, so the four bytes
    /// at 52..56 are padding and a transcription that gave `flags` a pointer's width would move
    /// every member after it by eight — which the size assertion catches and the offsets make
    /// legible.
    #[test]
    fn the_dh_method_is_the_authoritys_shape() {
        assert_eq!(core::mem::size_of::<DhMethod>(), 72);
        assert_eq!(core::mem::align_of::<DhMethod>(), 8);
        assert_eq!(core::mem::offset_of!(DhMethod, name), 0);
        assert_eq!(core::mem::offset_of!(DhMethod, generate_key), 8);
        assert_eq!(core::mem::offset_of!(DhMethod, compute_key), 16);
        assert_eq!(core::mem::offset_of!(DhMethod, bn_mod_exp), 24);
        assert_eq!(core::mem::offset_of!(DhMethod, init), 32);
        assert_eq!(core::mem::offset_of!(DhMethod, finish), 40);
        assert_eq!(core::mem::offset_of!(DhMethod, flags), 48);
        assert_eq!(core::mem::offset_of!(DhMethod, app_data), 56);
        assert_eq!(core::mem::offset_of!(DhMethod, generate_params), 64);
    }

    /// The lifecycle sentinels. They are stored and read back, never called, so each returns a
    /// constant that would be visible if a transcription called one.
    unsafe extern "C" fn sentinel_generate_key(_dh: *mut Dh) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_compute_key(
        _key: *mut c_uchar,
        _pub_key: *const BigNum,
        _dh: *mut Dh,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_bn_mod_exp(
        _dh: *const Dh,
        _r: *mut BigNum,
        _a: *const BigNum,
        _p: *const BigNum,
        _m: *const BigNum,
        _ctx: *mut BnCtx,
        _m_ctx: *mut MontCtx,
    ) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_life(_dh: *mut Dh) -> c_int {
        7
    }
    unsafe extern "C" fn sentinel_generate_params(
        _dh: *mut Dh,
        _prime_len: c_int,
        _generator: c_int,
        _cb: *mut BnGencb,
    ) -> c_int {
        7
    }

    /// **A fresh table is all NULLs**, which is `OPENSSL_zalloc`'s contribution and the reason
    /// every getter answers `None`/NULL before its setter runs. The name getter is not NULL
    /// because `DH_meth_new` duplicates the caller's string.
    #[test]
    fn a_fresh_method_table_is_zeroed() {
        // SAFETY: the argument is a literal NUL-terminated string.
        let m = unsafe { DH_meth_new(c"probe".as_ptr(), 0x1234) };
        assert!(!m.is_null());
        // SAFETY: `m` is a live table for the length of this test.
        unsafe {
            assert!((*m).generate_key.is_none());
            assert!((*m).compute_key.is_none());
            assert!((*m).bn_mod_exp.is_none());
            assert!((*m).init.is_none());
            assert!((*m).finish.is_none());
            assert!((*m).generate_params.is_none());
            assert!((*m).app_data.is_null());
            assert_eq!(DH_meth_get_flags(m), 0x1234);
            assert_eq!(
                core::ffi::CStr::from_ptr(DH_meth_get0_name(m)).to_str(),
                Ok("probe")
            );
            DH_meth_free(m);
        }
    }

    /// **Every setter/getter pair round-trips the sentinel and then NULL.** The `bn_mod_exp`,
    /// `init`, `finish`, `generate_key`, `compute_key` and `generate_params` members are the six
    /// function-pointer fields; each is NULL on the fresh table, answers its setter's 1, answers
    /// the sentinel, accepts NULL and is NULL again. The round trip leaves every member NULL, so
    /// one table serves all six without order dependence.
    #[test]
    fn every_member_round_trips() {
        // SAFETY: the argument is a literal NUL-terminated string; `m` is live throughout.
        let m = unsafe { DH_meth_new(c"round".as_ptr(), 0) };
        assert!(!m.is_null());
        // SAFETY: `m` is a live table for the remainder of this test, and every `Some(SENT_*)`
        // is a function the test never calls.
        unsafe {
            assert_eq!(DH_meth_set_generate_key(m, Some(SENT_GK)), 1);
            assert!(DH_meth_get_generate_key(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_GK)));
            assert_eq!(DH_meth_set_generate_key(m, None), 1);
            assert!(DH_meth_get_generate_key(m).is_none());

            assert_eq!(DH_meth_set_compute_key(m, Some(SENT_CK)), 1);
            assert!(DH_meth_get_compute_key(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_CK)));
            assert_eq!(DH_meth_set_compute_key(m, None), 1);
            assert!(DH_meth_get_compute_key(m).is_none());

            assert_eq!(DH_meth_set_bn_mod_exp(m, Some(SENT_BM)), 1);
            assert!(DH_meth_get_bn_mod_exp(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_BM)));
            assert_eq!(DH_meth_set_bn_mod_exp(m, None), 1);
            assert!(DH_meth_get_bn_mod_exp(m).is_none());

            assert_eq!(DH_meth_set_init(m, Some(SENT_LF)), 1);
            assert!(DH_meth_get_init(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_LF)));
            assert_eq!(DH_meth_set_init(m, None), 1);
            assert!(DH_meth_get_init(m).is_none());

            assert_eq!(DH_meth_set_finish(m, Some(SENT_LF)), 1);
            assert!(DH_meth_get_finish(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_LF)));
            assert_eq!(DH_meth_set_finish(m, None), 1);
            assert!(DH_meth_get_finish(m).is_none());

            assert_eq!(DH_meth_set_generate_params(m, Some(SENT_GP)), 1);
            assert!(
                DH_meth_get_generate_params(m).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_GP))
            );
            assert_eq!(DH_meth_set_generate_params(m, None), 1);
            assert!(DH_meth_get_generate_params(m).is_none());

            // `app_data` is not a function pointer and its NULL is a value, not a refusal.
            let marker = 0x1234_usize as *mut c_void;
            assert_eq!(DH_meth_set0_app_data(m, marker), 1);
            assert_eq!(DH_meth_get0_app_data(m), marker);
            assert_eq!(DH_meth_set0_app_data(m, core::ptr::null_mut()), 1);
            assert!(DH_meth_get0_app_data(m).is_null());

            assert_eq!(DH_meth_set_flags(m, 0x0f0f), 1);
            assert_eq!(DH_meth_get_flags(m), 0x0f0f);

            DH_meth_free(m);
        }
    }

    /// **`DH_meth_dup` copies every member and deep-copies the name.** The duplicate's name is a
    /// different pointer (`strdup`) holding the same bytes, and every other member is shared
    /// *by value* — including `app_data`, which is why the header says a method's application
    /// data must outlive every duplicate of it. Releasing the original leaves the duplicate
    /// valid; the duplicate is released by the getter read after the free.
    #[test]
    fn dup_copies_the_table_and_deep_copies_the_name() {
        // SAFETY: the argument is a literal NUL-terminated string; both tables are live until
        // their own frees.
        unsafe {
            let orig = DH_meth_new(c"dup-me".as_ptr(), 0x42);
            assert!(!orig.is_null());
            assert_eq!(DH_meth_set_generate_key(orig, Some(SENT_GK)), 1);
            let marker = 0x5678_usize as *mut c_void;
            assert_eq!(DH_meth_set0_app_data(orig, marker), 1);

            let copy = DH_meth_dup(orig);
            assert!(!copy.is_null());
            assert_eq!(DH_meth_get_flags(copy), 0x42);
            assert_eq!(
                core::ffi::CStr::from_ptr(DH_meth_get0_name(copy)).to_str(),
                Ok("dup-me")
            );
            assert_eq!(DH_meth_get0_app_data(copy), marker);
            assert!(
                DH_meth_get_generate_key(copy).is_some_and(|f| core::ptr::fn_addr_eq(f, SENT_GK))
            );
            // The name is a second allocation, not a shared pointer.
            assert_ne!(DH_meth_get0_name(copy), DH_meth_get0_name(orig));

            DH_meth_free(orig);
            // The duplicate survives the original's release, name and all.
            assert_eq!(
                core::ffi::CStr::from_ptr(DH_meth_get0_name(copy)).to_str(),
                Ok("dup-me")
            );
            DH_meth_free(copy);
        }
    }

    /// **`DH_meth_set1_name` duplicates first and releases second.** The observable half is that
    /// a successful set changes the name's identity, and that `DH_meth_set1_name(m, NULL)`
    /// answers 0 and leaves the old name in place — because a NULL argument makes
    /// `CRYPTO_strdup` answer NULL, which the authority treats as the failure arm.
    #[test]
    fn set1_name_is_a_duplicate_then_a_release() {
        // SAFETY: the arguments are literal NUL-terminated strings, or NULL; `m` is live.
        unsafe {
            let m = DH_meth_new(c"first".as_ptr(), 0);
            assert!(!m.is_null());
            let before = DH_meth_get0_name(m);
            assert_eq!(DH_meth_set1_name(m, c"second".as_ptr()), 1);
            let after = DH_meth_get0_name(m);
            assert_ne!(before, after);
            assert_eq!(core::ffi::CStr::from_ptr(after).to_str(), Ok("second"));
            // A NULL name refuses, and the refusal is not the free-then-store path.
            assert_eq!(DH_meth_set1_name(m, core::ptr::null()), 0);
            assert_eq!(
                core::ffi::CStr::from_ptr(DH_meth_get0_name(m)).to_str(),
                Ok("second")
            );
            DH_meth_free(m);
        }
    }

    /// **NULL is accepted where the authority accepts it.** `DH_meth_free(NULL)` is a no-op and
    /// the getters are not called on NULL (the authority dereferences unconditionally), so the
    /// only NULL-legal entry point is the free.
    #[test]
    fn free_accepts_null() {
        // SAFETY: NULL is the documented no-op argument.
        unsafe { DH_meth_free(core::ptr::null_mut()) };
    }
}
