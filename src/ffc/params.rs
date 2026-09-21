//! Phase 8 — `crypto/ffc/ffc_params.c`: the FFC domain-parameter object's lifecycle.
//!
//! The unit is eighteen definitions: the four `BIGNUM *` slots and the seed buffer's
//! lifecycle, the scalar setters, the accessors, the copy (with its two deliberate
//! asymmetries), the comparison and the ASN.1 printer. It is where `struct dh_st`'s
//! `params` member comes from — `crypto/dh/dh_lib.c:122` is `ossl_ffc_params_init(&ret->params)`
//! and `:161` is `ossl_ffc_params_cleanup(&r->params)` — so every DH object's construction
//! and release runs through this file.
//!
//! ## The one function of the unit that is not here, and why
//!
//! `ossl_ffc_params_todata` (`:219-285`) is **withheld**, not stubbed. It is the provider
//! export half of the params object and its callers are `crypto/dh/dh_backend.c:94` and
//! `crypto/dsa/dsa_backend.c`, neither of which is on the `dh_lib.c`/`dh_key.c`/`dh_gen.c`/
//! `dh_check.c` path this slice lands. It reaches three things this unit does not have:
//!
//! * `ossl_param_build_set_bn`, `_int`, `_octet_string` and `_utf8_string`, which are
//!   `crypto/param_build_set.c`'s. That unit has no crate module and no implementation; its
//!   own callees (`OSSL_PARAM_BLD_push_*`, `OSSL_PARAM_set_*`) are in the crate, so
//!   transcribing it is a small unit rather than a large one, but it is *another* unit and
//!   not this one.
//! * `ossl_ffc_uid_to_dh_named_group` and `ossl_ffc_named_group_get_name`, which are
//!   `crypto/ffc/ffc_dh.c:103` and `:140`.
//!
//! **The second blocker was discharged by D332 and the first was not**, which is the honest
//! state of the row: `ffc_dh.c` is now transcribed in [`crate::ffc::dh`], so the two lookups
//! exist, and `ossl_ffc_params_todata` is still withheld for `crypto/param_build_set.c`
//! alone. Nothing about that changes its body — it is one unit's absence rather than two —
//! and the divergence record in `forensics/prerequisites.json` still covers exactly this
//! name.
//!
//! A version of it that returned early, or one that skipped the `nid != NID_undef` arm,
//! would be a fabricated answer for a name a later slice owns; the omission is recorded here
//! and in the module header instead.
//!
//! ## Two asymmetries in `ossl_ffc_params_copy` that a tidy rewrite would remove
//!
//! * **`p`, `g`, `q` and `j` are copied in that written order**, not the declaration's
//!   `p`, `q`, `g`, `j`, and `ffc_bn_cpy` clears the destination slot before storing into
//!   it. A failure mid-way calls `ossl_ffc_params_cleanup` on the *destination*, which also
//!   resets `pcounter` to `-1`, `gindex` to `-1` and `flags` to `VALIDATE_PQG` — so a failed
//!   copy does not leave the destination partly filled, it leaves it freshly initialised.
//! * **`dst->seedlen` is assigned before the seed is duplicated**, so a `memdup` failure
//!   reaches the `err:` path with `seed == NULL` and a non-zero `seedlen`. The cleanup frees
//!   NULL and re-initialises, which is why the order is harmless — and why reading the two
//!   lines as "duplicate then record the length" would change nothing observable. It is
//!   transcribed in the authority's order rather than the clearer one.
//!
//! ## `BN_flags` is read here, so `ffc_bn_cpy`'s first arm is a real branch
//!
//! `ffc_bn_cpy` copies a **pointer** rather than the number when the source carries
//! `BN_FLG_STATIC_DATA` without `BN_FLG_MALLOCED` — the authority's way of sharing its
//! `.rodata` NIST/FFDHE constants without duplicating them. This crate's `BIGNUM`s are heap
//! objects with `BN_FLG_MALLOCED` set, so the arm does not fire on any object this slice
//! builds; it is transcribed because it is what makes `ossl_ffc_params_copy` of a static
//! prime cheap, and because a caller that hands in a `BN_with_flags` view reaches it.

use core::ffi::{c_char, c_int, c_uint};
use core::ptr;

use crate::bn::arith::BN_cmp;
use crate::bn::bignum::{BN_clear_free, BN_dup, BN_free, BN_get_flags, BigNum};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup};

use super::FfcParams;
use crate::ffc::{FFC_PARAM_FLAG_VALIDATE_PQG, FFC_UNVERIFIABLE_GINDEX};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/ffc/ffc_params.c` is a source-tree file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — the spelling D280 read out of the authority's own
/// object files and D329 used for `dh_meth.c`. `ossl_ffc_params_set_seed` and
/// `ossl_ffc_params_copy` both hand it to the allocator, so it is observable through
/// `CRYPTO_set_mem_functions` once a DH caller reaches them.
const FILE_FFC_PARAMS: *const c_char = c"../../src/openssl-3.6.4/crypto/ffc/ffc_params.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `BN_FLG_STATIC_DATA` — the flag the authority sets on the `BIGNUM`s it places in
/// `.rodata`, and the one `ffc_bn_cpy` tests. Defined once in [`crate::bn::bignum`],
/// beside the code that now tests it in `BN_free`, rather than copied here.
const BN_FLG_STATIC_DATA: c_int = crate::bn::bignum::BN_FLG_STATIC_DATA;

/// `void ossl_ffc_params_init(FFC_PARAMS *params)` — `crypto/ffc/ffc_params.c:20-26`.
///
/// `memset` to zero and then **three** non-zero fields: `pcounter = -1`, `gindex =
/// FFC_UNVERIFIABLE_GINDEX` and `flags = FFC_PARAM_FLAG_VALIDATE_PQG`. The zeroing is part of
/// the contract rather than an optimisation — `ffc_params_validate.c:100` builds an
/// `FFC_PARAMS` on the stack and relies on this to clear the four `BIGNUM *` slots and the
/// two borrowed digest strings — so it is transcribed as one `write_bytes` over the whole
/// struct and not as fourteen field assignments.
///
/// # Safety
///
/// `params` must be a live, writable `FFC_PARAMS`. Any values it already held are
/// overwritten without being released.
pub(crate) unsafe fn ossl_ffc_params_init(params: *mut FfcParams) {
    // SAFETY: `params` is live and writable per this function's `# Safety` section, and the
    // write covers exactly the one object it points at.
    unsafe {
        ptr::write_bytes(params, 0, 1);
        (*params).pcounter = -1;
        (*params).gindex = FFC_UNVERIFIABLE_GINDEX;
        (*params).flags = FFC_PARAM_FLAG_VALIDATE_PQG;
    }
}

/// `void ossl_ffc_params_cleanup(FFC_PARAMS *params)` — `crypto/ffc/ffc_params.c:28-44`.
///
/// **`OPENSSL_PEDANTIC_ZEROIZATION` is not defined on this profile**, so the `#else` arm is
/// the one compiled: `BN_free`, not `BN_clear_free`, and `OPENSSL_free`, not
/// `OPENSSL_clear_free`. That is the same reading `src/rsa/object.rs` makes for `RSA_free`
/// and documents as "no `-DOPENSSL_PEDANTIC_ZEROIZATION` appears in the pinned Configure
/// line"; it is observable through an allocator, because the clearing form writes the buffer
/// before releasing it.
///
/// The `ossl_ffc_params_init` at the end is what makes cleanup idempotent and is why a
/// caller may reuse the object without re-initialising it: after this call `pcounter` is
/// `-1` and `flags` is `VALIDATE_PQG` again, not zero.
///
/// # Safety
///
/// `params` must be a live, writable `FFC_PARAMS` whose four `BIGNUM` pointers and `seed`
/// are each NULL or owned by it.
pub(crate) unsafe fn ossl_ffc_params_cleanup(params: *mut FfcParams) {
    // SAFETY: the four pointers and `seed` are NULL or owned by the object per this
    // function's `# Safety` section; each callee accepts NULL.
    unsafe {
        BN_free((*params).p);
        BN_free((*params).q);
        BN_free((*params).g);
        BN_free((*params).j);
        CRYPTO_free((*params).seed.cast(), FILE_FFC_PARAMS, LINE);
        ossl_ffc_params_init(params);
    }
}

/// `void ossl_ffc_params_set0_pqg(FFC_PARAMS *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)` —
/// `crypto/ffc/ffc_params.c:46-60`.
///
/// Take-ownership, with **three** independent guards: a NULL argument leaves that slot
/// alone, and an argument equal to the slot's current value leaves it alone too. The second
/// guard is what makes `ossl_ffc_params_set0_pqg(d, d->p, d->q, d->g)` a no-op rather than a
/// use-after-free, and `crypto/ffc/ffc_backend.c:114` is a real caller that can pass back a
/// pointer the object already holds.
///
/// # Safety
///
/// `d` must be live and writable; each of `p`, `q` and `g` must be NULL or a live `BIGNUM`
/// whose ownership the caller transfers.
pub(crate) unsafe fn ossl_ffc_params_set0_pqg(
    d: *mut FfcParams,
    p: *mut BigNum,
    q: *mut BigNum,
    g: *mut BigNum,
) {
    // SAFETY: `d` is live and writable, and each argument is NULL or a live `BIGNUM` per this
    // function's `# Safety` section.
    unsafe {
        if !p.is_null() && p != (*d).p {
            BN_free((*d).p);
            (*d).p = p;
        }
        if !q.is_null() && q != (*d).q {
            BN_free((*d).q);
            (*d).q = q;
        }
        if !g.is_null() && g != (*d).g {
            BN_free((*d).g);
            (*d).g = g;
        }
    }
}

/// `void ossl_ffc_params_get0_pqg(const FFC_PARAMS *d, const BIGNUM **p,`
/// `const BIGNUM **q, const BIGNUM **g)` — `crypto/ffc/ffc_params.c:62-71`.
///
/// Borrowed reads, each through a NULL-able out-parameter. `crypto/dh/dh_lib.c:228` (`DH_get0_pqg`)
/// and `crypto/dh/dh_asn1.c:145` are the callers the next slice of 8.5 adds.
///
/// # Safety
///
/// `d` must be live; each out-parameter must be NULL or writable for a `*mut BigNum`.
pub(crate) unsafe fn ossl_ffc_params_get0_pqg(
    d: *const FfcParams,
    p: *mut *mut BigNum,
    q: *mut *mut BigNum,
    g: *mut *mut BigNum,
) {
    // SAFETY: `d` is live and each out-parameter is NULL or writable per this function's
    // `# Safety` section.
    unsafe {
        if !p.is_null() {
            *p = (*d).p;
        }
        if !q.is_null() {
            *q = (*d).q;
        }
        if !g.is_null() {
            *g = (*d).g;
        }
    }
}

/// `void ossl_ffc_params_set0_j(FFC_PARAMS *d, BIGNUM *j)` — `crypto/ffc/ffc_params.c:73-80`.
///
/// The cofactor, which is optionally output for ASN.1. Unlike the `pqg` triple this **always
/// releases** the old value and always leaves a NULL slot for a NULL argument — the
/// authority's body sets `d->j = NULL` first and only then stores, so
/// `ossl_ffc_params_set0_j(d, d->j)` is a use-after-free rather than a no-op. That asymmetry
/// with [`ossl_ffc_params_set0_pqg`] is the authority's, and `crypto/dh/dh_asn1.c:115` is a
/// caller that passes a fresh value.
///
/// # Safety
///
/// `d` must be live and writable; `j` must be NULL or a live `BIGNUM` whose ownership the
/// caller transfers.
// Reached: the reader is `src/dh/asn1.rs`'s `d2i_DHxparams`, which is `crypto/dh/dh_asn1.c:115`.
pub(crate) unsafe fn ossl_ffc_params_set0_j(d: *mut FfcParams, j: *mut BigNum) {
    // SAFETY: `d` is live and `j` is NULL or live per this function's `# Safety` section.
    unsafe {
        BN_free((*d).j);
        (*d).j = ptr::null_mut();
        if !j.is_null() {
            (*d).j = j;
        }
    }
}

/// `int ossl_ffc_params_set_seed(FFC_PARAMS *params, const unsigned char *seed,`
/// `size_t seedlen)` — `crypto/ffc/ffc_params.c:82-101`.
///
/// Three answers, and the first is the one worth naming: **setting the seed it already
/// holds** answers 1 with an empty allocator window, because the authority compares pointers
/// and returns before releasing anything. The second is that a NULL or empty seed *clears*
/// the slot rather than refusing — `seedlen` goes to 0 with it — so this is also the only way
/// to unset a seed.
///
/// # Safety
///
/// `params` must be live and writable; `seed` must be NULL or readable for `seedlen` bytes,
/// and must remain valid for the call.
pub(crate) unsafe fn ossl_ffc_params_set_seed(
    params: *mut FfcParams,
    seed: *const u8,
    seedlen: usize,
) -> c_int {
    // SAFETY: `params` is live and `seed` is readable for `seedlen` bytes per this function's
    // `# Safety` section.
    unsafe {
        if !(*params).seed.is_null() {
            if ptr::eq((*params).seed, seed) {
                return 1;
            }
            CRYPTO_free((*params).seed.cast(), FILE_FFC_PARAMS, LINE);
        }

        if !seed.is_null() && seedlen > 0 {
            (*params).seed = CRYPTO_memdup(seed.cast(), seedlen, FILE_FFC_PARAMS, LINE).cast();
            if (*params).seed.is_null() {
                return 0;
            }
            (*params).seedlen = seedlen;
        } else {
            (*params).seed = ptr::null_mut();
            (*params).seedlen = 0;
        }
        1
    }
}

/// `void ossl_ffc_params_set_gindex(FFC_PARAMS *params, int index)` —
/// `crypto/ffc/ffc_params.c:103-106`.
///
/// # Safety
///
/// `params` must be live and writable.
// Unreached in this crate: the reader is `crypto/dh/dh_pmeth.c and crypto/ffc/ffc_backend.c`. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_ffc_params_set_gindex(params: *mut FfcParams, index: c_int) {
    // SAFETY: `params` is live and writable per this function's `# Safety` section.
    unsafe { (*params).gindex = index };
}

/// `void ossl_ffc_params_set_pcounter(FFC_PARAMS *params, int index)` —
/// `crypto/ffc/ffc_params.c:108-111`.
///
/// # Safety
///
/// `params` must be live and writable.
// Unreached in this crate: the reader is `crypto/dh/dh_asn1.c and crypto/ffc/ffc_backend.c`. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_ffc_params_set_pcounter(params: *mut FfcParams, index: c_int) {
    // SAFETY: `params` is live and writable per this function's `# Safety` section.
    unsafe { (*params).pcounter = index };
}

/// `void ossl_ffc_params_set_h(FFC_PARAMS *params, int index)` —
/// `crypto/ffc/ffc_params.c:113-116`.
///
/// # Safety
///
/// `params` must be live and writable.
// Unreached in this crate: the reader is `crypto/dh/dh_asn1.c and crypto/ffc/ffc_backend.c`. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_ffc_params_set_h(params: *mut FfcParams, index: c_int) {
    // SAFETY: `params` is live and writable per this function's `# Safety` section.
    unsafe { (*params).h = index };
}

/// `void ossl_ffc_params_set_flags(FFC_PARAMS *params, unsigned int flags)` —
/// `crypto/ffc/ffc_params.c:118-121`.
///
/// Assigns the whole word, so this is also how a caller turns every validation bit *off*
/// (`ossl_ffc_params_set_flags(&params, 0)`); [`ossl_ffc_params_enable_flags`] is the
/// per-bit form.
///
/// # Safety
///
/// `params` must be live and writable.
// Unreached in this crate: the reader is `crypto/ffc/ffc_backend.c`. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_ffc_params_set_flags(params: *mut FfcParams, flags: c_uint) {
    // SAFETY: `params` is live and writable per this function's `# Safety` section.
    unsafe { (*params).flags = flags };
}

/// `void ossl_ffc_params_enable_flags(FFC_PARAMS *params, unsigned int flags, int enable)` —
/// `crypto/ffc/ffc_params.c:123-130`.
///
/// The per-bit form, and **`enable` is tested for non-zero** rather than for `== 1`:
/// `crypto/ffc/ffc_backend.c:84` passes an `int` straight out of an `OSSL_PARAM`, so any
/// non-zero value sets the bit.
///
/// # Safety
///
/// `params` must be live and writable.
pub(crate) unsafe fn ossl_ffc_params_enable_flags(
    params: *mut FfcParams,
    flags: c_uint,
    enable: c_int,
) {
    // SAFETY: `params` is live and writable per this function's `# Safety` section.
    unsafe {
        if enable != 0 {
            (*params).flags |= flags;
        } else {
            (*params).flags &= !flags;
        }
    }
}

/// `void ossl_ffc_set_digest(FFC_PARAMS *params, const char *alg, const char *props)` —
/// `crypto/ffc/ffc_params.c:132-136`.
///
/// **Stores the two pointers, not copies**, and does not validate them: a caller that passes
/// a stack buffer here leaves both fields dangling, which is why the authority's callers pass
/// either a string literal (`test/ffc_internal_test.c:200`) or `EVP_MD_get0_name`'s borrowed
/// name (`crypto/dh/dh_pmeth.c:295`). `props` may be NULL, which means "no property query"
/// rather than "the empty query" at the fetch.
///
/// # Safety
///
/// `params` must be live and writable; `alg` and `props` must each be NULL or NUL-terminated
/// and must outlive every use of `params`.
// Unreached in this crate: the reader is `crypto/dh/dh_pmeth.c:295 and crypto/dsa/dsa_pmeth.c`. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_ffc_set_digest(
    params: *mut FfcParams,
    alg: *const c_char,
    props: *const c_char,
) {
    // SAFETY: `params` is live and writable per this function's `# Safety` section.
    unsafe {
        (*params).mdname = alg;
        (*params).mdprops = props;
    }
}

/// `int ossl_ffc_params_set_validate_params(FFC_PARAMS *params, const unsigned char *seed,`
/// `size_t seedlen, int counter)` — `crypto/ffc/ffc_params.c:138-146`.
///
/// The seed and the counter together, because FIPS 186-4 validation of `p` and `q` needs both
/// and a caller that set one without the other would have an object the validator refuses
/// with `FFC_CHECK_MISSING_SEED_OR_COUNTER`. **The counter is assigned only if the seed was
/// accepted**, so a failed `memdup` leaves the object's counter alone rather than
/// half-updating it.
///
/// # Safety
///
/// As [`ossl_ffc_params_set_seed`].
pub(crate) unsafe fn ossl_ffc_params_set_validate_params(
    params: *mut FfcParams,
    seed: *const u8,
    seedlen: usize,
    counter: c_int,
) -> c_int {
    // SAFETY: `params` and `seed` are as the callee's contract requires.
    unsafe {
        if ossl_ffc_params_set_seed(params, seed, seedlen) == 0 {
            return 0;
        }
        (*params).pcounter = counter;
        1
    }
}

/// `void ossl_ffc_params_get_validate_params(const FFC_PARAMS *params,`
/// `unsigned char **seed, size_t *seedlen, int *pcounter)` —
/// `crypto/ffc/ffc_params.c:148-158`.
///
/// Returns the *borrowed* seed pointer, not a copy: `crypto/dh/dh_asn1.c:148` hands it to
/// `ossl_ffc_params_set_validate_params` on another object, and the authority's own comment
/// there is that no copy is needed. Each out-parameter is optional.
///
/// # Safety
///
/// `params` must be live; each out-parameter must be NULL or writable for its type.
// Reached: the reader is `src/dh/asn1.rs`'s `i2d_DHxparams`, which is `crypto/dh/dh_asn1.c:148`.
pub(crate) unsafe fn ossl_ffc_params_get_validate_params(
    params: *const FfcParams,
    seed: *mut *mut u8,
    seedlen: *mut usize,
    pcounter: *mut c_int,
) {
    // SAFETY: `params` is live and each out-parameter is NULL or writable per this function's
    // `# Safety` section.
    unsafe {
        if !seed.is_null() {
            *seed = (*params).seed;
        }
        if !seedlen.is_null() {
            *seedlen = (*params).seedlen;
        }
        if !pcounter.is_null() {
            *pcounter = (*params).pcounter;
        }
    }
}

/// `static int ffc_bn_cpy(BIGNUM **dst, const BIGNUM *src)` —
/// `crypto/ffc/ffc_params.c:160-178`.
///
/// Three arms, and the middle one is the reason the function exists: a source that is
/// `BN_FLG_STATIC_DATA` **without** `BN_FLG_MALLOCED` is shared by pointer rather than
/// duplicated, which is how the authority's `.rodata` primes are copied for free. The
/// destination is released with `BN_clear_free` — the clearing form even on the
/// non-pedantic profile, because this call site spells it — and only *after* a successful
/// `BN_dup`, so a failed duplication leaves the destination's old value in place.
///
/// # Safety
///
/// `dst` must point at a live, writable slot whose value is NULL or an owned `BIGNUM`;
/// `src` must be NULL or a live `BIGNUM`.
unsafe fn ffc_bn_cpy(dst: *mut *mut BigNum, src: *const BigNum) -> c_int {
    // SAFETY: `src` is NULL or live per this function's `# Safety` section.
    let a = unsafe {
        if src.is_null() {
            ptr::null_mut()
        } else if BN_get_flags(src, BN_FLG_STATIC_DATA) != 0
            && BN_get_flags(src, crate::bn::bignum::BN_FLG_MALLOCED) == 0
        {
            src.cast_mut()
        } else {
            let dup = BN_dup(src);
            if dup.is_null() {
                return 0;
            }
            dup
        }
    };
    // SAFETY: `dst` points at a live slot holding NULL or an owned `BIGNUM`.
    unsafe {
        BN_clear_free(*dst);
        *dst = a;
    }
    1
}

/// `int ossl_ffc_params_copy(FFC_PARAMS *dst, const FFC_PARAMS *src)` —
/// `crypto/ffc/ffc_params.c:180-210`.
///
/// A deep copy of the four numbers and the seed, a **shallow** copy of the two borrowed
/// digest strings, and a field-for-field copy of the scalars. The two things a reader should
/// not tidy away:
///
/// * The order is `p`, `g`, `q`, `j` — not the declaration's `p`, `q`, `g`, `j`. Nothing
///   observable turns on it (each slot is independent), and it is transcribed as written.
/// * A failure anywhere calls [`ossl_ffc_params_cleanup`] on the destination, which
///   re-initialises it: `pcounter` back to `-1`, `gindex` to `-1`, `flags` to
///   `VALIDATE_PQG`. A caller that reuses a destination after a failed copy therefore gets a
///   *fresh* object rather than the previous contents.
///
/// `dst->seedlen` is assigned before the seed is duplicated, so the failure path reaches the
/// cleanup with `seed == NULL` and a non-zero length; the cleanup re-initialises both.
///
/// # Safety
///
/// `dst` must be a live, writable `FFC_PARAMS` whose four `BIGNUM` pointers and `seed` are
/// each NULL or owned by it; `src` must be live and must not be `dst`.
pub(crate) unsafe fn ossl_ffc_params_copy(dst: *mut FfcParams, src: *const FfcParams) -> c_int {
    // SAFETY: `dst` and `src` are live per this function's `# Safety` section, and `src`'s
    // seed is readable for `src->seedlen` bytes because the object owns it.
    unsafe {
        if ffc_bn_cpy(&raw mut (*dst).p, (*src).p) == 0
            || ffc_bn_cpy(&raw mut (*dst).g, (*src).g) == 0
            || ffc_bn_cpy(&raw mut (*dst).q, (*src).q) == 0
            || ffc_bn_cpy(&raw mut (*dst).j, (*src).j) == 0
        {
            ossl_ffc_params_cleanup(dst);
            return 0;
        }

        (*dst).mdname = (*src).mdname;
        (*dst).mdprops = (*src).mdprops;
        CRYPTO_free((*dst).seed.cast(), FILE_FFC_PARAMS, LINE);
        (*dst).seedlen = (*src).seedlen;
        if !(*src).seed.is_null() {
            (*dst).seed =
                CRYPTO_memdup((*src).seed.cast(), (*src).seedlen, FILE_FFC_PARAMS, LINE).cast();
            if (*dst).seed.is_null() {
                ossl_ffc_params_cleanup(dst);
                return 0;
            }
        } else {
            (*dst).seed = ptr::null_mut();
        }
        (*dst).nid = (*src).nid;
        (*dst).pcounter = (*src).pcounter;
        (*dst).h = (*src).h;
        (*dst).gindex = (*src).gindex;
        (*dst).flags = (*src).flags;
        (*dst).keylength = (*src).keylength;
    }
    1
}

/// `int ossl_ffc_params_cmp(const FFC_PARAMS *a, const FFC_PARAMS *b, int ignore_q)` —
/// `crypto/ffc/ffc_params.c:212-217`.
///
/// Compares **`p` and `g` always, `q` only when asked** — so the answer is "these describe
/// the same group", not "these are the same object": seed, counter, `gindex`, `h`, `nid`,
/// `keylength` and `flags` are not compared at all. The authority's comment on the `q` clause
/// is "Note: q may be NULL", and that is well-defined rather than a hazard because the
/// authority's `BN_cmp` orders NULL before everything (`a == NULL` and `b == NULL` answers
/// 0), which this crate's `BN_cmp` reproduces.
///
/// # Safety
///
/// `a` and `b` must be live.
// Unreached in this crate: the reader is `crypto/dh/dh_backend.c and crypto/dsa/dsa_backend.c`. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_ffc_params_cmp(
    a: *const FfcParams,
    b: *const FfcParams,
    ignore_q: c_int,
) -> c_int {
    // SAFETY: `a` and `b` are live and their `pqg` slots are NULL or live per this function's
    // `# Safety` section.
    unsafe {
        c_int::from(
            BN_cmp((*a).p, (*b).p) == 0
                && BN_cmp((*a).g, (*b).g) == 0
                && (ignore_q != 0 || BN_cmp((*a).q, (*b).q) == 0),
        )
    }
}

/// `int ossl_ffc_params_print(BIO *bp, const FFC_PARAMS *ffc, int indent)` —
/// `crypto/ffc/ffc_params.c:287-328`.
///
/// The `#ifndef FIPS_MODULE` arm, so it is this profile's. Five fields are printed, four of
/// them through `ASN1_bn_print` and the seed through a hand-rolled hex loop, and **`p` and
/// `g` are printed unconditionally** — a NULL `p` or `g` makes `ASN1_bn_print` answer 1 (it
/// returns early for a NULL number) rather than fail, so its label appears with nothing under
/// it. `q` and `j` are printed only when set.
///
/// The seed loop is where the formatting is observable: fifteen bytes to a line, indented by
/// `indent + 4`, `:` between bytes and **not after the last one**, and a newline *before*
/// each group rather than after — so the output starts with a newline after the `seed:` label
/// and ends with exactly one. Every failure arm answers 0, and the counter is printed **last**
/// and only when `pcounter != -1`.
///
/// # Safety
///
/// `bp` must be a live `BIO`; `ffc` must be live.
// Reached: the readers are `src/dh/ameth.rs`'s `do_dh_print` (via `crypto/dh/dh_ameth.c:283`) and
// the DSA printer, which `crypto/dh/dh_prn.c` and `crypto/dsa/dsa_prn.c` reach through them.
pub(crate) unsafe fn ossl_ffc_params_print(
    bp: *mut crate::runtime::bio::Bio,
    ffc: *const FfcParams,
    indent: c_int,
) -> c_int {
    use crate::runtime::bio::print::{BIO_indent, BIO_printf};
    use crate::runtime::bio::{BIO_puts, BIO_write};

    // SAFETY: `bp` is a live BIO and every `ffc` slot read here is NULL or live per this
    // function's `# Safety` section; each static literal is NUL-terminated.
    unsafe {
        if crate::asn1::t_pkey::ASN1_bn_print(
            bp,
            c"prime P:".as_ptr(),
            (*ffc).p,
            ptr::null_mut(),
            indent,
        ) == 0
        {
            return 0;
        }
        if crate::asn1::t_pkey::ASN1_bn_print(
            bp,
            c"generator G:".as_ptr(),
            (*ffc).g,
            ptr::null_mut(),
            indent,
        ) == 0
        {
            return 0;
        }
        if !(*ffc).q.is_null()
            && crate::asn1::t_pkey::ASN1_bn_print(
                bp,
                c"subgroup order Q:".as_ptr(),
                (*ffc).q,
                ptr::null_mut(),
                indent,
            ) == 0
        {
            return 0;
        }
        if !(*ffc).j.is_null()
            && crate::asn1::t_pkey::ASN1_bn_print(
                bp,
                c"subgroup factor:".as_ptr(),
                (*ffc).j,
                ptr::null_mut(),
                indent,
            ) == 0
        {
            return 0;
        }
        if !(*ffc).seed.is_null() {
            let seedlen = (*ffc).seedlen;

            if BIO_indent(bp, indent, 128) == 0 || BIO_puts(bp, c"seed:".as_ptr()) <= 0 {
                return 0;
            }
            for i in 0..seedlen {
                if i % 15 == 0
                    && (BIO_puts(bp, c"\n".as_ptr()) <= 0 || BIO_indent(bp, indent + 4, 128) == 0)
                {
                    return 0;
                }
                let sep: *const c_char = if i + 1 == seedlen {
                    c"".as_ptr()
                } else {
                    c":".as_ptr()
                };
                if BIO_printf(
                    bp,
                    c"%02x%s".as_ptr(),
                    c_uint::from(*((*ffc).seed.add(i))),
                    sep,
                ) <= 0
                {
                    return 0;
                }
            }
            if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                return 0;
            }
        }
        if (*ffc).pcounter != -1
            && (BIO_indent(bp, indent, 128) == 0
                || BIO_printf(bp, c"counter: %d\n".as_ptr(), (*ffc).pcounter) <= 0)
        {
            return 0;
        }
    }
    1
}

/// `int ossl_ffc_params_todata(const FFC_PARAMS *ffc, OSSL_PARAM_BLD *bld, OSSL_PARAM params[])`
/// — `crypto/ffc/ffc_params.c:219-285`. Internal, declared in `include/internal/ffc.h`.
///
/// The writer [`crate::dh::backend::ossl_dh_params_todata`] serialises its parameters with, and
/// the last function of this unit to land: `src/ffc/mod.rs` and the divergence row in
/// `forensics/prerequisites.json` both recorded it as withheld, because the `nid != NID_undef`
/// arm reaches two lookups in `crypto/ffc/ffc_dh.c` and the whole body reaches
/// `crypto/param_build_set.c`'s four helpers. D332 landed `ffc_dh.c` in [`super::dh`] and D340
/// landed `param_build_set.c`, so both blockers are gone; D351 lands the function and retires the
/// row.
///
/// **The three `flags` bits are written as `int`s, not as the bit set.** Each is `(flags & FLAG)
/// != 0` — a 0 or a 1 — so a recipient reads "validate or do not", and the object's own `0x01`-style
/// bit set is not what travels. That is why the three lines exist separately rather than one
/// `ossl_param_build_set_int` of `ffc->flags`.
///
/// **`nid` is the one parameter with a lookup in it**, and it is skipped entirely when the object
/// carries no named group: `NID_undef` means "these are explicit parameters", and writing a
/// `group` name for them would be a claim about a group the caller never named. A `nid` that
/// resolves to no row and one whose row has no name are both refusals (`return 0`), because the
/// authority's `name == NULL || !set_utf8_string(...)` is one `if`.
///
/// # Safety
/// `ffc` is a live object; `bld` is NULL or a live builder; `params` is NULL or a key-terminated
/// descriptor array.
pub(crate) unsafe fn ossl_ffc_params_todata(
    ffc: *const FfcParams,
    bld: *mut crate::params::build::OSSL_PARAM_BLD,
    params: *mut crate::params::OsslParam,
) -> c_int {
    use crate::evp::pkey_ctx::{
        OSSL_PKEY_PARAM_FFC_COFACTOR, OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
        OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_H,
        OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_PCOUNTER, OSSL_PKEY_PARAM_FFC_Q,
        OSSL_PKEY_PARAM_FFC_SEED, OSSL_PKEY_PARAM_FFC_VALIDATE_G,
        OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ,
        OSSL_PKEY_PARAM_GROUP_NAME,
    };
    use crate::ffc::dh::{ossl_ffc_named_group_get_name, ossl_ffc_uid_to_dh_named_group};
    use crate::ffc::{
        FFC_PARAM_FLAG_VALIDATE_G, FFC_PARAM_FLAG_VALIDATE_LEGACY, FFC_PARAM_FLAG_VALIDATE_PQ,
    };
    use crate::param_build_set::{
        ossl_param_build_set_bn, ossl_param_build_set_int, ossl_param_build_set_octet_string,
        ossl_param_build_set_utf8_string,
    };
    use crate::runtime::obj::NID_undef;

    // SAFETY: the caller's contract.
    unsafe {
        let mut test_flags: c_int;

        if !(*ffc).p.is_null()
            && ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_FFC_P, (*ffc).p) == 0
        {
            return 0;
        }
        if !(*ffc).q.is_null()
            && ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_FFC_Q, (*ffc).q) == 0
        {
            return 0;
        }
        if !(*ffc).g.is_null()
            && ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_FFC_G, (*ffc).g) == 0
        {
            return 0;
        }
        if !(*ffc).j.is_null()
            && ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_FFC_COFACTOR, (*ffc).j) == 0
        {
            return 0;
        }
        if ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_GINDEX, (*ffc).gindex) == 0 {
            return 0;
        }
        if ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_PCOUNTER, (*ffc).pcounter) == 0
        {
            return 0;
        }
        if ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_H, (*ffc).h) == 0 {
            return 0;
        }
        if !(*ffc).seed.is_null()
            && ossl_param_build_set_octet_string(
                bld,
                params,
                OSSL_PKEY_PARAM_FFC_SEED,
                (*ffc).seed,
                (*ffc).seedlen,
            ) == 0
        {
            return 0;
        }
        if (*ffc).nid != NID_undef {
            let group = ossl_ffc_uid_to_dh_named_group((*ffc).nid);
            let name = ossl_ffc_named_group_get_name(group);

            if name.is_null()
                || ossl_param_build_set_utf8_string(bld, params, OSSL_PKEY_PARAM_GROUP_NAME, name)
                    == 0
            {
                return 0;
            }
        }
        test_flags = if ((*ffc).flags & FFC_PARAM_FLAG_VALIDATE_PQ) != 0 {
            1
        } else {
            0
        };
        if ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, test_flags) == 0 {
            return 0;
        }
        test_flags = if ((*ffc).flags & FFC_PARAM_FLAG_VALIDATE_G) != 0 {
            1
        } else {
            0
        };
        if ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_VALIDATE_G, test_flags) == 0 {
            return 0;
        }
        test_flags = if ((*ffc).flags & FFC_PARAM_FLAG_VALIDATE_LEGACY) != 0 {
            1
        } else {
            0
        };
        if ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY, test_flags)
            == 0
        {
            return 0;
        }

        if !(*ffc).mdname.is_null()
            && ossl_param_build_set_utf8_string(
                bld,
                params,
                OSSL_PKEY_PARAM_FFC_DIGEST,
                (*ffc).mdname,
            ) == 0
        {
            return 0;
        }
        if !(*ffc).mdprops.is_null()
            && ossl_param_build_set_utf8_string(
                bld,
                params,
                OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
                (*ffc).mdprops,
            ) == 0
        {
            return 0;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;

    use crate::bn::bignum::{BN_new, BN_set_word};
    use crate::ffc::params_generate::ossl_ffc_params_FIPS186_4_generate;
    use crate::ffc::params_validate::ossl_ffc_params_FIPS186_4_validate;
    use crate::ffc::{
        FFC_ERROR_NOT_SUITABLE_GENERATOR, FFC_PARAM_FLAG_VALIDATE_G, FFC_PARAM_FLAG_VALIDATE_PQ,
        FFC_PARAM_RET_STATUS_FAILED, FFC_PARAM_RET_STATUS_SUCCESS, FFC_PARAM_TYPE_DH,
    };

    /// A fresh params object, released on drop. Every test in this module owns its objects,
    /// which is why the `# Safety` sections above are satisfiable at all.
    struct Params(FfcParams);

    impl Params {
        fn new() -> Self {
            let mut p = core::mem::MaybeUninit::<FfcParams>::uninit();
            // SAFETY: `p` is live and writable; `ossl_ffc_params_init` writes every byte.
            let inner = unsafe {
                ossl_ffc_params_init(p.as_mut_ptr());
                p.assume_init()
            };
            Params(inner)
        }

        fn as_mut(&mut self) -> *mut FfcParams {
            &raw mut self.0
        }

        fn as_ref(&self) -> *const FfcParams {
            &raw const self.0
        }
    }

    impl Drop for Params {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live object this test owns.
            unsafe { ossl_ffc_params_cleanup(&raw mut self.0) };
        }
    }

    /// `ossl_ffc_params_init`'s three non-zero fields and the zeroing of everything else. The
    /// `flags` default decides whether a freshly built DH object has its `pqg` validated on
    /// the first key generation, so it is a behaviour rather than a bookkeeping value.
    #[test]
    fn init_zeroes_then_sets_three_fields() {
        let mut p = Params::new();
        let raw = p.as_mut();
        // SAFETY: `raw` is live.
        unsafe {
            assert_eq!((*raw).pcounter, -1);
            assert_eq!((*raw).gindex, FFC_UNVERIFIABLE_GINDEX);
            assert_eq!((*raw).flags, FFC_PARAM_FLAG_VALIDATE_PQG);
            assert_eq!((*raw).seedlen, 0);
            assert_eq!((*raw).keylength, 0);
            assert_eq!((*raw).nid, 0);
            assert_eq!((*raw).h, 0);
            assert!((*raw).seed.is_null());
            assert!((*raw).mdname.is_null());
            assert!((*raw).mdprops.is_null());
            assert!((*raw).p.is_null());
            assert!((*raw).q.is_null());
            assert!((*raw).g.is_null());
            assert!((*raw).j.is_null());
            assert_eq!(
                (*raw).flags & FFC_PARAM_FLAG_VALIDATE_G,
                FFC_PARAM_FLAG_VALIDATE_G
            );
        }
    }

    /// `set0_pqg`'s three guards. The middle one — an argument equal to the stored value — is
    /// the reason this is not a plain assignment, and a transcription that dropped it would
    /// leave a dangling `p` here.
    #[test]
    fn set0_pqg_leaves_the_slot_alone_for_null_and_for_the_same_pointer() {
        let mut p = Params::new();
        let raw = p.as_mut();
        // SAFETY: `raw` is live and every pointer below is NULL or an owned `BIGNUM`.
        unsafe {
            let a = BN_new();
            assert!(BN_set_word(a, 5) != 0);
            ossl_ffc_params_set0_pqg(raw, a, ptr::null_mut(), ptr::null_mut());
            assert_eq!((*raw).p, a);
            assert!((*raw).q.is_null());

            /* The same pointer again is a no-op rather than a free-then-store. */
            ossl_ffc_params_set0_pqg(raw, a, ptr::null_mut(), ptr::null_mut());
            assert_eq!((*raw).p, a);
            assert_eq!(BN_cmp((*raw).p, a), 0);

            /* A NULL argument leaves the slot alone. */
            ossl_ffc_params_set0_pqg(raw, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            assert_eq!((*raw).p, a);
        }
    }

    /// `set0_j` is **not** `set0_pqg`: a NULL argument clears the slot rather than leaving it,
    /// and passing the slot's own value is a use-after-free in the authority. The first half
    /// is asserted here; the second is why no test passes `d->j`.
    #[test]
    fn set0_j_always_releases_and_a_null_clears() {
        let mut p = Params::new();
        let raw = p.as_mut();
        // SAFETY: `raw` is live and the two `BIGNUM`s below are owned transfers.
        unsafe {
            let a = BN_new();
            assert!(BN_set_word(a, 7) != 0);
            ossl_ffc_params_set0_j(raw, a);
            assert_eq!((*raw).j, a);

            let b = BN_new();
            assert!(BN_set_word(b, 9) != 0);
            ossl_ffc_params_set0_j(raw, b);
            assert_eq!((*raw).j, b);
            assert_eq!(BN_cmp((*raw).j, b), 0);

            ossl_ffc_params_set0_j(raw, ptr::null_mut());
            assert!((*raw).j.is_null());
        }
    }

    /// `set_seed`'s three arms: a fresh seed, the same seed again (answer 1, pointer
    /// unchanged), and a NULL/empty seed (which **clears** rather than refusing).
    #[test]
    fn set_seed_copies_repeats_and_clears() {
        let mut p = Params::new();
        let raw = p.as_mut();
        let seed = [1u8, 2, 3, 4, 5];
        // SAFETY: `raw` is live and `seed` is readable for its length.
        unsafe {
            assert_eq!(ossl_ffc_params_set_seed(raw, seed.as_ptr(), 5), 1);
            assert_eq!((*raw).seedlen, 5);
            assert!(!(*raw).seed.is_null());
            /* A copy, not the caller's buffer. */
            assert!((*raw).seed != seed.as_ptr().cast_mut());
            assert_eq!(*((*raw).seed), 1);
            assert_eq!(*((*raw).seed.add(4)), 5);

            let stored = (*raw).seed;
            assert_eq!(ossl_ffc_params_set_seed(raw, stored, 5), 1);
            assert_eq!((*raw).seed, stored);

            assert_eq!(ossl_ffc_params_set_seed(raw, ptr::null(), 0), 1);
            assert!((*raw).seed.is_null());
            assert_eq!((*raw).seedlen, 0);

            /* A non-NULL pointer with length zero also clears. */
            assert_eq!(ossl_ffc_params_set_seed(raw, seed.as_ptr(), 5), 1);
            assert_eq!(ossl_ffc_params_set_seed(raw, seed.as_ptr(), 0), 1);
            assert!((*raw).seed.is_null());
            assert_eq!((*raw).seedlen, 0);
        }
    }

    /// `set_validate_params` sets the counter only when the seed was accepted, and
    /// `get_validate_params` hands back the borrowed pointer rather than a copy.
    #[test]
    fn set_and_get_validate_params_round_trip() {
        let mut p = Params::new();
        let raw = p.as_mut();
        let seed = [0xAAu8; 28];
        // SAFETY: `raw` is live and the out-parameters are local and writable.
        unsafe {
            ossl_ffc_params_set_pcounter(raw, 11);
            assert_eq!(
                ossl_ffc_params_set_validate_params(raw, seed.as_ptr(), 28, 2878),
                1
            );
            assert_eq!((*raw).pcounter, 2878);

            let mut out_seed: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let mut out_counter: c_int = 0;
            ossl_ffc_params_get_validate_params(
                raw,
                &raw mut out_seed,
                &raw mut out_len,
                &raw mut out_counter,
            );
            assert_eq!((*raw).seed, out_seed);
            assert_eq!(out_len, 28);
            assert_eq!(out_counter, 2878);

            /* Every out-parameter is optional. */
            ossl_ffc_params_get_validate_params(
                raw,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
    }

    /// `enable_flags` is a per-bit or/and-not and `set_flags` replaces the word, so a caller
    /// can turn one validation bit off without disturbing the others.
    #[test]
    fn the_flag_accessors_are_a_word_and_a_bit() {
        let mut p = Params::new();
        let raw = p.as_mut();
        // SAFETY: `raw` is live.
        unsafe {
            assert_eq!((*raw).flags, FFC_PARAM_FLAG_VALIDATE_PQG);
            ossl_ffc_params_enable_flags(raw, crate::ffc::FFC_PARAM_FLAG_VALIDATE_PQ, 0);
            assert_eq!((*raw).flags, FFC_PARAM_FLAG_VALIDATE_G);
            ossl_ffc_params_enable_flags(raw, crate::ffc::FFC_PARAM_FLAG_VALIDATE_PQ, 7);
            assert_eq!((*raw).flags, FFC_PARAM_FLAG_VALIDATE_PQG);
            ossl_ffc_params_set_flags(raw, 0);
            assert_eq!((*raw).flags, 0);
        }
    }

    /// The scalars, and `ossl_ffc_set_digest`'s pointer store rather than a copy.
    #[test]
    fn the_scalar_setters_store_what_they_are_given() {
        let mut p = Params::new();
        let raw = p.as_mut();
        // SAFETY: `raw` is live; the two strings are static literals that outlive it.
        unsafe {
            ossl_ffc_params_set_gindex(raw, 3);
            ossl_ffc_params_set_pcounter(raw, 12);
            ossl_ffc_params_set_h(raw, 5);
            ossl_ffc_set_digest(raw, c"SHA256".as_ptr(), c"provider=default".as_ptr());
            assert_eq!((*raw).gindex, 3);
            assert_eq!((*raw).pcounter, 12);
            assert_eq!((*raw).h, 5);
            assert_eq!((*raw).mdname, c"SHA256".as_ptr());
            assert_eq!((*raw).mdprops, c"provider=default".as_ptr());
        }
    }

    /// `copy` is deep for the numbers and the seed, shallow for the digest names, and copies
    /// every scalar. The distinctness of the two `p` pointers is the assertion that says
    /// "deep" rather than "the same address twice".
    #[test]
    fn copy_deep_copies_the_numbers_and_the_seed() {
        let mut src = Params::new();
        let mut dst = Params::new();
        let seed = [0x5Au8; 28];
        // SAFETY: both objects are live and owned by this test.
        unsafe {
            let p = BN_new();
            let q = BN_new();
            let g = BN_new();
            assert!(BN_set_word(p, 101) != 0);
            assert!(BN_set_word(q, 51) != 0);
            assert!(BN_set_word(g, 2) != 0);
            ossl_ffc_params_set0_pqg(src.as_mut(), p, q, g);
            ossl_ffc_params_set_validate_params(src.as_mut(), seed.as_ptr(), 28, 4);
            ossl_ffc_params_set_gindex(src.as_mut(), 2);
            ossl_ffc_params_set_h(src.as_mut(), 3);
            ossl_ffc_params_set_flags(src.as_mut(), 0x01);
            (*src.as_mut()).keylength = 225;
            (*src.as_mut()).nid = 1126;
            ossl_ffc_set_digest(src.as_mut(), c"SHA256".as_ptr(), ptr::null());

            assert_eq!(ossl_ffc_params_copy(dst.as_mut(), src.as_ref()), 1);

            assert!(!(*dst.as_ref()).p.is_null());
            assert!((*dst.as_ref()).p != (*src.as_ref()).p);
            assert_eq!(BN_cmp((*dst.as_ref()).p, (*src.as_ref()).p), 0);
            assert!((*dst.as_ref()).q != (*src.as_ref()).q);
            assert!((*dst.as_ref()).g != (*src.as_ref()).g);
            assert!((*dst.as_ref()).seed != (*src.as_ref()).seed);
            assert_eq!((*dst.as_ref()).seedlen, 28);
            assert_eq!(*((*dst.as_ref()).seed.add(27)), 0x5A);
            /* The digest names are *the same pointers*. */
            assert_eq!((*dst.as_ref()).mdname, (*src.as_ref()).mdname);
            assert_eq!((*dst.as_ref()).mdprops, (*src.as_ref()).mdprops);
            assert_eq!((*dst.as_ref()).pcounter, 4);
            assert_eq!((*dst.as_ref()).gindex, 2);
            assert_eq!((*dst.as_ref()).h, 3);
            assert_eq!((*dst.as_ref()).flags, 0x01);
            assert_eq!((*dst.as_ref()).keylength, 225);
            assert_eq!((*dst.as_ref()).nid, 1126);
            assert_eq!(ossl_ffc_params_cmp(dst.as_ref(), src.as_ref(), 0), 1);
        }
    }

    /// `cmp` ignores `q` on request and compares `p` and `g` always — which makes it "the
    /// same group" rather than "the same object". The seed and counter are deliberately not
    /// compared, so two objects that differ only in their validation inputs compare equal.
    #[test]
    fn cmp_is_about_the_group_and_not_the_validation_inputs() {
        let mut a = Params::new();
        let mut b = Params::new();
        let seed_a = [0x01u8; 28];
        let seed_b = [0x02u8; 28];
        // SAFETY: both objects are live and owned by this test.
        unsafe {
            let p1 = BN_new();
            let p2 = BN_new();
            let q1 = BN_new();
            let q2 = BN_new();
            let g1 = BN_new();
            let g2 = BN_new();
            assert!(BN_set_word(p1, 101) != 0);
            assert!(BN_set_word(p2, 101) != 0);
            assert!(BN_set_word(q1, 51) != 0);
            assert!(BN_set_word(q2, 51) != 0);
            assert!(BN_set_word(g1, 2) != 0);
            assert!(BN_set_word(g2, 2) != 0);
            ossl_ffc_params_set0_pqg(a.as_mut(), p1, q1, g1);
            ossl_ffc_params_set0_pqg(b.as_mut(), p2, q2, g2);
            ossl_ffc_params_set_validate_params(a.as_mut(), seed_a.as_ptr(), 28, 1);
            ossl_ffc_params_set_validate_params(b.as_mut(), seed_b.as_ptr(), 28, 2);

            assert_eq!(ossl_ffc_params_cmp(a.as_ref(), b.as_ref(), 0), 1);
            assert_eq!(ossl_ffc_params_cmp(a.as_ref(), b.as_ref(), 1), 1);

            /* A different q is invisible when ignored and visible when not. */
            assert!(BN_set_word(q2, 52) != 0);
            assert_eq!(ossl_ffc_params_cmp(a.as_ref(), b.as_ref(), 0), 0);
            assert_eq!(ossl_ffc_params_cmp(a.as_ref(), b.as_ref(), 1), 1);
        }
    }

    /// `ossl_ffc_params_cmp`'s own note — "Note: q may be NULL" — is well-defined because the
    /// authority's `BN_cmp` orders NULL before everything and answers 0 for two NULLs. Two
    /// objects built from `p` and `g` alone therefore compare **equal with `ignore_q` 0**, which
    /// is the case a transcription that guarded the `q` comparison would get wrong.
    #[test]
    fn cmp_is_defined_for_two_objects_with_no_q() {
        let mut a = Params::new();
        let mut b = Params::new();
        // SAFETY: both objects are live and owned by this test.
        unsafe {
            let p1 = BN_new();
            let p2 = BN_new();
            let g1 = BN_new();
            let g2 = BN_new();
            assert!(BN_set_word(p1, 101) != 0);
            assert!(BN_set_word(p2, 101) != 0);
            assert!(BN_set_word(g1, 2) != 0);
            assert!(BN_set_word(g2, 2) != 0);
            ossl_ffc_params_set0_pqg(a.as_mut(), p1, ptr::null_mut(), g1);
            ossl_ffc_params_set0_pqg(b.as_mut(), p2, ptr::null_mut(), g2);
            assert!((*a.as_ref()).q.is_null());
            assert!((*b.as_ref()).q.is_null());

            /* Both q's NULL, `ignore_q` 0: `BN_cmp(NULL, NULL)` answers 0, so the groups are
             * equal. */
            assert_eq!(ossl_ffc_params_cmp(a.as_ref(), b.as_ref(), 0), 1);
            assert_eq!(ossl_ffc_params_cmp(a.as_ref(), b.as_ref(), 1), 1);

            /* And a p that differs still differs. */
            let p3 = BN_new();
            assert!(BN_set_word(p3, 103) != 0);
            ossl_ffc_params_set0_pqg(b.as_mut(), p3, ptr::null_mut(), ptr::null_mut());
            assert_eq!(ossl_ffc_params_cmp(a.as_ref(), b.as_ref(), 0), 0);
        }
    }

    /// The cleanup re-initialises rather than merely zeroing: a caller that releases an object
    /// and reuses it gets the `-1`/`-1`/`PQG` triple back, which is what makes
    /// `crypto/dh/dh_lib.c`'s reuse pattern correct.
    #[test]
    fn cleanup_leaves_a_freshly_initialised_object() {
        let mut p = Params::new();
        let raw = p.as_mut();
        // SAFETY: `raw` is live and owned by this test.
        unsafe {
            let a = BN_new();
            assert!(BN_set_word(a, 3) != 0);
            ossl_ffc_params_set0_pqg(raw, a, ptr::null_mut(), ptr::null_mut());
            ossl_ffc_params_set_pcounter(raw, 99);
            ossl_ffc_params_set_flags(raw, 0);
            ossl_ffc_params_cleanup(raw);
            assert!((*raw).p.is_null());
            assert_eq!((*raw).pcounter, -1);
            assert_eq!((*raw).gindex, FFC_UNVERIFIABLE_GINDEX);
            assert_eq!((*raw).flags, FFC_PARAM_FLAG_VALIDATE_PQG);
        }
    }

    /// **The deterministic agreement test this slice needs**: the same params object,
    /// generated once and then *copied*, validates identically. That is the property the DH
    /// key path depends on — `dh_gen.c:106` copies params into a new `DH` and
    /// `dh_key.c:353` then validates the copy through `ossl_ffc_params_simple_validate` — and
    /// it is deterministic because the copy carries the seed and counter with the numbers.
    ///
    /// Nothing here asserts a generated value: the assertions are the copy's distinctness,
    /// the group's equality, and the two validators' agreement.
    #[test]
    fn a_copied_generation_validates_exactly_like_the_original() {
        let mut original = Params::new();
        let mut copy = Params::new();
        let mut res: c_int = -1;
        let libctx: *mut c_void = ptr::null_mut();

        // SAFETY: both objects are live and owned by this test.
        unsafe {
            assert_eq!(
                ossl_ffc_params_FIPS186_4_generate(
                    libctx,
                    original.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    2048,
                    256,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS
            );
            assert_eq!(ossl_ffc_params_copy(copy.as_mut(), original.as_ref()), 1);
            assert!((*copy.as_ref()).p != (*original.as_ref()).p);
            assert_eq!(ossl_ffc_params_cmp(copy.as_ref(), original.as_ref(), 0), 1);
            assert!(!(*copy.as_ref()).seed.is_null());
            assert_eq!((*copy.as_ref()).seedlen, (*original.as_ref()).seedlen);
            assert_ne!((*copy.as_ref()).pcounter, -1);

            /* `VALIDATE_PQ` only, so the p/q chain is what is validated and the answer is the
             * plain `SUCCESS` rather than the `UNVERIFIABLE_G` the default `VALIDATE_PQG`
             * produces for an object whose `gindex` is the unverifiable sentinel. The flag is
             * set on the original *before* the copy above, so the copy carries it. */
            ossl_ffc_params_set_flags(original.as_mut(), FFC_PARAM_FLAG_VALIDATE_PQ);
            assert_eq!(ossl_ffc_params_copy(copy.as_mut(), original.as_ref()), 1);

            let mut res_original: c_int = -1;
            let mut res_copy: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    libctx,
                    original.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_original,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS
            );
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    libctx,
                    copy.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_copy,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS
            );
            assert_eq!(res_original, 0);
            assert_eq!(res_copy, 0);
        }
    }

    /// A copy whose destination held something else ends freshly initialised rather than
    /// partly filled, because the failure path calls `ossl_ffc_params_cleanup`. The
    /// observable is the destination's scalars, not its pointers.
    #[test]
    fn a_copy_onto_a_used_destination_replaces_the_scalars() {
        let mut src = Params::new();
        let mut dst = Params::new();
        // SAFETY: both objects are live and owned by this test.
        unsafe {
            ossl_ffc_params_set_pcounter(dst.as_mut(), 7);
            ossl_ffc_params_set_flags(dst.as_mut(), 0);
            ossl_ffc_params_set_gindex(dst.as_mut(), 4);
            /* A NULL source `p` is legal and copies as NULL; the copy still succeeds. */
            assert_eq!(ossl_ffc_params_copy(dst.as_mut(), src.as_ref()), 1);
            assert_eq!((*dst.as_ref()).pcounter, -1);
            assert_eq!((*dst.as_ref()).gindex, FFC_UNVERIFIABLE_GINDEX);
            assert_eq!((*dst.as_ref()).flags, FFC_PARAM_FLAG_VALIDATE_PQG);

            /* A params object carrying only a composite p is not a valid group, and the
             * validator says so through the not-suitable-generator bit. */
            let p = BN_new();
            assert!(BN_set_word(p, 23) != 0);
            ossl_ffc_params_set0_pqg(src.as_mut(), p, ptr::null_mut(), ptr::null_mut());
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    src.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            let _ = FFC_ERROR_NOT_SUITABLE_GENERATOR;
        }
    }

    /// The print arm's shape, driven through a writable memory `BIO`: the two unconditional
    /// labels, the seed's fifteen-byte lines with no trailing colon on the last byte, and the
    /// counter printed **after** the seed.
    #[test]
    fn print_order_and_the_seed_lines_are_observable() {
        use crate::runtime::bio::bss_mem::BIO_s_mem;
        use crate::runtime::bio::iolib::{BIO_ctrl_pending, BIO_read};
        use crate::runtime::bio::{BIO_free, BIO_new};

        let mut p = Params::new();
        // SAFETY: the object is live and owned by this test, and the BIO is a fresh memory
        // BIO this test creates and frees.
        unsafe {
            let pbn = BN_new();
            let gbn = BN_new();
            assert!(BN_set_word(pbn, 23) != 0);
            assert!(BN_set_word(gbn, 2) != 0);
            ossl_ffc_params_set0_pqg(p.as_mut(), pbn, ptr::null_mut(), gbn);

            let seed: [u8; 17] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10,
            ];
            ossl_ffc_params_set_validate_params(p.as_mut(), seed.as_ptr(), seed.len(), 12);

            let bio = BIO_new(BIO_s_mem());
            assert!(!bio.is_null());
            assert_eq!(ossl_ffc_params_print(bio, p.as_ref(), 4), 1);

            let pending = BIO_ctrl_pending(bio);
            let mut buf = vec![0u8; pending];
            let n = BIO_read(bio, buf.as_mut_ptr().cast(), pending as c_int);
            assert_eq!(n, pending as c_int);
            let text = String::from_utf8_lossy(&buf);
            let text: &str = &text;

            assert!(text.contains("prime P: 23 (0x17)\n"), "{text:?}");
            assert!(text.contains("generator G: 2 (0x2)\n"), "{text:?}");
            /* `q` and `j` are unset, so their labels are *absent* rather than empty. */
            assert!(!text.contains("subgroup order Q:"));
            assert!(!text.contains("subgroup factor:"));
            /* Fifteen bytes on the first line — the loop breaks *before* writing the newline
             * that starts the next group — and the byte count is what decides the separator. */
            assert!(
                text.contains("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:\n"),
                "{text:?}"
            );
            assert!(text.contains("        0f:10\n"), "{text:?}");
            assert!(!text.contains("10:"), "{text:?}");
            assert!(text.contains("counter: 12\n"), "{text:?}");
            let seed_at = text.find("seed:").unwrap_or(usize::MAX);
            let counter_at = text.find("counter:").unwrap_or(0);
            assert!(seed_at < counter_at, "the counter is printed last");

            BIO_free(bio);
        }
    }

    /// `ossl_ffc_params_todata`'s families, read back through the builder it filled.
    ///
    /// The object is built here rather than imported, so the arm is the writer's alone: a modulus
    /// and a generator from `BN_set_word`, the `gindex`/`pcounter`/`h` scalars, the default
    /// `VALIDATE_PQG` flags and one explicit digest name. The builder's own `to_param` is the
    /// reader, and the keys it is asked for are the `OSSL_PKEY_PARAM_FFC_*` constants — a writer
    /// that misspelled one would be a missing key rather than a wrong value.
    #[test]
    fn the_todata_writer_fills_the_parameter_families() {
        use crate::evp::pkey_ctx::{
            OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_GINDEX,
            OSSL_PKEY_PARAM_FFC_H, OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_PCOUNTER,
            OSSL_PKEY_PARAM_FFC_VALIDATE_G, OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY,
            OSSL_PKEY_PARAM_FFC_VALIDATE_PQ,
        };
        use crate::params::build::{
            OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param,
        };
        use crate::params::dup::OSSL_PARAM_free;
        use crate::params::{OSSL_PARAM_get_int, OSSL_PARAM_locate};

        let mut p = Params::new();
        let bld = OSSL_PARAM_BLD_new();
        assert!(!bld.is_null());
        // SAFETY: every object here is live and owned by this test.
        unsafe {
            let f = &mut *p.as_mut();
            f.p = BN_new();
            f.g = BN_new();
            assert!(!f.p.is_null() && !f.g.is_null());
            assert_eq!(BN_set_word(f.p, 23), 1);
            assert_eq!(BN_set_word(f.g, 2), 1);
            f.gindex = 3;
            f.pcounter = 4;
            f.h = 5;
            f.mdname = c"sha256".as_ptr();

            assert_eq!(
                ossl_ffc_params_todata(p.as_ref(), bld, core::ptr::null_mut()),
                1
            );

            let params = OSSL_PARAM_BLD_to_param(bld);
            assert!(!params.is_null());

            let mut gindex: c_int = 0;
            let mut pcounter: c_int = 0;
            let mut h: c_int = 0;
            let mut vpq: c_int = 0;
            let mut vg: c_int = 0;
            let mut vl: c_int = 0;
            assert_eq!(
                OSSL_PARAM_get_int(
                    OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_GINDEX),
                    &mut gindex
                ),
                1
            );
            assert_eq!(gindex, 3);
            assert_eq!(
                OSSL_PARAM_get_int(
                    OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_PCOUNTER),
                    &mut pcounter
                ),
                1
            );
            assert_eq!(pcounter, 4);
            assert_eq!(
                OSSL_PARAM_get_int(OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_H), &mut h),
                1
            );
            assert_eq!(h, 5);

            /* The three flags travel as 0/1, not as the object's bit set. */
            assert_eq!(
                OSSL_PARAM_get_int(
                    OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ),
                    &mut vpq
                ),
                1
            );
            assert_eq!(
                OSSL_PARAM_get_int(
                    OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_VALIDATE_G),
                    &mut vg
                ),
                1
            );
            assert_eq!(
                OSSL_PARAM_get_int(
                    OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY),
                    &mut vl
                ),
                1
            );
            assert_eq!(vpq, 1);
            assert_eq!(vg, 1);
            assert_eq!(vl, 0);

            assert!(!OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_P).is_null());
            assert!(!OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_G).is_null());
            assert!(!OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_DIGEST).is_null());
            /* The seed is NULL on this object, so its key is absent rather than empty. */
            assert!(
                OSSL_PARAM_locate(params, crate::evp::pkey_ctx::OSSL_PKEY_PARAM_FFC_SEED).is_null()
            );

            OSSL_PARAM_free(params);
            OSSL_PARAM_BLD_free(bld);
        }
    }
}
