//! `crypto/srp/srp_vfy.c` — the SRP verifier store and creators. Phase 12.8.
//!
//! The fourteen exports this file lands — the `SRP_user_pwd` object (`SRP_user_pwd_new`,
//! `_free`, `_set_gN`, `_set1_ids`, `_set0_sv`), the `SRP_VBASE` database (`SRP_VBASE_new`,
//! `_free`, `_add0_user`, `_get_by_user`, `_get1_by_user`) and the verifier creators
//! (`SRP_create_verifier[_BN][_ex]`) — plus the SRP-variant base64 codec `t_fromb64`/
//! `t_tob64` and the statics `SRP_user_pwd_set_sv`, `srp_user_pwd_dup`, `SRP_gN_new_init`,
//! `SRP_gN_free`, `SRP_get_gN_by_id`, `SRP_gN_place_bn` and `find_user`. The seventh
//! export, `SRP_VBASE_init`, is **withheld** on Phase 13's `TXT_DB_read`/`TXT_DB_free`; the
//! private helpers that only it reaches are transcribed but marked `#[allow(dead_code)]`
//! with that caller named at each site, so nothing here is dead for an unrecorded reason.
//!
//! ## The SRP base64 variant
//!
//! The authority's `t_fromb64`/`t_tob64` (`:44-176`) are not the ordinary base64 codec: they
//! use a different alphabet and no `=` padding, padding at the *front* with zero bytes and
//! stripping the leading encoded output instead. That is why their EVP calls set
//! `EVP_ENCODE_CTX_USE_SRP_ALPHABET` (and the encoder also `EVP_ENCODE_CTX_NO_NEWLINES`),
//! and why they are transcribed here rather than reached through `EVP_DecodeBlock`.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
// `#[no_mangle] pub extern "C" fn` is the ABI spelling of each export, but the enclosing
// `srp` module is `pub(crate)`, so `unreachable_pub` (a warn this crate promotes with
// `-D warnings`) would otherwise force the ABI part of the way down to `pub(crate)`. This is
// the allow `src/provider/base.rs` records for the same reason.
#![allow(unreachable_pub)]
// The authority's C initialisers (`s`, `vf`, `tmp_salt`, ...) are dead on the paths that
// reach its `err:` label; the assignments are kept so the transcription reads as the source
// does.
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr};
use core::mem::size_of;
use core::ptr;

use crate::bn::arith::BN_mod_exp;
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2bin, BN_clear_free, BN_dup, BN_free, BN_new, BN_num_bits, BigNum,
};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EvpMd,
};
use crate::evp::encode::{
    evp_encode_ctx_set_flags, EVP_DecodeFinal, EVP_DecodeInit, EVP_DecodeUpdate,
    EVP_ENCODE_CTX_free, EVP_ENCODE_CTX_new, EVP_EncodeFinal, EVP_EncodeInit, EVP_EncodeUpdate,
    EvpEncodeCtx,
};
use crate::rand::rand_lib::{RAND_bytes_ex, RAND_priv_bytes};
use crate::runtime::bio::sys::{memmove, strcmp, strlen};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_insert, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};

use super::srp_lib::{SRP_Calc_x_ex, SRP_get_default_gN};
use super::{SrpGN, SrpGNCache, SrpUserPwd, SrpVbase};

/// The authority translation unit for this module.
pub(crate) const FILE: &CStr = c"crypto/srp/srp_vfy.c";

/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h`'s 20-byte SHA-1 answer.
const SHA_DIGEST_LENGTH: c_int = 20;
/// `SRP_RANDOM_SALT_LEN` — `crypto/srp/srp_vfy.c:28`.
const SRP_RANDOM_SALT_LEN: c_int = 20;
/// `MAX_LEN` — `crypto/srp/srp_vfy.c:29`.
const MAX_LEN: usize = 2500;

/// `EVP_ENCODE_CTX_NO_NEWLINES` — `include/crypto/evp.h:897`.
const EVP_ENCODE_CTX_NO_NEWLINES: c_uint = 1;
/// `EVP_ENCODE_CTX_USE_SRP_ALPHABET` — `include/crypto/evp.h:899`.
const EVP_ENCODE_CTX_USE_SRP_ALPHABET: c_uint = 2;

/// Convert an SRP-variant base64 string into raw bytes; the decoded length, or -1 —
/// `crypto/srp/srp_vfy.c:44-127`.
///
/// # Safety
///
/// `a` must be writable for `alen` bytes and `src` NUL-terminated.
unsafe fn t_fromb64(a: *mut c_uchar, alen: usize, src: *const c_char) -> c_int {
    let outl: c_int;
    let mut outl2: c_int = 0;
    let pad = c"00";

    let mut src = src;
    loop {
        // SAFETY: `src` is NUL-terminated per the contract, so this read is in bounds.
        let ch = unsafe { *src };
        if ch != b' ' as c_char && ch != b'\t' as c_char && ch != b'\n' as c_char {
            break;
        }
        // SAFETY: the byte just read is not the terminator.
        src = unsafe { src.add(1) };
    }
    // SAFETY: `src` is NUL-terminated per the contract.
    let size = unsafe { strlen(src) };
    let mut padsize = 4 - (size & 3);
    padsize &= 3;

    // Four bytes in `src` become three bytes output.
    if size > c_int::MAX as usize || ((size + padsize) / 4) * 3 > alen {
        return -1;
    }

    // SAFETY: no arguments.
    let ctx: *mut EvpEncodeCtx = EVP_ENCODE_CTX_new();
    if ctx.is_null() {
        return -1;
    }

    'done: {
        // 1 byte of data always requires 2 bytes of encoding, so a `padsize` of 3 cannot
        // arise; the authority rejects it rather than proceeding.
        if padsize == 3 {
            outl = -1;
            break 'done;
        }

        // Valid `padsize` values are now 0, 1 or 2.
        // SAFETY: `ctx` is live.
        unsafe {
            EVP_DecodeInit(ctx);
            evp_encode_ctx_set_flags(ctx, EVP_ENCODE_CTX_USE_SRP_ALPHABET);
        }

        // Add any encoded padding that is required.
        let mut l: c_int = 0;
        if padsize != 0 {
            // SAFETY: `ctx` is live; `a` is writable for `alen` bytes; `pad` is 2 bytes.
            let r =
                unsafe { EVP_DecodeUpdate(ctx, a, &mut l, pad.as_ptr().cast(), padsize as c_int) };
            if r < 0 {
                outl = -1;
                break 'done;
            }
        }
        // SAFETY: `ctx` is live; `a`/`src` are as above and `size` counts `src`'s bytes.
        let r = unsafe { EVP_DecodeUpdate(ctx, a, &mut outl2, src.cast(), size as c_int) };
        if r < 0 {
            outl = -1;
            break 'done;
        }
        l += outl2;
        // SAFETY: `ctx` is live; `a + l` is inside the caller's buffer.
        unsafe { EVP_DecodeFinal(ctx, a.add(l as usize), &mut outl2) };
        l += outl2;

        // Strip off the leading padding.
        if padsize != 0 {
            if padsize as c_int >= l {
                outl = -1;
                break 'done;
            }
            // SAFETY: `l > padsize`, so the shifted range is inside the buffer.
            unsafe {
                memmove(
                    a.cast(),
                    a.add(padsize).cast(),
                    (l - padsize as c_int) as usize,
                );
            }
            l -= padsize as c_int;
        }
        outl = l;
    }

    // SAFETY: `ctx` came from `EVP_ENCODE_CTX_new`.
    unsafe { EVP_ENCODE_CTX_free(ctx) };
    outl
}

/// Convert raw bytes into a NUL-terminated SRP-variant base64 string; 1 on success, 0 on
/// error — `crypto/srp/srp_vfy.c:133-176`.
///
/// # Safety
///
/// `dst` must be writable for at least `2 * size + 2` bytes and `src` readable for `size`.
unsafe fn t_tob64(dst: *mut c_char, src: *const c_uchar, size: c_int) -> c_int {
    // SAFETY: no arguments.
    let ctx: *mut EvpEncodeCtx = EVP_ENCODE_CTX_new();
    let mut outl: c_int = 0;
    let mut outl2: c_int = 0;
    let pad: [c_uchar; 2] = [0, 0];

    if ctx.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is live.
    unsafe {
        EVP_EncodeInit(ctx);
        evp_encode_ctx_set_flags(
            ctx,
            EVP_ENCODE_CTX_NO_NEWLINES | EVP_ENCODE_CTX_USE_SRP_ALPHABET,
        );
    }

    // Pad at the front with zero bytes until the length is a multiple of 3, so that
    // `EVP_EncodeUpdate`/`EVP_EncodeFinal` add no `=` padding of their own.
    let leadz = 3 - (size % 3);
    if leadz != 3 {
        // SAFETY: `ctx` is live; `dst` is writable; `pad` is 2 bytes and `leadz` is 1 or 2.
        let ok = unsafe { EVP_EncodeUpdate(ctx, dst.cast(), &mut outl, pad.as_ptr(), leadz) };
        if ok == 0 {
            // SAFETY: `ctx` came from `EVP_ENCODE_CTX_new`.
            unsafe { EVP_ENCODE_CTX_free(ctx) };
            return 0;
        }
    }

    // SAFETY: `ctx` is live; `dst + outl` is inside the caller's buffer; `src` is readable
    // for `size` bytes.
    let ok = unsafe {
        EVP_EncodeUpdate(
            ctx,
            dst.cast::<c_uchar>().add(outl as usize),
            &mut outl2,
            src,
            size,
        )
    };
    if ok == 0 {
        // SAFETY: as above.
        unsafe { EVP_ENCODE_CTX_free(ctx) };
        return 0;
    }
    outl += outl2;
    // SAFETY: `ctx` is live; `dst + outl` is inside the caller's buffer.
    unsafe { EVP_EncodeFinal(ctx, dst.cast::<c_uchar>().add(outl as usize), &mut outl2) };
    outl += outl2;

    // Strip the encoded padding at the front.
    if leadz != 3 {
        // SAFETY: `outl > leadz` on this path, so the shifted range is inside the buffer.
        unsafe {
            memmove(
                dst.cast(),
                dst.cast::<c_uchar>().add(leadz as usize).cast(),
                (outl - leadz) as usize,
            );
            *dst.add((outl - leadz) as usize) = 0;
        }
    }

    // SAFETY: `ctx` came from `EVP_ENCODE_CTX_new`.
    unsafe { EVP_ENCODE_CTX_free(ctx) };
    1
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for [`SRP_user_pwd_free`].
///
/// # Safety
///
/// `p` must be NULL or a live [`SrpUserPwd`].
unsafe extern "C" fn srp_user_pwd_free_void(p: *mut c_void) {
    // SAFETY: `p` is NULL or a live `SRP_user_pwd` per the contract.
    unsafe { SRP_user_pwd_free(p.cast()) };
}

/// `void SRP_user_pwd_free(SRP_user_pwd *user_pwd)` — `crypto/srp/srp_vfy.c:178-187`.
///
/// # Safety
///
/// `user_pwd` must be NULL or a live object this module allocated.
#[no_mangle]
pub unsafe extern "C" fn SRP_user_pwd_free(user_pwd: *mut SrpUserPwd) {
    if user_pwd.is_null() {
        return;
    }
    // SAFETY: `user_pwd` is live per the contract; its fields are the ones this module set.
    unsafe {
        BN_free((*user_pwd).s);
        BN_clear_free((*user_pwd).v);
        CRYPTO_free((*user_pwd).id.cast(), FILE.as_ptr(), 184);
        CRYPTO_free((*user_pwd).info.cast(), FILE.as_ptr(), 185);
        CRYPTO_free(user_pwd.cast(), FILE.as_ptr(), 186);
    }
}

/// `SRP_user_pwd *SRP_user_pwd_new(void)` — `crypto/srp/srp_vfy.c:189-202`.
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn SRP_user_pwd_new() -> *mut SrpUserPwd {
    // The allocation is one `SRP_user_pwd`, the authority's `OPENSSL_malloc`.
    let ret = CRYPTO_malloc(size_of::<SrpUserPwd>(), FILE.as_ptr(), 193).cast::<SrpUserPwd>();
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is a fresh, uninitialised object; every field is written before return.
    unsafe {
        (*ret).N = ptr::null();
        (*ret).g = ptr::null();
        (*ret).s = ptr::null_mut();
        (*ret).v = ptr::null_mut();
        (*ret).id = ptr::null_mut();
        (*ret).info = ptr::null_mut();
    }
    ret
}

/// `void SRP_user_pwd_set_gN(SRP_user_pwd *vinfo, const BIGNUM *g, const BIGNUM *N)` —
/// `crypto/srp/srp_vfy.c:204-209`.
///
/// # Safety
///
/// `vinfo` must be live; `g` and `N` must be NULL or live `BIGNUM`s outliving `vinfo`.
#[no_mangle]
pub unsafe extern "C" fn SRP_user_pwd_set_gN(
    vinfo: *mut SrpUserPwd,
    g: *const BigNum,
    N: *const BigNum,
) {
    // SAFETY: `vinfo` is live per the contract.
    unsafe {
        (*vinfo).N = N;
        (*vinfo).g = g;
    }
}

/// `int SRP_user_pwd_set1_ids(SRP_user_pwd *vinfo, const char *id, const char *info)` —
/// `crypto/srp/srp_vfy.c:211-221`.
///
/// # Safety
///
/// `vinfo` must be live; `id` and `info` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_user_pwd_set1_ids(
    vinfo: *mut SrpUserPwd,
    id: *const c_char,
    info: *const c_char,
) -> c_int {
    // SAFETY: `vinfo` is live per the contract.
    unsafe {
        CRYPTO_free((*vinfo).id.cast(), FILE.as_ptr(), 214);
        CRYPTO_free((*vinfo).info.cast(), FILE.as_ptr(), 215);
        (*vinfo).id = ptr::null_mut();
        (*vinfo).info = ptr::null_mut();
        if !id.is_null() {
            (*vinfo).id = CRYPTO_strdup(id, FILE.as_ptr(), 218);
            if (*vinfo).id.is_null() {
                return 0;
            }
        }
        if info.is_null() {
            return 1;
        }
        (*vinfo).info = CRYPTO_strdup(info, FILE.as_ptr(), 220);
        c_int::from(!(*vinfo).info.is_null())
    }
}

/// `int SRP_user_pwd_set_sv(SRP_user_pwd *vinfo, const char *s, const char *v)` —
/// `crypto/srp/srp_vfy.c:223-248`.
///
/// Waits for `SRP_VBASE_init` (withheld on Phase 13's `TXT_DB_read`), its only caller.
///
/// # Safety
///
/// `vinfo` must be live; `s` and `v` must be NULL or NUL-terminated.
#[allow(dead_code)] // waits for SRP_VBASE_init, withheld on Phase 13's TXT_DB_read
unsafe fn SRP_user_pwd_set_sv(vinfo: *mut SrpUserPwd, s: *const c_char, v: *const c_char) -> c_int {
    let mut tmp = [0u8; MAX_LEN];

    // SAFETY: `vinfo` is live per the contract.
    unsafe {
        (*vinfo).v = ptr::null_mut();
        (*vinfo).s = ptr::null_mut();
    }

    // SAFETY: `tmp` is `MAX_LEN` bytes and `v` is NUL-terminated.
    let mut len = unsafe { t_fromb64(tmp.as_mut_ptr(), tmp.len(), v) };
    if len < 0 {
        return 0;
    }
    // SAFETY: `tmp` holds `len` decoded bytes; `len` is non-negative.
    unsafe {
        (*vinfo).v = BN_bin2bn(tmp.as_ptr(), len, ptr::null_mut());
    }
    // SAFETY: `vinfo` is live.
    let mut ok = !unsafe { (*vinfo).v }.is_null();
    if ok {
        // SAFETY: `tmp` is `MAX_LEN` bytes and `s` is NUL-terminated.
        len = unsafe { t_fromb64(tmp.as_mut_ptr(), tmp.len(), s) };
        ok = len >= 0;
    }
    if ok {
        // SAFETY: `tmp` holds `len` decoded bytes; `len` is non-negative.
        unsafe {
            (*vinfo).s = BN_bin2bn(tmp.as_ptr(), len, ptr::null_mut());
        }
        // SAFETY: `vinfo` is live.
        ok = !unsafe { (*vinfo).s }.is_null();
    }
    if !ok {
        // SAFETY: `vinfo` is live and `v` may be NULL.
        unsafe {
            BN_free((*vinfo).v);
            (*vinfo).v = ptr::null_mut();
        }
        return 0;
    }
    1
}

/// `int SRP_user_pwd_set0_sv(SRP_user_pwd *vinfo, BIGNUM *s, BIGNUM *v)` —
/// `crypto/srp/srp_vfy.c:250-257`.
///
/// # Safety
///
/// `vinfo` must be live; `s` and `v` must be NULL or live `BIGNUM`s whose ownership passes.
#[no_mangle]
pub unsafe extern "C" fn SRP_user_pwd_set0_sv(
    vinfo: *mut SrpUserPwd,
    s: *mut BigNum,
    v: *mut BigNum,
) -> c_int {
    // SAFETY: `vinfo` is live per the contract.
    unsafe {
        BN_free((*vinfo).s);
        BN_clear_free((*vinfo).v);
        (*vinfo).v = v;
        (*vinfo).s = s;
        c_int::from(!(*vinfo).s.is_null() && !(*vinfo).v.is_null())
    }
}

/// `static SRP_user_pwd *srp_user_pwd_dup(SRP_user_pwd *src)` —
/// `crypto/srp/srp_vfy.c:259-275`.
///
/// # Safety
///
/// `src` must be NULL or a live [`SrpUserPwd`].
unsafe fn srp_user_pwd_dup(src: *mut SrpUserPwd) -> *mut SrpUserPwd {
    if src.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no arguments.
    let ret = unsafe { SRP_user_pwd_new() };
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ret` is live; `src`'s pointers are the caller's.
    unsafe {
        SRP_user_pwd_set_gN(ret, (*src).g, (*src).N);
        let ids_ok = SRP_user_pwd_set1_ids(ret, (*src).id, (*src).info) != 0;
        let sv_ok = ids_ok && SRP_user_pwd_set0_sv(ret, BN_dup((*src).s), BN_dup((*src).v)) != 0;
        if !ids_ok || !sv_ok {
            SRP_user_pwd_free(ret);
            return ptr::null_mut();
        }
    }
    ret
}

/// `SRP_VBASE *SRP_VBASE_new(char *seed_key)` — `crypto/srp/srp_vfy.c:277-299`.
///
/// # Safety
///
/// `seed_key` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_VBASE_new(seed_key: *mut c_char) -> *mut SrpVbase {
    // The allocation is one `SRP_VBASE`, the authority's `OPENSSL_malloc`.
    let vb = CRYPTO_malloc(size_of::<SrpVbase>(), FILE.as_ptr(), 279).cast::<SrpVbase>();
    if vb.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `vb` is a fresh, uninitialised object.
    unsafe {
        (*vb).users_pwd = OPENSSL_sk_new_null();
        if (*vb).users_pwd.is_null() {
            CRYPTO_free(vb.cast(), FILE.as_ptr(), 286);
            return ptr::null_mut();
        }
        (*vb).gN_cache = OPENSSL_sk_new_null();
        if (*vb).gN_cache.is_null() {
            OPENSSL_sk_free((*vb).users_pwd);
            CRYPTO_free(vb.cast(), FILE.as_ptr(), 286);
            return ptr::null_mut();
        }
        (*vb).default_g = ptr::null();
        (*vb).default_N = ptr::null();
        (*vb).seed_key = ptr::null_mut();
        if !seed_key.is_null() {
            (*vb).seed_key = CRYPTO_strdup(seed_key, FILE.as_ptr(), 292);
            if (*vb).seed_key.is_null() {
                OPENSSL_sk_free((*vb).users_pwd);
                OPENSSL_sk_free((*vb).gN_cache);
                CRYPTO_free(vb.cast(), FILE.as_ptr(), 295);
                return ptr::null_mut();
            }
        }
    }
    vb
}

/// `void SRP_VBASE_free(SRP_VBASE *vb)` — `crypto/srp/srp_vfy.c:301-309`.
///
/// # Safety
///
/// `vb` must be NULL or a live object this module allocated.
#[no_mangle]
pub unsafe extern "C" fn SRP_VBASE_free(vb: *mut SrpVbase) {
    if vb.is_null() {
        return;
    }
    // SAFETY: `vb` is live per the contract and owns both stacks and its seed key.
    unsafe {
        OPENSSL_sk_pop_free((*vb).users_pwd, Some(srp_user_pwd_free_void));
        OPENSSL_sk_free((*vb).gN_cache);
        CRYPTO_free((*vb).seed_key.cast(), FILE.as_ptr(), 307);
        CRYPTO_free(vb.cast(), FILE.as_ptr(), 308);
    }
}

/// `static SRP_gN_cache *SRP_gN_new_init(const char *ch)` — `crypto/srp/srp_vfy.c:311-334`.
///
/// Waits for `SRP_VBASE_init` (withheld on Phase 13's `TXT_DB_read`), its only caller.
///
/// # Safety
///
/// `ch` must be NULL or NUL-terminated.
#[allow(dead_code)] // waits for SRP_VBASE_init, withheld on Phase 13's TXT_DB_read
unsafe fn SRP_gN_new_init(ch: *const c_char) -> *mut SrpGNCache {
    let mut tmp = [0u8; MAX_LEN];
    // The allocation is one `SRP_gN_cache`, the authority's `OPENSSL_malloc`.
    let newgN = CRYPTO_malloc(size_of::<SrpGNCache>(), FILE.as_ptr(), 315).cast::<SrpGNCache>();
    if newgN.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `tmp` is `MAX_LEN` bytes and `ch` is NUL-terminated.
    let len = unsafe { t_fromb64(tmp.as_mut_ptr(), tmp.len(), ch) };
    if len < 0 {
        // SAFETY: `newgN` is live and holds nothing yet.
        unsafe { CRYPTO_free(newgN.cast(), FILE.as_ptr(), 332) };
        return ptr::null_mut();
    }

    // SAFETY: `newgN` is live; `ch` is NUL-terminated.
    unsafe {
        (*newgN).b64_bn = CRYPTO_strdup(ch, FILE.as_ptr(), 324);
    }
    // SAFETY: `newgN` is live.
    if unsafe { (*newgN).b64_bn }.is_null() {
        // SAFETY: `newgN` is live.
        unsafe { CRYPTO_free(newgN.cast(), FILE.as_ptr(), 332) };
        return ptr::null_mut();
    }

    // SAFETY: `newgN` is live; `tmp` holds `len` decoded bytes; `len` is non-negative.
    unsafe {
        (*newgN).bn = BN_bin2bn(tmp.as_ptr(), len, ptr::null_mut());
    }
    // SAFETY: `newgN` is live.
    if unsafe { (*newgN).bn }.is_null() {
        // SAFETY: `newgN` is live and owns `b64_bn`.
        unsafe {
            CRYPTO_free((*newgN).b64_bn.cast(), FILE.as_ptr(), 330);
            CRYPTO_free(newgN.cast(), FILE.as_ptr(), 332);
        }
        return ptr::null_mut();
    }
    newgN
}

/// `static void SRP_gN_free(SRP_gN_cache *gN_cache)` — `crypto/srp/srp_vfy.c:336-343`.
///
/// Waits for `SRP_VBASE_init` (withheld on Phase 13's `TXT_DB_read`), its only caller.
///
/// # Safety
///
/// `gN_cache` must be NULL or a live object this module allocated.
#[allow(dead_code)] // waits for SRP_VBASE_init, withheld on Phase 13's TXT_DB_read
unsafe fn SRP_gN_free(gN_cache: *mut SrpGNCache) {
    if gN_cache.is_null() {
        return;
    }
    // SAFETY: `gN_cache` is live per the contract and owns both fields.
    unsafe {
        CRYPTO_free((*gN_cache).b64_bn.cast(), FILE.as_ptr(), 340);
        BN_free((*gN_cache).bn);
        CRYPTO_free(gN_cache.cast(), FILE.as_ptr(), 342);
    }
}

/// `static SRP_gN *SRP_get_gN_by_id(const char *id, STACK_OF(SRP_gN) *gN_tab)` —
/// `crypto/srp/srp_vfy.c:345-359`.
///
/// Waits for `SRP_VBASE_init` (withheld on Phase 13's `TXT_DB_read`), its only caller.
///
/// # Safety
///
/// `id` must be NULL or NUL-terminated; `gN_tab` NULL or a live stack of [`SrpGN`].
#[allow(dead_code)] // waits for SRP_VBASE_init, withheld on Phase 13's TXT_DB_read
unsafe fn SRP_get_gN_by_id(id: *const c_char, gN_tab: *mut OpenSslStack) -> *mut SrpGN {
    if !gN_tab.is_null() {
        // SAFETY: `gN_tab` is a live stack per the contract.
        let num = unsafe { OPENSSL_sk_num(gN_tab) };
        let mut i: c_int = 0;
        while i < num {
            // SAFETY: `i` is in range.
            let gN = unsafe { OPENSSL_sk_value(gN_tab, i) }.cast::<SrpGN>();
            if !gN.is_null()
                // SAFETY: `gN` is live and `id` is NULL or NUL-terminated.
                && (id.is_null() || unsafe { strcmp((*gN).id, id) } == 0)
            {
                return gN;
            }
            i += 1;
        }
    }
    // SAFETY: forwarded under this function's contract.
    unsafe { SRP_get_default_gN(id) }
}

/// `static BIGNUM *SRP_gN_place_bn(STACK_OF(SRP_gN_cache) *gN_cache, char *ch)` —
/// `crypto/srp/srp_vfy.c:361-382`.
///
/// Waits for `SRP_VBASE_init` (withheld on Phase 13's `TXT_DB_read`), its only caller.
///
/// # Safety
///
/// `gN_cache` must be NULL or a live stack of [`SrpGNCache`]; `ch` NULL or NUL-terminated.
#[allow(dead_code)] // waits for SRP_VBASE_init, withheld on Phase 13's TXT_DB_read
unsafe fn SRP_gN_place_bn(gN_cache: *mut OpenSslStack, ch: *const c_char) -> *mut BigNum {
    if gN_cache.is_null() {
        return ptr::null_mut();
    }

    // Search whether we have it already.
    // SAFETY: `gN_cache` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(gN_cache) };
    let mut i: c_int = 0;
    while i < num {
        // SAFETY: `i` is in range.
        let cache = unsafe { OPENSSL_sk_value(gN_cache, i) }.cast::<SrpGNCache>();
        // SAFETY: `cache` is live; `ch` is NUL-terminated.
        if unsafe { strcmp((*cache).b64_bn, ch) } == 0 {
            // SAFETY: `cache` is live.
            return unsafe { (*cache).bn };
        }
        i += 1;
    }

    // It is the first time that we find it.
    // SAFETY: `ch` is NULL or NUL-terminated.
    let newgN = unsafe { SRP_gN_new_init(ch) };
    if !newgN.is_null() {
        // SAFETY: `gN_cache` is live; `newgN` is a live object whose ownership passes on
        // success.
        let inserted = unsafe { OPENSSL_sk_insert(gN_cache, newgN.cast(), 0) };
        if inserted > 0 {
            // SAFETY: `newgN` was inserted and is still owned by the stack.
            return unsafe { (*newgN).bn };
        }
        // SAFETY: the insertion failed, so `newgN` is still this call's to release.
        unsafe { SRP_gN_free(newgN) };
    }
    ptr::null_mut()
}

/// `static SRP_user_pwd *find_user(SRP_VBASE *vb, char *username)` —
/// `crypto/srp/srp_vfy.c:512-527`.
///
/// # Safety
///
/// `vb` must be NULL or live; `username` NULL or NUL-terminated.
unsafe fn find_user(vb: *mut SrpVbase, username: *mut c_char) -> *mut SrpUserPwd {
    if vb.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `vb` is live per the contract.
    let num = unsafe { OPENSSL_sk_num((*vb).users_pwd) };
    let mut i: c_int = 0;
    while i < num {
        // SAFETY: `i` is in range.
        let user = unsafe { OPENSSL_sk_value((*vb).users_pwd, i) }.cast::<SrpUserPwd>();
        // SAFETY: `user` is live; `username` is NUL-terminated.
        if unsafe { strcmp((*user).id, username) } == 0 {
            return user;
        }
        i += 1;
    }
    ptr::null_mut()
}

/// `int SRP_VBASE_add0_user(SRP_VBASE *vb, SRP_user_pwd *user_pwd)` —
/// `crypto/srp/srp_vfy.c:529-534`.
///
/// # Safety
///
/// `vb` must be live; `user_pwd` must be NULL or a live object whose ownership passes.
#[no_mangle]
pub unsafe extern "C" fn SRP_VBASE_add0_user(
    vb: *mut SrpVbase,
    user_pwd: *mut SrpUserPwd,
) -> c_int {
    // SAFETY: `vb` is live per the contract.
    if unsafe { OPENSSL_sk_push((*vb).users_pwd, user_pwd.cast()) } <= 0 {
        return 0;
    }
    1
}

/// `SRP_user_pwd *SRP_VBASE_get_by_user(SRP_VBASE *vb, char *username)` —
/// `crypto/srp/srp_vfy.c:543-546`.
///
/// DEPRECATED: use [`SRP_VBASE_get1_by_user`]. The returned pointer is **not** the caller's
/// to free.
///
/// # Safety
///
/// `vb` must be NULL or live; `username` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_VBASE_get_by_user(
    vb: *mut SrpVbase,
    username: *mut c_char,
) -> *mut SrpUserPwd {
    // SAFETY: forwarded under this function's contract.
    unsafe { find_user(vb, username) }
}

/// `SRP_user_pwd *SRP_VBASE_get1_by_user(SRP_VBASE *vb, char *username)` —
/// `crypto/srp/srp_vfy.c:553-606`.
///
/// The returned pointer **is** the caller's to free.
///
/// # Safety
///
/// `vb` must be NULL or live; `username` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SRP_VBASE_get1_by_user(
    vb: *mut SrpVbase,
    username: *mut c_char,
) -> *mut SrpUserPwd {
    if vb.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: forwarded under this function's contract.
    let existing = unsafe { find_user(vb, username) };
    if !existing.is_null() {
        // SAFETY: `existing` is live.
        return unsafe { srp_user_pwd_dup(existing) };
    }

    // If the user is unknown we set parameters as well if we have a seed key.
    // SAFETY: `vb` is live per the contract.
    if unsafe { (*vb).seed_key.is_null() || (*vb).default_g.is_null() || (*vb).default_N.is_null() }
    {
        return ptr::null_mut();
    }

    // SAFETY: no arguments.
    let user = unsafe { SRP_user_pwd_new() };
    if user.is_null() {
        return ptr::null_mut();
    }

    let mut digv = [0u8; SHA_DIGEST_LENGTH as usize];
    let mut digs = [0u8; SHA_DIGEST_LENGTH as usize];
    let mut ctxt: *mut crate::evp::digest::EvpMdCtx = ptr::null_mut();
    let mut md: *mut EvpMd = ptr::null_mut();

    'done: {
        // SAFETY: `user` and `vb` are live.
        unsafe {
            SRP_user_pwd_set_gN(user, (*vb).default_g, (*vb).default_N);
        }
        // SAFETY: `user` is live; `username` is NULL or NUL-terminated.
        if unsafe { SRP_user_pwd_set1_ids(user, username, ptr::null()) } == 0 {
            break 'done;
        }

        // SAFETY: `digv` is `SHA_DIGEST_LENGTH` bytes.
        if unsafe { RAND_priv_bytes(digv.as_mut_ptr(), SHA_DIGEST_LENGTH) } <= 0 {
            break 'done;
        }
        // SAFETY: no arguments beyond the forwarded strings.
        md = unsafe { EVP_MD_fetch(ptr::null_mut(), c"SHA1".as_ptr(), ptr::null()) };
        if md.is_null() {
            break 'done;
        }
        // SAFETY: no arguments.
        ctxt = EVP_MD_CTX_new();
        // SAFETY: `md` is live; `vb`'s seed key and `username` are NUL-terminated; the digests
        // are `SHA_DIGEST_LENGTH` bytes.
        let ok = unsafe {
            !ctxt.is_null()
                && EVP_DigestInit_ex(ctxt, md, ptr::null_mut()) != 0
                && EVP_DigestUpdate(ctxt, (*vb).seed_key.cast(), strlen((*vb).seed_key)) != 0
                && EVP_DigestUpdate(ctxt, username.cast(), strlen(username)) != 0
                && EVP_DigestFinal_ex(ctxt, digs.as_mut_ptr(), ptr::null_mut()) != 0
        };
        if !ok {
            break 'done;
        }
        // SAFETY: `ctxt` and `md` are live.
        unsafe {
            EVP_MD_CTX_free(ctxt);
            ctxt = ptr::null_mut();
            EVP_MD_free(md);
            md = ptr::null_mut();
        }
        // SAFETY: `user` is live and takes ownership of both new `BIGNUM`s.
        if unsafe {
            SRP_user_pwd_set0_sv(
                user,
                BN_bin2bn(digs.as_ptr(), SHA_DIGEST_LENGTH, ptr::null_mut()),
                BN_bin2bn(digv.as_ptr(), SHA_DIGEST_LENGTH, ptr::null_mut()),
            )
        } != 0
        {
            return user;
        }
    }

    // SAFETY: `md` came from `EVP_MD_fetch` (or is NULL); `ctxt` from `EVP_MD_CTX_new` (or
    // is NULL); `user` is this call's.
    unsafe {
        EVP_MD_free(md);
        EVP_MD_CTX_free(ctxt);
        SRP_user_pwd_free(user);
    }
    ptr::null_mut()
}

/// `char *SRP_create_verifier_ex(const char *user, const char *pass, char **salt, char
/// **verifier, const char *N, const char *g, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/srp/srp_vfy.c:611-698`.
///
/// # Safety
///
/// `user`, `pass`, `N`, `g` and `propq` must be NULL or NUL-terminated; `salt` and
/// `verifier` must be writable slots; `libctx` NULL or a live library context.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub unsafe extern "C" fn SRP_create_verifier_ex(
    user: *const c_char,
    pass: *const c_char,
    salt: *mut *mut c_char,
    verifier: *mut *mut c_char,
    N: *const c_char,
    g: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_char {
    let mut result: *mut c_char = ptr::null_mut();
    let mut vf: *mut c_char = ptr::null_mut();
    let mut defgNid: *mut c_char = ptr::null_mut();
    let mut vfsize: c_int = 0;
    let mut tmp = [0u8; MAX_LEN];
    let mut tmp2 = [0u8; MAX_LEN];
    let mut N_bn_alloc: *mut BigNum = ptr::null_mut();
    let mut g_bn_alloc: *mut BigNum = ptr::null_mut();
    let mut s: *mut BigNum = ptr::null_mut();
    let mut v: *mut BigNum = ptr::null_mut();

    'done: {
        if user.is_null() || pass.is_null() || salt.is_null() || verifier.is_null() {
            break 'done;
        }

        // `N` non-NULL selects an explicit group; otherwise the default table is walked.
        let N_bn: *const BigNum;
        let g_bn: *const BigNum;
        if !N.is_null() {
            // SAFETY: `tmp` is `MAX_LEN` bytes and `N` is NUL-terminated.
            let len = unsafe { t_fromb64(tmp.as_mut_ptr(), tmp.len(), N) };
            if len <= 0 {
                break 'done;
            }
            // SAFETY: `tmp` holds `len` decoded bytes; `len` is positive.
            N_bn_alloc = unsafe { BN_bin2bn(tmp.as_ptr(), len, ptr::null_mut()) };
            if N_bn_alloc.is_null() {
                break 'done;
            }
            N_bn = N_bn_alloc;
            // SAFETY: `tmp` is `MAX_LEN` bytes and `g` is NUL-terminated.
            let len = unsafe { t_fromb64(tmp.as_mut_ptr(), tmp.len(), g) };
            if len <= 0 {
                break 'done;
            }
            // SAFETY: `tmp` holds `len` decoded bytes; `len` is positive.
            g_bn_alloc = unsafe { BN_bin2bn(tmp.as_ptr(), len, ptr::null_mut()) };
            if g_bn_alloc.is_null() {
                break 'done;
            }
            g_bn = g_bn_alloc;
            defgNid = c"*".as_ptr().cast_mut();
        } else {
            // SAFETY: `g` is NUL-terminated.
            let gN = unsafe { SRP_get_default_gN(g) };
            if gN.is_null() {
                break 'done;
            }
            // SAFETY: `gN` is a live row of the process-lifetime table.
            unsafe {
                N_bn = (*gN).N;
                g_bn = (*gN).g;
                defgNid = (*gN).id;
            }
        }

        // SAFETY: `salt` is writable per the contract.
        if unsafe { *salt }.is_null() {
            // SAFETY: `tmp2` is `SRP_RANDOM_SALT_LEN` bytes.
            if unsafe { RAND_bytes_ex(libctx, tmp2.as_mut_ptr(), SRP_RANDOM_SALT_LEN as usize, 0) }
                <= 0
            {
                break 'done;
            }
            // SAFETY: `tmp2` holds `SRP_RANDOM_SALT_LEN` random bytes.
            s = unsafe { BN_bin2bn(tmp2.as_ptr(), SRP_RANDOM_SALT_LEN, ptr::null_mut()) };
        } else {
            // SAFETY: `tmp2` is `MAX_LEN` bytes and `*salt` is NUL-terminated.
            let len = unsafe { t_fromb64(tmp2.as_mut_ptr(), tmp2.len(), *salt) };
            if len <= 0 {
                break 'done;
            }
            // SAFETY: `tmp2` holds `len` decoded bytes; `len` is positive.
            s = unsafe { BN_bin2bn(tmp2.as_ptr(), len, ptr::null_mut()) };
        }
        if s.is_null() {
            break 'done;
        }

        // SAFETY: forwarded under this function's contract.
        if unsafe {
            SRP_create_verifier_BN_ex(
                user, pass, &raw mut s, &raw mut v, N_bn, g_bn, libctx, propq,
            )
        } == 0
        {
            break 'done;
        }

        // SAFETY: `v` is live; `tmp` is `MAX_LEN` bytes.
        if unsafe { BN_bn2bin(v, tmp.as_mut_ptr()) } < 0 {
            break 'done;
        }
        // SAFETY: `v` is live.
        let num_v = unsafe { bn_num_bytes(v) };
        vfsize = num_v * 2;
        // The allocation is `vfsize` bytes, the authority's `OPENSSL_malloc`.
        vf = CRYPTO_malloc(vfsize as usize, FILE.as_ptr(), 670).cast::<c_char>();
        if vf.is_null() {
            break 'done;
        }
        // SAFETY: `vf` is `vfsize` bytes; `tmp` holds `num_v` bytes; `num_v` is positive.
        if unsafe { t_tob64(vf, tmp.as_ptr(), num_v) } == 0 {
            break 'done;
        }

        // SAFETY: `salt` is writable per the contract.
        if unsafe { *salt }.is_null() {
            // The allocation is `SRP_RANDOM_SALT_LEN * 2` bytes, the authority's
            // `OPENSSL_malloc_array`.
            let tmp_salt = CRYPTO_malloc((SRP_RANDOM_SALT_LEN as usize) * 2, FILE.as_ptr(), 678)
                .cast::<c_char>();
            if tmp_salt.is_null() {
                break 'done;
            }
            // SAFETY: `tmp_salt` is `SRP_RANDOM_SALT_LEN * 2` bytes; `tmp2` holds
            // `SRP_RANDOM_SALT_LEN` bytes.
            if unsafe { t_tob64(tmp_salt, tmp2.as_ptr(), SRP_RANDOM_SALT_LEN) } == 0 {
                // SAFETY: `tmp_salt` is live.
                unsafe { CRYPTO_free(tmp_salt.cast(), FILE.as_ptr(), 682) };
                break 'done;
            }
            // SAFETY: `salt` is writable per the contract.
            unsafe { *salt = tmp_salt };
        }

        // SAFETY: both slots are writable per the contract.
        unsafe {
            *verifier = vf;
            vf = ptr::null_mut();
        }
        result = defgNid;
    }

    // SAFETY: every pointer below is live or NULL; `CRYPTO_clear_free` accepts NULL.
    unsafe {
        BN_free(N_bn_alloc);
        BN_free(g_bn_alloc);
        CRYPTO_clear_free(vf.cast(), vfsize as usize, FILE.as_ptr(), 694);
        BN_clear_free(s);
        BN_clear_free(v);
    }
    result
}

/// `char *SRP_create_verifier(const char *user, const char *pass, char **salt, char
/// **verifier, const char *N, const char *g)` — `crypto/srp/srp_vfy.c:700-704`.
///
/// # Safety
///
/// As [`SRP_create_verifier_ex`], with a NULL library context and property query.
#[no_mangle]
pub unsafe extern "C" fn SRP_create_verifier(
    user: *const c_char,
    pass: *const c_char,
    salt: *mut *mut c_char,
    verifier: *mut *mut c_char,
    N: *const c_char,
    g: *const c_char,
) -> *mut c_char {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        SRP_create_verifier_ex(
            user,
            pass,
            salt,
            verifier,
            N,
            g,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int SRP_create_verifier_BN_ex(const char *user, const char *pass, BIGNUM **salt, BIGNUM
/// **verifier, const BIGNUM *N, const BIGNUM *g, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/srp/srp_vfy.c:715-763`.
///
/// # Safety
///
/// `user` and `pass` must be NULL or NUL-terminated; `salt` and `verifier` writable slots;
/// `N` and `g` NULL or live `BIGNUM`s; `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub unsafe extern "C" fn SRP_create_verifier_BN_ex(
    user: *const c_char,
    pass: *const c_char,
    salt: *mut *mut BigNum,
    verifier: *mut *mut BigNum,
    N: *const BigNum,
    g: *const BigNum,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut result: c_int = 0;
    let mut tmp2 = [0u8; MAX_LEN];
    let mut salttmp: *mut BigNum = ptr::null_mut();
    let mut verif: *mut BigNum = ptr::null_mut();

    // SAFETY: no arguments.
    let bn_ctx = unsafe { BN_CTX_new_ex(libctx) };

    let x = 'body: {
        if user.is_null()
            || pass.is_null()
            || salt.is_null()
            || verifier.is_null()
            || N.is_null()
            || g.is_null()
            || bn_ctx.is_null()
        {
            break 'body ptr::null_mut();
        }

        // SAFETY: `salt` is writable per the contract.
        if unsafe { *salt }.is_null() {
            // SAFETY: `tmp2` is `SRP_RANDOM_SALT_LEN` bytes.
            if unsafe { RAND_bytes_ex(libctx, tmp2.as_mut_ptr(), SRP_RANDOM_SALT_LEN as usize, 0) }
                <= 0
            {
                break 'body ptr::null_mut();
            }
            // SAFETY: `tmp2` holds `SRP_RANDOM_SALT_LEN` random bytes.
            salttmp = unsafe { BN_bin2bn(tmp2.as_ptr(), SRP_RANDOM_SALT_LEN, ptr::null_mut()) };
            if salttmp.is_null() {
                break 'body ptr::null_mut();
            }
        } else {
            // SAFETY: `salt` is writable per the contract.
            salttmp = unsafe { *salt };
        }

        // SAFETY: forwarded under this function's contract.
        let x = unsafe { SRP_Calc_x_ex(salttmp, user, pass, libctx, propq) };
        if x.is_null() {
            break 'body ptr::null_mut();
        }

        // SAFETY: no arguments.
        verif = unsafe { BN_new() };
        if verif.is_null() {
            break 'body x;
        }

        // SAFETY: all pointers are live.
        if unsafe { BN_mod_exp(verif, g, x, N, bn_ctx) } == 0 {
            // SAFETY: `verif` is live.
            unsafe { BN_clear_free(verif) };
            break 'body x;
        }

        result = 1;
        // SAFETY: both slots are writable per the contract.
        unsafe {
            *salt = salttmp;
            *verifier = verif;
        }
        break 'body x;
    };

    // SAFETY: `bn_ctx` is live or NULL; `x` is live or NULL.
    unsafe {
        if !salt.is_null() && *salt != salttmp {
            BN_clear_free(salttmp);
        }
        BN_clear_free(x);
        BN_CTX_free(bn_ctx);
    }
    result
}

/// `int SRP_create_verifier_BN(const char *user, const char *pass, BIGNUM **salt, BIGNUM
/// **verifier, const BIGNUM *N, const BIGNUM *g)` — `crypto/srp/srp_vfy.c:765-771`.
///
/// # Safety
///
/// As [`SRP_create_verifier_BN_ex`], with a NULL library context and property query.
#[no_mangle]
pub unsafe extern "C" fn SRP_create_verifier_BN(
    user: *const c_char,
    pass: *const c_char,
    salt: *mut *mut BigNum,
    verifier: *mut *mut BigNum,
    N: *const BigNum,
    g: *const BigNum,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        SRP_create_verifier_BN_ex(
            user,
            pass,
            salt,
            verifier,
            N,
            g,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `BN_num_bytes(a)` — `include/openssl/bn.h`'s macro `((BN_num_bits(a) + 7) / 8)`, written
/// as its body because a macro has no symbol.
///
/// # Safety
///
/// `a` must be NULL or a live `BIGNUM`.
unsafe fn bn_num_bytes(a: *const BigNum) -> c_int {
    // SAFETY: `a` is NULL or live per the caller's contract.
    (unsafe { BN_num_bits(a) } + 7) / 8
}
