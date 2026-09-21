//! Phase 8 — `crypto/dsa/dsa_sign.c`: the `DSA_SIG` object, `DSA_do_sign`, `DSA_sign_setup`,
//! the DER `DSA-Sig-Value` codec and the sign/verify pair.
//!
//! The file's whole definition set: [`DSA_do_sign`] (`dsa_sign.c:22-25`), [`DSA_sign_setup`]
//! (`:27-32`), [`DSA_SIG_new`] (`:34-39`), [`DSA_SIG_free`] (`:41-48`), [`d2i_DSA_SIG`]
//! (`:50-76`), [`i2d_DSA_SIG`] (`:78-117`), [`DSA_size`] (`:119-132`), [`DSA_SIG_get0`]
//! (`:134-140`), [`DSA_SIG_set0`] (`:142-151`), `ossl_dsa_sign_int` (`:153-178`),
//! [`DSA_sign`] (`:180-185`) and [`DSA_verify`] (`:194-217`).
//!
//! ## What the DER codec needs, and where it now is
//!
//! `DSA_size`, `DSA_sign` and `DSA_verify` all reach [`i2d_DSA_SIG`]/[`d2i_DSA_SIG`], and those
//! two are defined **in this file** (it is one of `crypto/dsa/build.info`'s `$COMMON` units, so
//! it is compiled into the FIPS module too and cannot call the ASN.1 machinery), and their whole
//! body is `crypto/asn1_dsa.c`'s [`ossl_encode_der_dsa_sig`] / [`ossl_decode_der_dsa_sig`] over
//! `include/internal/packet.h`'s `WPACKET`/`PACKET`. Those two units had no crate module and no
//! stratum's plan row when D333 recorded the block; D342 lands them (D327's rule) and the five
//! exports D333 left `open` with them.
//!
//! ## What the twelve definitions here are
//!
//! `DSA_do_sign` and `DSA_sign_setup` are pure method dispatch, and the authority's own
//! `DSA_sign_setup` sits inside `#ifndef OPENSSL_NO_DEPRECATED_3_0` — which this profile does not
//! define (D172), so it is compiled and transcribed. The four `DSA_SIG` entry points are the
//! object's whole surface: `OPENSSL_zalloc` then two `BN_clear_free`s, which is why a caller that
//! replaces a signature's halves with [`DSA_SIG_set0`] finds the old ones **cleared** rather than
//! merely dropped. The DER pair and the sign/verify arm are the other half.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};

use crate::asn1_dsa::{ossl_decode_der_dsa_sig, ossl_encode_der_dsa_sig};
use crate::bn::bignum::{BN_clear_free, BN_new, BigNum};
use crate::bn::ctx::BnCtx;
use crate::dsa::ossl::{ossl_dsa_do_sign_int, DSA_get_default_method};
use crate::dsa::vrf::DSA_do_verify;
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_total_written, WPACKET_init_len,
    WPACKET_init_null, WPACKET_init_static_len, Wpacket,
};
use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_new, BufMem};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc};

use super::{Dsa, DsaSig};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/dsa/dsa_sign.c` is a source-tree file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix. It reaches an application through
/// `CRYPTO_set_mem_functions`, so it is part of the contract and `RT-DSA` compares it.
const FILE_DSA_SIGN: *const c_char = c"../../src/openssl-3.6.4/crypto/dsa/dsa_sign.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)` — `dsa_sign.c:22-25`.
///
/// The method dispatch: `dsa->meth->dsa_do_sign(dgst, dlen, dsa)`. The authority's table supplies
/// the real entry point, so this is the way an application reaches
/// [`crate::dsa::ossl::ossl_dsa_do_sign_int`]; a table that leaves the member NULL answers a NULL
/// signature here, exactly as `DH_generate_key` answers 0 for its own nullable member.
///
/// # Safety
///
/// `dgst` is readable for `dlen` bytes; `dsa` is a live object whose parameters and private key the
/// caller set.
#[no_mangle]
pub unsafe extern "C" fn DSA_do_sign(
    dgst: *const c_uchar,
    dlen: c_int,
    dsa: *mut Dsa,
) -> *mut DsaSig {
    // SAFETY: `dsa` is live per the contract.
    let meth = unsafe { (*dsa).meth };
    // SAFETY: `meth` is the object's own table; the header marks `dsa_do_sign` nullable and the
    // authority calls it without a test. An absent member answers NULL, the failure answer.
    match unsafe { (*meth).dsa_do_sign } {
        // SAFETY: `f` is the table's entry point, handed the arguments the authority hands it.
        Some(f) => unsafe { f(dgst, dlen, dsa) },
        None => core::ptr::null_mut(),
    }
}

/// `int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)` —
/// `dsa_sign.c:27-32`. Inside `#ifndef OPENSSL_NO_DEPRECATED_3_0`, which this profile does not
/// define.
///
/// The method dispatch to `dsa->meth->dsa_sign_setup`. Note what the caller gets back: `r` through
/// `rp` and the **inverse of `k`** through `kinvp`, which is the whole reason the signature's two
/// halves are computed in two calls.
///
/// # Safety
///
/// `dsa` is a live object with a private key; `ctx_in` is NULL or live; `kinvp` and `rp` are live
/// out-parameters.
#[no_mangle]
pub unsafe extern "C" fn DSA_sign_setup(
    dsa: *mut Dsa,
    ctx_in: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    let meth = unsafe { (*dsa).meth };
    // SAFETY: `meth` is the object's own table; the member is nullable and an absent one answers 0.
    match unsafe { (*meth).dsa_sign_setup } {
        // SAFETY: `f` is the table's entry point, handed the arguments the authority hands it.
        Some(f) => unsafe { f(dsa, ctx_in, kinvp, rp) },
        None => 0,
    }
}

/// `DSA_SIG *DSA_SIG_new(void)` — `dsa_sign.c:34-39`.
///
/// A zeroed 16-byte object: **both halves start NULL**, which is why [`DSA_SIG_set0`] is the only
/// way to fill one and why `DSA_SIG_free` may release either.
///
/// # Safety
///
/// Takes no pointer.
#[no_mangle]
pub unsafe extern "C" fn DSA_SIG_new() -> *mut DsaSig {
    // SAFETY: `CRYPTO_zalloc` reads no caller pointer and is a safe function in this crate (D113).
    CRYPTO_zalloc(core::mem::size_of::<DsaSig>(), FILE_DSA_SIGN, LINE).cast::<DsaSig>()
}

/// `void DSA_SIG_free(DSA_SIG *sig)` — `dsa_sign.c:41-48`.
///
/// NULL is a no-op. **Both halves are *cleared* rather than freed** — `BN_clear_free` — because a
/// signature's `k`-derived values are secret-adjacent material; the release is in the authority's
/// order, `r` then `s` then the object.
///
/// # Safety
///
/// `sig` is NULL or a live signature.
#[no_mangle]
pub unsafe extern "C" fn DSA_SIG_free(sig: *mut DsaSig) {
    if sig.is_null() {
        return;
    }
    // SAFETY: `sig` is live per the contract and each half is NULL or the object's own.
    unsafe {
        BN_clear_free((*sig).r);
        BN_clear_free((*sig).s);
        CRYPTO_free(sig.cast(), FILE_DSA_SIGN, LINE);
    }
}

/// `void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)` —
/// `dsa_sign.c:143-150`.
///
/// # Safety
///
/// `sig` is live; each out-parameter is NULL or writable for a `*const BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn DSA_SIG_get0(
    sig: *const DsaSig,
    pr: *mut *const BigNum,
    ps: *mut *const BigNum,
) {
    // SAFETY: `sig` is live and each out-parameter is NULL or writable per the contract.
    unsafe {
        if !pr.is_null() {
            *pr = (*sig).r;
        }
        if !ps.is_null() {
            *ps = (*sig).s;
        }
    }
}

/// `int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)` — `dsa_sign.c:152-162`.
///
/// **A NULL in either half refuses before anything is released**, so a caller that passes one
/// value and a NULL keeps the signature it had. On success both old halves are cleared and the new
/// pointers stored, and the answer is 1.
///
/// # Safety
///
/// `sig` is live; each of `r` and `s` is NULL or a live `BIGNUM` whose ownership the caller
/// transfers on the success path.
#[no_mangle]
pub unsafe extern "C" fn DSA_SIG_set0(sig: *mut DsaSig, r: *mut BigNum, s: *mut BigNum) -> c_int {
    if r.is_null() || s.is_null() {
        return 0;
    }
    // SAFETY: `sig` is live and each old half is NULL or the object's own.
    unsafe {
        BN_clear_free((*sig).r);
        BN_clear_free((*sig).s);
        (*sig).r = r;
        (*sig).s = s;
    }
    1
}

/// `DSA_SIG *d2i_DSA_SIG(DSA_SIG **psig, const unsigned char **ppin, long len)` —
/// `dsa_sign.c:50-76`.
///
/// A negative `len` answers NULL. An existing `*psig` is **reused** and updated in place; only when
/// there is none is a fresh object allocated, and a fresh object is freed on failure while a
/// caller's is not. Two NULL halves are allocated before the decode, because the decoder writes
/// *through* them.
///
/// # Safety
///
/// `psig` is NULL or a writable pointer slot; `ppin` is a readable pointer slot over at least `len`
/// bytes; each `*psig` is NULL or a live `DSA_SIG`.
#[no_mangle]
pub unsafe extern "C" fn d2i_DSA_SIG(
    psig: *mut *mut DsaSig,
    ppin: *mut *const c_uchar,
    len: c_long,
) -> *mut DsaSig {
    if len < 0 {
        return core::ptr::null_mut();
    }

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used.
    unsafe {
        let sig = if !psig.is_null() && !(*psig).is_null() {
            *psig
        } else {
            let s = DSA_SIG_new();
            if s.is_null() {
                return core::ptr::null_mut();
            }
            s
        };

        if (*sig).r.is_null() {
            (*sig).r = BN_new();
        }
        if (*sig).s.is_null() {
            (*sig).s = BN_new();
        }
        if (*sig).r.is_null()
            || (*sig).s.is_null()
            || ossl_decode_der_dsa_sig((*sig).r, (*sig).s, ppin, len as usize) == 0
        {
            if psig.is_null() || (*psig).is_null() {
                DSA_SIG_free(sig);
            }
            return core::ptr::null_mut();
        }
        if !psig.is_null() && (*psig).is_null() {
            *psig = sig;
        }
        sig
    }
}

/// `int i2d_DSA_SIG(const DSA_SIG *sig, unsigned char **ppout)` — `dsa_sign.c:78-117`.
///
/// Three call shapes, and the `BUF_MEM`/`WPACKET` pair is why they are distinct: `ppout == NULL`
/// measures through a NULL-buffered packet; `*ppout == NULL` grows a `BUF_MEM` and hands its
/// buffer to the caller, detaching it so the `BUF_MEM` free cannot take it back; otherwise the
/// bytes are written where the caller points and the caller's pointer advances past them.
///
/// # Safety
///
/// `sig` is live; `ppout` is NULL or a writable slot whose `*ppout` is NULL or writable for the
/// encoded length.
#[no_mangle]
pub unsafe extern "C" fn i2d_DSA_SIG(sig: *const DsaSig, ppout: *mut *mut c_uchar) -> c_int {
    let mut buf: *mut BufMem = core::ptr::null_mut();
    let mut encoded_len: usize = 0;
    // SAFETY: `pkt`, `buf`, `r`, `s` are live per this module's own contracts.
    let mut pkt: Wpacket = unsafe { core::mem::zeroed() };

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used.
    unsafe {
        if ppout.is_null() {
            if WPACKET_init_null(&mut pkt, 0) == 0 {
                return -1;
            }
        } else if (*ppout).is_null() {
            buf = BUF_MEM_new();
            if buf.is_null() || WPACKET_init_len(&mut pkt, buf, 0) == 0 {
                BUF_MEM_free(buf);
                return -1;
            }
        } else if WPACKET_init_static_len(&mut pkt, *ppout, usize::MAX, 0) == 0 {
            return -1;
        }

        if ossl_encode_der_dsa_sig(&mut pkt, (*sig).r, (*sig).s) == 0
            || WPACKET_get_total_written(&mut pkt, &mut encoded_len) == 0
            || WPACKET_finish(&mut pkt) == 0
        {
            BUF_MEM_free(buf);
            WPACKET_cleanup(&mut pkt);
            return -1;
        }

        if !ppout.is_null() {
            if (*ppout).is_null() {
                *ppout = (*buf).data.cast::<c_uchar>();
                (*buf).data = core::ptr::null_mut();
                BUF_MEM_free(buf);
            } else {
                *ppout = (*ppout).add(encoded_len);
            }
        }

        encoded_len as c_int
    }
}

/// `int DSA_size(const DSA *dsa)` — `dsa_sign.c:119-132`.
///
/// A NULL `q` answers **-1**, not 0: the authority's `ret` starts at -1 and only a successful
/// measurement replaces it, and a negative measurement is normalised to 0. The size is measured by
/// encoding a signature whose two halves are both `q`, which is the widest either half can be.
///
/// # Safety
///
/// `dsa` is a live `DSA`.
#[no_mangle]
pub unsafe extern "C" fn DSA_size(dsa: *const Dsa) -> c_int {
    let mut ret: c_int = -1;

    // SAFETY: `dsa` is live per the contract.
    unsafe {
        if !(*dsa).params.q.is_null() {
            let sig = DsaSig {
                r: (*dsa).params.q,
                s: (*dsa).params.q,
            };
            ret = i2d_DSA_SIG(&sig, core::ptr::null_mut());

            if ret < 0 {
                ret = 0;
            }
        }
    }
    ret
}

/// `int ossl_dsa_sign_int(int type, const unsigned char *dgst, int dlen, unsigned char *sig,`
/// `unsigned int *siglen, DSA *dsa, unsigned int nonce_type, const char *digestname,`
/// `OSSL_LIB_CTX *libctx, const char *propq)` — `dsa_sign.c:153-178`. Internal
/// (`include/crypto/dsa.h`), so `pub(crate)`.
///
/// A NULL `sig` is the **sizing** call: it answers 1 with `*siglen` set to [`DSA_size`]. Otherwise
/// the signature is produced on one of two arms — the method table's `DSA_do_sign` when the object
/// has no `libctx` or a non-default method, and [`ossl_dsa_do_sign_int`] when it has both — and
/// encoded through [`i2d_DSA_SIG`]. `type` is unread, exactly as in the authority, which passes its
/// own `type` through from the deprecated header and never uses it.
///
/// # Safety
///
/// `dgst` is readable for `dlen` bytes; `sig` is NULL or writable for `*siglen` bytes; `siglen` is a
/// live slot; `dsa` is a live object whose parameters and private key the caller set. `digestname`,
/// `libctx` and `propq` are handed to the nonce draw and are NULL on the legacy path.
#[allow(clippy::too_many_arguments)] // the authority's own ten-parameter signature, kept verbatim
pub(crate) unsafe fn ossl_dsa_sign_int(
    _type: c_int,
    dgst: *const c_uchar,
    dlen: c_int,
    sig: *mut c_uchar,
    siglen: *mut c_uint,
    dsa: *mut Dsa,
    nonce_type: c_uint,
    digestname: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used.
    unsafe {
        if sig.is_null() {
            *siglen = DSA_size(dsa) as c_uint;
            return 1;
        }

        /* legacy case uses the method table */
        let s = if (*dsa).libctx.is_null() || (*dsa).meth != DSA_get_default_method() {
            DSA_do_sign(dgst, dlen, dsa)
        } else {
            ossl_dsa_do_sign_int(dgst, dlen, dsa, nonce_type, digestname, libctx, propq)
        };
        if s.is_null() {
            *siglen = 0;
            return 0;
        }
        let mut out = sig;
        *siglen = i2d_DSA_SIG(s, &mut out) as c_uint;
        DSA_SIG_free(s);
    }
    1
}

/// `int DSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,`
/// `unsigned int *siglen, DSA *dsa)` — `dsa_sign.c:180-185`.
///
/// The public wrapper: [`ossl_dsa_sign_int`] with the nonce and digest parameters NULL.
///
/// # Safety
///
/// As [`ossl_dsa_sign_int`].
#[no_mangle]
pub unsafe extern "C" fn DSA_sign(
    _type: c_int,
    dgst: *const c_uchar,
    dlen: c_int,
    sig: *mut c_uchar,
    siglen: *mut c_uint,
    dsa: *mut Dsa,
) -> c_int {
    // SAFETY: the caller's contract is `ossl_dsa_sign_int`'s.
    unsafe {
        ossl_dsa_sign_int(
            _type,
            dgst,
            dlen,
            sig,
            siglen,
            dsa,
            0,
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
        )
    }
}

/// `int DSA_verify(int type, const unsigned char *dgst, int dgst_len,`
/// `const unsigned char *sigbuf, int siglen, DSA *dsa)` — `dsa_sign.c:194-217`.
///
/// The DER re-encode is a **strictness check**: the decoded signature is encoded again and the
/// result must equal `sigbuf` byte for byte, so a signature with trailing garbage or a non-canonical
/// length refuses before any arithmetic. `OPENSSL_clear_free` releases the re-encode on every
/// path, the label shared by all three refusals being the one `err:`.
///
/// # Safety
///
/// `dgst` is readable for `dgst_len` bytes; `sigbuf` is readable for `siglen` bytes; `dsa` is a live
/// object whose parameters and public key the caller set.
#[no_mangle]
pub unsafe extern "C" fn DSA_verify(
    _type: c_int,
    dgst: *const c_uchar,
    dgst_len: c_int,
    sigbuf: *const c_uchar,
    siglen: c_int,
    dsa: *mut Dsa,
) -> c_int {
    let mut ret: c_int = -1;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used.
    unsafe {
        let mut p = sigbuf;
        let s = DSA_SIG_new();
        if s.is_null() {
            return ret;
        }

        let mut der: *mut c_uchar = core::ptr::null_mut();
        let mut derlen: c_int = -1;

        /* The authority's three `goto err` sites are the `if` bodies below; the release that
         * follows them is the single `err:` label. */
        let mut slot: *mut DsaSig = s;
        if !d2i_DSA_SIG(&mut slot, &mut p, siglen as c_long).is_null() {
            derlen = i2d_DSA_SIG(s, &mut der);
            /* Ensure signature uses DER and doesn't have trailing garbage. */
            let canonical = derlen == siglen
                && (derlen <= 0
                    || core::slice::from_raw_parts(sigbuf, derlen as usize)
                        == core::slice::from_raw_parts(der, derlen as usize));
            if canonical {
                ret = DSA_do_verify(dgst, dgst_len, s, dsa);
            }
        }

        CRYPTO_clear_free(
            der.cast::<c_void>(),
            derlen.max(0) as usize,
            FILE_DSA_SIGN,
            LINE,
        );
        DSA_SIG_free(s);
    }
    ret
}
