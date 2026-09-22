//! `crypto/x509/x_pubkey.c` — the `X509_PUBKEY` object layer, its `ASN1_ITEM` and the
//! `d2i`/`i2d` public-key family. Phase 8.8 (D349), completed by D369.
//!
//! ## What this module is, and the cycle that used to hold it
//!
//! `crypto/x509/x_pubkey.c` is 1,079 lines, **24 exports** and **17 internals**. D349 landed
//! three of the exports and one internal — the accessors the `EVP_PKEY_ASN1_METHOD` objects
//! call by name — and withheld the rest for a measured reason: the `i2d_*_PUBKEY`/`d2i_*_PUBKEY`
//! family builds a temporary `EVP_PKEY` and calls `EVP_PKEY_assign`, whose `EVP_PKEY_set_type`
//! lookup reads `crypto/asn1/ameth_lib.c`'s `standard_methods[]`, the table of Phase 8's
//! objects that was then empty (`src/evp/pkey_asn1.rs`'s `D-PKEY-AMETH-1`, D341's cycle).
//!
//! **That cycle is gone.** D353 published the eleven in-reach `standard_methods[]` rows, so
//! `EVP_PKEY_assign`, `EVP_PKEY_set_type`, `EVP_PKEY_type` and the twelve legacy accessors all
//! answer; D367 landed the pkey half of the decoder cache and `OSSL_DECODER_CTX_new_for_pkey`;
//! D362 landed the encoder chain and `OSSL_ENCODER_CTX_new_for_pkey`. The re-measurement is
//! therefore this module: **23 of the 24 exports** and **9 of the 17 internals** are in reach
//! and are transcribed here.
//!
//! ## What is withheld, with its coordinate
//!
//! Two blocks, both measured rather than preferred:
//!
//! * **The eight `crypto/ec/ecx_meth.c`-dependent internals** — four `ossl_d2i_*_PUBKEY` and
//!   the four `ossl_i2d_*_PUBKEY` twins for `ED25519`, `ED448`, `X25519` and `X448`. The
//!   `d2i` half reads `ossl_evp_pkey_get1_ED25519`/`_ED448`/`_X25519`/`_X448`
//!   (`crypto/ec/ecx_backend.c`), which no module in the crate defines; the `i2d` half calls
//!   `EVP_PKEY_assign(pktmp, EVP_PKEY_ED25519, ...)` and then `i2d_PUBKEY`, and the four ECX
//!   rows are withheld from **both** `standard_methods[]` tables under `D-PKEY-AMETH-3`, so
//!   `EVP_PKEY_type` answers `NID_undef`, `EVP_PKEY_set_type` fails and `i2d_PUBKEY` answers
//!   `-1` where the authority answers the encoded length. A transcription would be a body that
//!   answers differently from the authority's — the class D349 named.
//! * **`X509_get0_pubkey_bitstr`** (`:1043-1048`), which reads `x->cert_info.key->public_key`
//!   off `struct x509_st`. The crate has no `X509` object (Phase 11's), so the three-member
//!   walk cannot be written. It is an export the prerequisite gate does not observe (it is not
//!   in the internal-symbol universe), which is why it carries no divergence row.
//!
//! ## The `ASN1_ITEM` layer this unit is the authority for
//!
//! `X509_PUBKEY` is an **`ASN1_ITYPE_EXTERN`** item (`IMPLEMENT_EXTERN_ASN1(X509_PUBKEY,
//! V_ASN1_SEQUENCE, x509_pubkey_ff)`, `:267`), the first the crate builds: its hooks are
//! `x509_pubkey_ex_new_ex` (`:109`), `x509_pubkey_ex_free` (`:85`), `x509_pubkey_ex_d2i_ex`
//! (`:128`), `x509_pubkey_ex_i2d` (`:241`) and `x509_pubkey_ex_print` (`:248`), and the
//! `asn1_ex_new`/`asn1_ex_clear`/`asn1_ex_d2i` slots are NULL, exactly as the authority's
//! initialiser leaves them. `ASN1_SEQUENCE(X509_PUBKEY_INTERNAL)` (`:63-66`) is the item the
//! hooks decode through, with the object's two leading fields as its columns, and
//! `ossl_d2i_X509_PUBKEY_INTERNAL` (`:68`) / `ossl_X509_PUBKEY_INTERNAL_free` (`:80`) are the
//! decoder and free path `ossl_d2i_PUBKEY_legacy` needs.
//!
//! `x509_pubkey_ex_d2i_ex` reaches the dispatch through `asn1_item_embed_d2i` directly —
//! **not** through `ASN1_item_ex_d2i` — with `depth` 0 and no library context, and does its own
//! free on failure; [`crate::asn1::d2i::asn1_item_embed_d2i`] is the crate's `pub(crate)`
//! spelling of that entry point, added here.
//!
//! ## The two collapses, each with its coordinate
//!
//! * `x509_pubkey_decode` (`:406`) tests `ENGINE_get_pkey_meth_engine(nid)` on the
//!   non-`flag_force_legacy` path and answers `0` when no ENGINE provides the method. ENGINE is
//!   Phase 13's, the crate has none, and no built-in type has an engine-provided method, so
//!   the authority's `#else` arm is what this transcription writes: `0`. The forced-legacy path
//!   — `ossl_d2i_PUBKEY_legacy` and `X509_PUBKEY_dup`'s recovery — is unaffected.
//! * `i2d_PUBKEY`'s provider arm reaches `OSSL_ENCODER_CTX_new_for_pkey` (`:572`), which D362
//!   landed; on every key this crate can build the encoder count is 0 and the arm answers `-1`,
//!   which is the authority's own answer for a key with no encoders.
//!
//! ## The raise sites
//!
//! This unit raises, so it **is** in `gen_err_raise_sites.py`'s `COVERED_FILES` now
//! (`crypto/x509/x_pubkey.c` -> stem `X509_PUBKEY`): twenty-four sites, `ERR_LIB_X509`/
//! `ERR_LIB_ASN1`/`ERR_LIB_EVP` with the `ERR_R_*` reasons, `ASN1_R_DECODE_ERROR`,
//! `EVP_R_DECODE_ERROR` and the three `X509_R_*` refusals. D349's module doc said the unit was
//! deliberately absent because the four landed functions raised nothing; that is no longer the
//! measurement.
//!
//! ## The court
//!
//! `RT-AMETH` (`courts/phase8/rt_ameth_probe.c`) carries the arms: a `X509_PUBKEY` built
//! through its own item round-trips through `i2d_X509_PUBKEY`/`d2i_X509_PUBKEY`, `X509_PUBKEY_dup`
//! reads the same algorithm and bytes, `X509_PUBKEY_eq` compares two built objects and refuses
//! against a NULL, and `d2i_PUBKEY`/`d2i_RSA_PUBKEY` are driven over their own encoders. Every
//! observation is a return code, a length, a NID or a drained reason — no address and no
//! random value is printed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::bitstr::{set_bits_left, ASN1_BIT_STRING_set};
use crate::asn1::d2i::{asn1_item_embed_d2i, ASN1_item_d2i, ASN1_item_d2i_ex};
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::{ASN1_item_ex_i2d, ASN1_item_i2d};
use crate::asn1::items::ASN1_BIT_STRING_it;
use crate::asn1::layout::*;
use crate::asn1::new::{ASN1_item_new, ASN1_item_new_ex};
use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_BIT_STRING_new, ASN1_STRING_set0};
use crate::asn1::tasn_prn::ASN1_item_print;
use crate::asn1::x_algor::{
    X509Algor, X509_ALGOR_cmp, X509_ALGOR_dup, X509_ALGOR_free, X509_ALGOR_it, X509_ALGOR_new,
    X509_ALGOR_set0,
};
use crate::bn::bignum::BigNum;
use crate::decoder_lib::OSSL_DECODER_from_data;
use crate::decoder_meth::{OSSL_DECODER_CTX_free, OsslDecoderCtx};
use crate::decoder_pkey::OSSL_DECODER_CTX_new_for_pkey;
use crate::dh::object::DH_free;
use crate::dh::Dh;
use crate::dsa::object::{DSA_free, DSA_get0_pqg};
use crate::dsa::Dsa;
use crate::ec::key::EC_KEY_free;
use crate::ec::EcKey;
use crate::encoder_lib::{
    OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_to_bio, OSSL_ENCODER_to_data,
};
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::p_legacy_assign::{EVP_PKEY_get1_EC_KEY, EVP_PKEY_get1_RSA};
use crate::evp::pkey::{
    evp_pkey_is_provided, EVP_PKEY_assign, EVP_PKEY_dup, EVP_PKEY_eq, EVP_PKEY_free,
    EVP_PKEY_get1_DH, EVP_PKEY_get1_DSA, EVP_PKEY_get_id, EVP_PKEY_new, EVP_PKEY_set_type,
    EVP_PKEY_up_ref, EvpPkey, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_RSA, EVP_PKEY_SM2,
};
use crate::rsa::object::RSA_free;
use crate::rsa::Rsa;
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_GET_BUF_MEM_PTR};
use crate::runtime::buffer::BufMem;
use crate::runtime::err::{
    err_sites, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, OBJ_obj2nid, OBJ_obj2txt};

/// `EVP_PKEY_PUBLIC_KEY` — `include/openssl/evp.h:110`, `KEY_PARAMETERS | SELECT_PUBLIC_KEY`.
///
/// The selection `x509_pubkey_ex_d2i_ex`, `X509_PUBKEY_set` and `i2d_PUBKEY` pass to the
/// decoder/encoder context: the public key plus its parameters. Composed from the three
/// `OSSL_KEYMGMT_SELECT_*` constants `src/evp/pkey.rs` publishes rather than re-spelled as a
/// number.
const EVP_PKEY_PUBLIC_KEY: c_int = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
    | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`. The bound of the `txtoidname` buffer
/// `x509_pubkey_ex_d2i_ex` fills with `OBJ_obj2txt`, and the same 50
/// `src/evp/pkey_ctx.rs` records.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// The authority's `ossl_assert` under `-DNDEBUG`, which this profile sets: a plain check that
/// returns its argument, not the `OPENSSL_die` form. `src/ec/pmeth.rs` carries the same helper.
#[inline]
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_zalloc`/`OPENSSL_free`/`OPENSSL_strdup`/
/// `OPENSSL_memdup` macro expansions, and the lines each expands at.
const FILE: &core::ffi::CStr = c"crypto/x509/x_pubkey.c";
/// `x509_pubkey_ex_new_ex`'s `OPENSSL_zalloc(sizeof(*ret))` (`:114`).
const LINE_ZALLOC_NEW_EX: c_int = 114;
/// `x509_pubkey_ex_free`'s `OPENSSL_free(pubkey->propq)` (`:93`).
const LINE_FREE_PROPQ: c_int = 93;
/// `x509_pubkey_ex_free`'s `OPENSSL_free(pubkey)` (`:94`).
const LINE_FREE_PUBKEY: c_int = 94;
/// `x509_pubkey_set0_libctx`'s `OPENSSL_free(x->propq)` (`:52`).
const LINE_FREE_PROPQ_SET0: c_int = 52;
/// `x509_pubkey_set0_libctx`'s `OPENSSL_strdup(propq)` (`:55`).
const LINE_STRDUP_SET0: c_int = 55;
/// `ossl_d2i_X509_PUBKEY_INTERNAL`'s `OPENSSL_zalloc(sizeof(*xpub))` (`:71`).
const LINE_ZALLOC_INTERNAL: c_int = 71;
/// `X509_PUBKEY_dup`'s `OPENSSL_zalloc(sizeof(*pubkey))` (`:288`).
const LINE_ZALLOC_DUP: c_int = 288;
/// `d2i_PUBKEY_int`'s `OPENSSL_zalloc(sizeof(*xpk2))` (`:508`).
const LINE_ZALLOC_D2I_INT: c_int = 508;
/// `x509_pubkey_ex_d2i_ex`'s `OPENSSL_memdup(in_saved, publen)` (`:196`).
const LINE_MEMDUP_D2I_EX: c_int = 196;
/// `x509_pubkey_ex_d2i_ex`'s `OPENSSL_free(tmpbuf)` (`:237`).
const LINE_FREE_TMPBUF: c_int = 237;
/// `X509_PUBKEY_set`'s `OPENSSL_free(der)` (`:363`).
const LINE_FREE_DER: c_int = 363;

/// `struct X509_pubkey_st` — `X509_PUBKEY`, from `crypto/x509/x_pubkey.c:31-43`.
///
/// The file's own definition, not a header's, so its fields are crate-private. The `ASN1_ITEM`
/// layer reads the first two members' offsets ([`X509_PUBKEY_INTERNAL_TT`]), the accessors read
/// all six, and `pkey` is written by [`x509_pubkey_decode`] and read by
/// [`X509_PUBKEY_get0`].
///
/// The authority writes the trailing member as `unsigned int flag_force_legacy : 1`; a C
/// bitfield has no Rust spelling, so it is a `c_uint` occupying the same four bytes at the same
/// offset, and the struct's size is unchanged. That is the same modelling
/// `src/ec/backend.rs` records for the authority's flag words.
#[repr(C)]
pub struct X509Pubkey {
    /// `X509_ALGOR *algor` — the subjectPublicKeyInfo algorithm, read by `set0_param`,
    /// `get0_param`, [`x509_pubkey_decode`] and [`x509_pubkey_ex_d2i_ex`].
    pub(crate) algor: *mut X509Algor,
    /// `ASN1_BIT_STRING *public_key` — the `subjectPublicKey` bit string, written by
    /// [`X509_PUBKEY_set0_public_key`] and read by [`X509_PUBKEY_get0_param`].
    pub(crate) public_key: *mut Asn1String,
    /// `EVP_PKEY *pkey` — the decoded key, filled by [`x509_pubkey_decode`] and read by
    /// [`X509_PUBKEY_get0`].
    pub(crate) pkey: *mut EvpPkey,
    /// `OSSL_LIB_CTX *libctx` — the decoding library context, read by
    /// [`ossl_x509_PUBKEY_get0_libctx`] and passed to the decoder. The crate models an
    /// `OSSL_LIB_CTX *` as `*mut c_void`, as every landed entry point does.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — the decoding property query, owned by the object and passed to the
    /// decoder.
    pub(crate) propq: *mut c_char,
    /// `unsigned int flag_force_legacy : 1` — forces the legacy decode path in
    /// [`x509_pubkey_decode`]; set by `d2i_PUBKEY_int` for `ossl_d2i_PUBKEY_legacy` and by
    /// [`X509_PUBKEY_dup`] when `EVP_PKEY_dup` fails.
    pub(crate) flag_force_legacy: c_uint,
}

const _: () = {
    assert!(core::mem::size_of::<X509Pubkey>() == 48);
    assert!(core::mem::offset_of!(X509Pubkey, algor) == 0);
    assert!(core::mem::offset_of!(X509Pubkey, public_key) == 8);
    assert!(core::mem::offset_of!(X509Pubkey, pkey) == 16);
    assert!(core::mem::offset_of!(X509Pubkey, libctx) == 24);
    assert!(core::mem::offset_of!(X509Pubkey, propq) == 32);
    assert!(core::mem::offset_of!(X509Pubkey, flag_force_legacy) == 40);
};

// ---------------------------------------------------------------------------------------------
// The `X509_PUBKEY_INTERNAL` item — `ASN1_SEQUENCE(X509_PUBKEY_INTERNAL)` (`:63-66`)
// ---------------------------------------------------------------------------------------------

/// `X509_PUBKEY_INTERNAL_seq_tt` — `ASN1_SEQUENCE(X509_PUBKEY_INTERNAL)`:
/// `ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR)` and
/// `ASN1_SIMPLE(X509_PUBKEY, public_key, ASN1_BIT_STRING)`.
///
/// Both columns are mandatory (`ASN1_SIMPLE` = `ASN1_EX_TYPE(0, 0, ...)`), so their template
/// flags and tags are zero; only the offsets and the two field items differ.
static X509_PUBKEY_INTERNAL_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"algor".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"public_key".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `X509_PUBKEY_INTERNAL`'s descriptor — `static_ASN1_SEQUENCE_END_name(X509_PUBKEY,
/// X509_PUBKEY_INTERNAL)` at `crypto/x509/x_pubkey.c:66`.
///
/// `static_`, so no public `_it` accessor exists in the authority and none is defined here:
/// [`x509_pubkey_internal_it`] is the crate-internal reader.
static X509_PUBKEY_INTERNAL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_PUBKEY_INTERNAL_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Pubkey>() as c_long,
    sname: c"X509_PUBKEY_INTERNAL".as_ptr(),
};

/// `ASN1_ITEM_rptr(X509_PUBKEY_INTERNAL)` — `x_pubkey.c:76`, `:83`, `:150`, `:244`, `:252`.
fn x509_pubkey_internal_it() -> *const Asn1Item {
    &X509_PUBKEY_INTERNAL_ITEM
}

/// `X509_PUBKEY *ossl_d2i_X509_PUBKEY_INTERNAL(const unsigned char **pp, long len,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/x509/x_pubkey.c:68-78`.
///
/// Allocates a zeroed object and decodes the two columns into it through `ASN1_item_d2i_ex`, so
/// the item's own `ASN1_ITYPE_SEQUENCE` decoder runs rather than the outer `EXTERN` hooks.
///
/// # Safety
///
/// `pp` points at a readable cursor for `len` bytes; `libctx` is NULL or a live context and
/// `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_d2i_X509_PUBKEY_INTERNAL(
    pp: *mut *const c_uchar,
    len: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut X509Pubkey {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let mut xpub = CRYPTO_zalloc(
        core::mem::size_of::<X509Pubkey>(),
        FILE.as_ptr(),
        LINE_ZALLOC_INTERNAL,
    )
    .cast::<X509Pubkey>();

    if xpub.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `xpub` is this call's own live slot and `pp` is the caller's cursor.
    unsafe {
        ASN1_item_d2i_ex(
            (&raw mut xpub).cast::<*mut c_void>(),
            pp,
            len,
            x509_pubkey_internal_it(),
            libctx,
            propq,
        )
    }
    .cast::<X509Pubkey>()
}

/// `void ossl_X509_PUBKEY_INTERNAL_free(X509_PUBKEY *xpub)` — `crypto/x509/x_pubkey.c:80-83`.
///
/// # Safety
///
/// `xpub` is NULL or a value [`ossl_d2i_X509_PUBKEY_INTERNAL`] built.
#[no_mangle]
pub unsafe extern "C" fn ossl_X509_PUBKEY_INTERNAL_free(xpub: *mut X509Pubkey) {
    // SAFETY: `xpub` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(xpub.cast::<c_void>(), x509_pubkey_internal_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `x509_pubkey_ff` hooks — `crypto/x509/x_pubkey.c:47-265`
// ---------------------------------------------------------------------------------------------

/// `static int x509_pubkey_set0_libctx(X509_PUBKEY *x, OSSL_LIB_CTX *libctx, const char *propq)`
/// — `crypto/x509/x_pubkey.c:47-61`.
///
/// Replaces the object's property query and answers 0 only when the duplicate cannot be made.
///
/// # Safety
///
/// `x` is NULL or a live object; `propq` is NULL or NUL-terminated.
unsafe fn x509_pubkey_set0_libctx(
    x: *mut X509Pubkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if !x.is_null() {
        // SAFETY: `x` is live per the contract.
        unsafe {
            (*x).libctx = libctx;
            CRYPTO_free(
                (*x).propq.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_PROPQ_SET0,
            );
            (*x).propq = ptr::null_mut();
            if !propq.is_null() {
                (*x).propq = CRYPTO_strdup(propq, FILE.as_ptr(), LINE_STRDUP_SET0);
                if (*x).propq.is_null() {
                    return 0;
                }
            }
        }
    }
    1
}

/// `static void x509_pubkey_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it)` —
/// `crypto/x509/x_pubkey.c:85-97`. The `ASN1_EXTERN_FUNCS.asn1_ex_free` hook.
///
/// # Safety
///
/// `pval` is NULL or a live slot holding NULL or a value this item built; `it` is unused.
unsafe extern "C" fn x509_pubkey_ex_free(pval: *mut *mut c_void, _it: *const Asn1Item) {
    if !pval.is_null() {
        // SAFETY: `pval` is a live slot per the contract.
        let pubkey = unsafe { *pval }.cast::<X509Pubkey>();
        if !pubkey.is_null() {
            // SAFETY: `pubkey` is a live object this item built.
            unsafe {
                X509_ALGOR_free((*pubkey).algor);
                ASN1_BIT_STRING_free((*pubkey).public_key);
                EVP_PKEY_free((*pubkey).pkey);
                CRYPTO_free(
                    (*pubkey).propq.cast::<c_void>(),
                    FILE.as_ptr(),
                    LINE_FREE_PROPQ,
                );
                CRYPTO_free(pubkey.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_PUBKEY);
                *pval = ptr::null_mut();
            }
        }
    }
}

/// `static int x509_pubkey_ex_populate(ASN1_VALUE **pval, const ASN1_ITEM *it)` —
/// `crypto/x509/x_pubkey.c:99-107`.
///
/// Builds whichever of the two mandatory members is absent and answers 0 only if a
/// constructor fails. The short-circuit is the authority's: an already-present member is not
/// rebuilt.
///
/// # Safety
///
/// `pval` is a live slot holding a live object; `it` is unused.
unsafe fn x509_pubkey_ex_populate(pval: *mut *mut c_void, _it: *const Asn1Item) -> c_int {
    // SAFETY: `pval` is a live slot per the contract.
    let pubkey = unsafe { *pval }.cast::<X509Pubkey>();
    // SAFETY: `pubkey` is live.
    unsafe {
        if (*pubkey).algor.is_null() {
            (*pubkey).algor = X509_ALGOR_new();
        }
        if (*pubkey).algor.is_null() {
            return 0;
        }
        if (*pubkey).public_key.is_null() {
            (*pubkey).public_key = ASN1_BIT_STRING_new();
        }
        if (*pubkey).public_key.is_null() {
            return 0;
        }
    }
    1
}

/// `static int x509_pubkey_ex_new_ex(ASN1_VALUE **pval, const ASN1_ITEM *it, OSSL_LIB_CTX
/// *libctx, const char *propq)` — `crypto/x509/x_pubkey.c:109-126`. The
/// `ASN1_EXTERN_FUNCS.asn1_ex_new_ex` hook.
///
/// # Safety
///
/// `pval` is a live slot; `libctx` is NULL or live and `propq` NULL or NUL-terminated.
unsafe extern "C" fn x509_pubkey_ex_new_ex(
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let mut ret = CRYPTO_zalloc(
        core::mem::size_of::<X509Pubkey>(),
        FILE.as_ptr(),
        LINE_ZALLOC_NEW_EX,
    )
    .cast::<X509Pubkey>();

    if ret.is_null() {
        return 0;
    }
    // SAFETY: `ret` is this call's own live object; `it` is unused by the helper.
    let populated =
        unsafe { x509_pubkey_ex_populate((&raw mut ret).cast::<*mut c_void>(), ptr::null()) } != 0;
    // SAFETY: `ret` is live and the two strings are the caller's.
    let ctx_set = unsafe { x509_pubkey_set0_libctx(ret, libctx, propq) } != 0;
    if !populated || !ctx_set {
        // SAFETY: `ret` is this call's own live object; the free hook takes its address.
        unsafe {
            x509_pubkey_ex_free((&raw mut ret).cast::<*mut c_void>(), ptr::null());
            ret = ptr::null_mut();
            raise_site(&err_sites::X509_PUBKEY_120);
        }
    } else {
        // SAFETY: `pval` is a live slot per the contract.
        unsafe { *pval = ret.cast::<c_void>() };
    }
    c_int::from(!ret.is_null())
}

/// `static int x509_pubkey_ex_d2i_ex(ASN1_VALUE **pval, const unsigned char **in, long len,
/// const ASN1_ITEM *it, int tag, int aclass, char opt, ASN1_TLC *ctx, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/x509/x_pubkey.c:128-239`. The
/// `ASN1_EXTERN_FUNCS.asn1_ex_d2i_ex` hook.
///
/// The legacy decode is tried **first** so an ENGINE-provided method is not overridden by a
/// provider; the `OSSL_DECODER` arm runs only when it did not answer and the object is not
/// forced legacy. Every error on the way is removed by `ERR_pop_to_mark` on the success path
/// and by `ERR_clear_last_mark` on each early exit, which is why the marks are part of the
/// transcription rather than bookkeeping.
///
/// # Safety
///
/// As the `asn1_ex_d2i_ex` hook type: `pval` a live slot, `in_` a readable cursor for `len`
/// bytes, `it` the item being decoded, `ctx` NULL or a live cache, `libctx` NULL or live and
/// `propq` NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)] // the hook type fixes the count
unsafe extern "C" fn x509_pubkey_ex_d2i_ex(
    pval: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
    opt: c_char,
    ctx: *mut Asn1Tlc,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `in_` is the caller's readable cursor.
    let in_saved = unsafe { *in_ };
    let mut ret: c_int;
    let mut dctx: *mut OsslDecoderCtx = ptr::null_mut();
    let mut tmpbuf: *mut c_uchar = ptr::null_mut();

    // SAFETY: `pval` is a live slot per the contract.
    if unsafe { *pval }.is_null()
        // SAFETY: `pval` is a live slot and the two strings are the caller's.
        && unsafe { x509_pubkey_ex_new_ex(pval, it, libctx, propq) } == 0
    {
        return 0;
    }
    // SAFETY: `pval` holds a live object; `it` is unused by the helper.
    if unsafe { x509_pubkey_ex_populate(pval, ptr::null()) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_144) };
        return 0;
    }

    // SAFETY: the caller's contract, and the dispatch's own signature.
    ret = unsafe {
        asn1_item_embed_d2i(
            pval,
            in_,
            len,
            x509_pubkey_internal_it(),
            tag,
            aclass,
            opt != 0,
            ctx,
            0,
            ptr::null_mut(),
            ptr::null(),
        )
    };
    if ret <= 0 {
        // SAFETY: `pval` holds the object this call built; `it` is unused by the free hook.
        unsafe { x509_pubkey_ex_free(pval, it) };
        return ret;
    }

    // SAFETY: `in_` is the caller's cursor and the decode advanced it.
    let publen = unsafe { (*in_).offset_from(in_saved) } as usize;
    if ossl_assert(publen > 0) == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_160) };
        return 0;
    }

    // SAFETY: `pval` holds the decoded object.
    let pubkey = unsafe { *pval }.cast::<X509Pubkey>();
    // SAFETY: `pubkey` is live; its `pkey` slot is a field.
    unsafe {
        EVP_PKEY_free((*pubkey).pkey);
        (*pubkey).pkey = ptr::null_mut();
    }

    ERR_set_mark();

    'body: {
        // SAFETY: `pubkey` is live and its `pkey` slot is writable.
        ret = unsafe { x509_pubkey_decode(&raw mut (*pubkey).pkey, pubkey) };
        if ret == -1 {
            ERR_clear_last_mark();
            break 'body;
        }

        // SAFETY: `pubkey` is live.
        let not_forced = unsafe { (*pubkey).flag_force_legacy } == 0;
        if ret <= 0 && not_forced {
            let mut in_data = in_saved;
            let slen = publen;

            if aclass != V_ASN1_UNIVERSAL {
                // SAFETY: `in_saved` is readable for `publen` bytes; the allocator takes the
                // file/line for its mdbg record only.
                tmpbuf = unsafe {
                    CRYPTO_memdup(
                        in_saved.cast::<c_void>(),
                        publen,
                        FILE.as_ptr(),
                        LINE_MEMDUP_D2I_EX,
                    )
                }
                .cast::<c_uchar>();
                if tmpbuf.is_null() {
                    return 0;
                }
                in_data = tmpbuf;
                // SAFETY: `tmpbuf` owns `publen` bytes, so the first is writable.
                unsafe { *tmpbuf = (V_ASN1_CONSTRUCTED | V_ASN1_SEQUENCE) as u8 };
            }

            let mut txtoidname = [0 as c_char; OSSL_MAX_NAME_SIZE];
            // SAFETY: `txtoidname` is this frame's buffer and `pubkey->algor->algorithm` is a
            // live OID read through the object.
            if unsafe {
                OBJ_obj2txt(
                    txtoidname.as_mut_ptr(),
                    OSSL_MAX_NAME_SIZE as c_int,
                    (*((*pubkey).algor)).algorithm,
                    0,
                )
            } <= 0
            {
                ERR_clear_last_mark();
                break 'body;
            }

            // SAFETY: `pubkey` is live; the three strings are the decoder's inputs and the
            // buffer is this frame's own, NUL-terminated by `OBJ_obj2txt`.
            dctx = unsafe {
                OSSL_DECODER_CTX_new_for_pkey(
                    &raw mut (*pubkey).pkey,
                    c"DER".as_ptr(),
                    c"SubjectPublicKeyInfo".as_ptr(),
                    txtoidname.as_ptr(),
                    EVP_PKEY_PUBLIC_KEY,
                    (*pubkey).libctx,
                    (*pubkey).propq,
                )
            };
            if !dctx.is_null() {
                let mut p = in_data;
                let mut consumed = slen;
                // SAFETY: `dctx` is live and the two locals are this frame's cursors.
                if unsafe { OSSL_DECODER_from_data(dctx, &raw mut p, &raw mut consumed) } != 0
                    && consumed != 0
                {
                    ERR_clear_last_mark();
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::X509_PUBKEY_227) };
                    break 'body;
                }
            }
        }

        ERR_pop_to_mark();
        ret = 1;
    }

    // SAFETY: `dctx` is NULL or a live context; `tmpbuf` is NULL or this call's own buffer.
    unsafe {
        OSSL_DECODER_CTX_free(dctx);
        CRYPTO_free(tmpbuf.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_TMPBUF);
    }
    ret
}

/// `static int x509_pubkey_ex_i2d(const ASN1_VALUE **pval, unsigned char **out,
/// const ASN1_ITEM *it, int tag, int aclass)` — `crypto/x509/x_pubkey.c:241-246`. The
/// `ASN1_EXTERN_FUNCS.asn1_ex_i2d` hook, one call to the internal item's encoder.
///
/// # Safety
///
/// As the hook type: `pval` points at a live value pointer, `out` is NULL or a writable
/// cursor.
unsafe extern "C" fn x509_pubkey_ex_i2d(
    pval: *mut *const c_void,
    out: *mut *mut c_uchar,
    _it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_ex_i2d(pval, out, x509_pubkey_internal_it(), tag, aclass) }
}

/// `static int x509_pubkey_ex_print(BIO *out, const ASN1_VALUE **pval, int indent,
/// const char *fname, const ASN1_PCTX *pctx)` — `crypto/x509/x_pubkey.c:248-253`. The
/// `ASN1_EXTERN_FUNCS.asn1_ex_print` hook.
///
/// # Safety
///
/// As the hook type: `out` a live BIO, `pval` a live value pointer, `pctx` NULL or live.
unsafe extern "C" fn x509_pubkey_ex_print(
    out: *mut Bio,
    pval: *mut *const c_void,
    indent: c_int,
    _fname: *const c_char,
    pctx: *const Asn1Pctx,
) -> c_int {
    // SAFETY: the caller's contract.
    let value = unsafe { *pval };
    // SAFETY: `out` is a live BIO and `value` is the live object.
    unsafe { ASN1_item_print(out, value, indent, x509_pubkey_internal_it(), pctx) }
}

/// `static const ASN1_EXTERN_FUNCS x509_pubkey_ff` — `crypto/x509/x_pubkey.c:255-265`.
///
/// Nine initialisers in the authority's order: `app_data` NULL, `asn1_ex_new` NULL,
/// `asn1_ex_free`/`asn1_ex_i2d`/`asn1_ex_print`/`asn1_ex_new_ex`/`asn1_ex_d2i_ex` set, and
/// `asn1_ex_clear` and `asn1_ex_d2i` zero. The four NULL/zero slots are the authority's own:
/// a cleared EXTERN value is a NULL pointer, which is why `asn1_ex_clear` is absent.
///
/// Wrapped for the reason [`crate::asn1::p8_pkey`]'s `SyncAux` is: an `ASN1_ITEM`'s `funcs`
/// points at a `static` whose `&` is shared by every decode, so the shared reference must be
/// sound. The fields are function pointers and a NULL `app_data`, none mutated through a
/// shared reference.
struct SyncExtern(Asn1ExternFuncs);

// SAFETY: as `Asn1Item`'s impl: the value is a `static` compiled from constants, its fields are
// scalars and function pointers, and no interior mutability is reachable through the shared
// reference the item's `funcs` slot takes.
unsafe impl Sync for SyncExtern {}

/// The `ASN1_EXTERN_FUNCS` block named above.
static X509_PUBKEY_FF: SyncExtern = SyncExtern(Asn1ExternFuncs {
    app_data: ptr::null_mut(),
    asn1_ex_new: None,
    asn1_ex_free: Some(x509_pubkey_ex_free),
    asn1_ex_clear: None,
    asn1_ex_d2i: None,
    asn1_ex_i2d: Some(x509_pubkey_ex_i2d),
    asn1_ex_print: Some(x509_pubkey_ex_print),
    asn1_ex_new_ex: Some(x509_pubkey_ex_new_ex),
    asn1_ex_d2i_ex: Some(x509_pubkey_ex_d2i_ex),
});

/// `X509_PUBKEY`'s descriptor — `IMPLEMENT_EXTERN_ASN1(X509_PUBKEY, V_ASN1_SEQUENCE,
/// x509_pubkey_ff)` at `crypto/x509/x_pubkey.c:267`.
///
/// `ASN1_ITYPE_EXTERN` with the tag `V_ASN1_SEQUENCE`, no templates, `tcount` 0, the hooks
/// above, `size` 0 and the name `X509_PUBKEY`.
static X509_PUBKEY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_EXTERN,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ptr::null(),
    tcount: 0,
    funcs: (&X509_PUBKEY_FF.0) as *const Asn1ExternFuncs as *const c_void,
    size: 0,
    sname: c"X509_PUBKEY".as_ptr(),
};

/// `const ASN1_ITEM *X509_PUBKEY_it(void)` — `include/openssl/x509.h:1460`.
#[no_mangle]
pub extern "C" fn X509_PUBKEY_it() -> *const Asn1Item {
    &X509_PUBKEY_ITEM
}

/// `X509_PUBKEY *X509_PUBKEY_new(void)` — `crypto/x509/x_pubkey.c:268`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_PUBKEY)`. For an `EXTERN` item this reaches
/// [`x509_pubkey_ex_new_ex`] with no library context.
#[no_mangle]
pub extern "C" fn X509_PUBKEY_new() -> *mut X509Pubkey {
    // SAFETY: `X509_PUBKEY_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_PUBKEY_it()).cast::<X509Pubkey>() }
}

/// `X509_PUBKEY *X509_PUBKEY_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/x_pubkey.c:270-280`.
///
/// # Safety
///
/// `libctx` is NULL or a live context and `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut X509Pubkey {
    // SAFETY: the item is a static the crate owns and the two strings are the caller's.
    let pubkey = unsafe { ASN1_item_new_ex(X509_PUBKEY_it(), libctx, propq) }.cast::<X509Pubkey>();
    // SAFETY: `pubkey` is NULL or live; the two strings are the caller's.
    if unsafe { x509_pubkey_set0_libctx(pubkey, libctx, propq) } == 0 {
        // SAFETY: `pubkey` is NULL or live.
        unsafe { X509_PUBKEY_free(pubkey) };
        return ptr::null_mut();
    }
    pubkey
}

/// `void X509_PUBKEY_free(X509_PUBKEY *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_free(a: *mut X509Pubkey) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), X509_PUBKEY_it()) }
}

/// `X509_PUBKEY *d2i_X509_PUBKEY(X509_PUBKEY **a, const unsigned char **in, long len)` —
/// `crypto/x509/x_pubkey.c:268`'s generated decoder.
///
/// For an `EXTERN` item the decode is entirely [`x509_pubkey_ex_d2i_ex`]'s, including the
/// opportunistic key decode.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the
/// input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_PUBKEY(
    a: *mut *mut X509Pubkey,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Pubkey {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_PUBKEY_it()).cast::<X509Pubkey>() }
}

/// `int i2d_X509_PUBKEY(const X509_PUBKEY *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_PUBKEY(a: *const X509Pubkey, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's enclosing `# Safety` section is the contract.
    unsafe { ASN1_item_i2d(a.cast::<c_void>(), out, X509_PUBKEY_it()) }
}

/// `X509_PUBKEY *X509_PUBKEY_dup(const X509_PUBKEY *a)` — `crypto/x509/x_pubkey.c:286-324`.
///
/// The authority implements this by hand because `ASN1_EXTERN_FUNCS` has no dup hook. The
/// recovered-pkey arm sets `flag_force_legacy` when `EVP_PKEY_dup` fails and re-decodes from the
/// copied algorithm and bit string, which is why the flag is written before the decode.
///
/// # Safety
///
/// `a` is NULL or a live object.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_dup(a: *const X509Pubkey) -> *mut X509Pubkey {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let mut pubkey = CRYPTO_zalloc(
        core::mem::size_of::<X509Pubkey>(),
        FILE.as_ptr(),
        LINE_ZALLOC_DUP,
    )
    .cast::<X509Pubkey>();

    if pubkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `a` is live per the contract.
    let (a_libctx, a_propq, a_algor, a_pubkey, a_pkey) = unsafe {
        (
            (*a).libctx,
            (*a).propq,
            (*a).algor,
            (*a).public_key,
            (*a).pkey,
        )
    };
    // SAFETY: `pubkey` is this call's own live object; the two strings are `a`'s, borrowed.
    if unsafe { x509_pubkey_set0_libctx(pubkey, a_libctx, a_propq) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_293) };
        // SAFETY: `pubkey` is this call's own live object.
        unsafe { x509_pubkey_ex_free((&raw mut pubkey).cast::<*mut c_void>(), ptr::null()) };
        return ptr::null_mut();
    }
    // SAFETY: `a` is live, so its two members are readable.
    unsafe {
        (*pubkey).algor = X509_ALGOR_dup(a_algor);
        (*pubkey).public_key = ASN1_BIT_STRING_new();
        if (*pubkey).algor.is_null()
            || (*pubkey).public_key.is_null()
            || ASN1_BIT_STRING_set((*pubkey).public_key, (*a_pubkey).data, (*a_pubkey).length) == 0
        {
            // SAFETY: `pubkey` is this call's own live object.
            x509_pubkey_ex_free((&raw mut pubkey).cast::<*mut c_void>(), ptr::null());
            raise_site(&err_sites::X509_PUBKEY_305);
            return ptr::null_mut();
        }
    }

    if !a_pkey.is_null() {
        ERR_set_mark();
        // SAFETY: `a_pkey` is live per `a`'s contract.
        let dup = unsafe { EVP_PKEY_dup(a_pkey) };
        // SAFETY: `pubkey` is this call's own live object.
        unsafe { (*pubkey).pkey = dup };
        if dup.is_null() {
            // SAFETY: `pubkey` is this call's own live object.
            unsafe { (*pubkey).flag_force_legacy = 1 };
            // SAFETY: `pubkey` is live and its `pkey` slot is writable.
            if unsafe { x509_pubkey_decode(&raw mut (*pubkey).pkey, pubkey) } <= 0 {
                // SAFETY: `pubkey` is this call's own live object.
                unsafe {
                    x509_pubkey_ex_free((&raw mut pubkey).cast::<*mut c_void>(), ptr::null());
                }
                ERR_clear_last_mark();
                return ptr::null_mut();
            }
        }
        ERR_pop_to_mark();
    }
    pubkey
}

/// `int X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey)` — `crypto/x509/x_pubkey.c:326-397`.
///
/// Two ways in: a legacy key with a method goes through `ameth->pub_encode`, and a provider key
/// through the `SubjectPublicKeyInfo` encoder. The passed key is adopted **by reference** — the
/// object's own freshly-decoded copy is thrown away so a caller that depends on the passed
/// instance gets it back — which is why the `pk->pkey != NULL` test is there.
///
/// # Safety
///
/// `x` is NULL or a live `X509_PUBKEY *` slot; `pkey` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_set(x: *mut *mut X509Pubkey, pkey: *mut EvpPkey) -> c_int {
    let mut pk: *mut X509Pubkey = ptr::null_mut();

    if x.is_null() || pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_331) };
        return 0;
    }

    // SAFETY: `pkey` is live per the contract.
    let ameth = unsafe { (*pkey).ameth };
    if !ameth.is_null() {
        // SAFETY: no preconditions; the constructor builds through the item.
        pk = X509_PUBKEY_new();
        if pk.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_PUBKEY_337) };
            // SAFETY: `pk` and `x` are this call's and the caller's.
            return unsafe { set_err_out(pk, x) };
        }
        // SAFETY: `ameth` is the key's own live method table.
        let pub_encode = unsafe { (*ameth).pub_encode };
        match pub_encode {
            Some(enc) => {
                // SAFETY: the callback is the key's own, with the authority's signature.
                if unsafe { enc(pk, pkey) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::X509_PUBKEY_342) };
                    // SAFETY: `pk` and `x` are this call's and the caller's.
                    return unsafe { set_err_out(pk, x) };
                }
            }
            None => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::X509_PUBKEY_346) };
                // SAFETY: `pk` and `x` are this call's and the caller's.
                return unsafe { set_err_out(pk, x) };
            }
        }
        // SAFETY: `pkey` is live per the contract.
    } else if unsafe { evp_pkey_is_provided(pkey) } != 0 {
        let mut der: *mut u8 = ptr::null_mut();
        let mut derlen: usize = 0;
        // SAFETY: `pkey` is live and the three strings are literals.
        let ectx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                pkey,
                EVP_PKEY_PUBLIC_KEY,
                c"DER".as_ptr(),
                c"SubjectPublicKeyInfo".as_ptr(),
                ptr::null(),
            )
        };

        // SAFETY: `ectx` is NULL or live; the two locals are writable.
        if unsafe { OSSL_ENCODER_to_data(ectx, &raw mut der, &raw mut derlen) } != 0 {
            // SAFETY: `der` owns `derlen` bytes.
            let mut pder: *const c_uchar = der;
            // SAFETY: `pder` is a readable cursor for `derlen` bytes.
            pk = unsafe { d2i_X509_PUBKEY(ptr::null_mut(), &raw mut pder, derlen as c_long) };
        }

        // SAFETY: `ectx` is NULL or live; `der` is NULL or this call's own.
        unsafe {
            OSSL_ENCODER_CTX_free(ectx);
            CRYPTO_free(der.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_DER);
        }
    }

    if pk.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_367) };
        // SAFETY: `pk` and `x` are this call's and the caller's.
        return unsafe { set_err_out(pk, x) };
    }

    // SAFETY: `x` is a live slot and `*x` is NULL or a live object; `pk` is this call's own.
    unsafe {
        X509_PUBKEY_free(*x);
        if EVP_PKEY_up_ref(pkey) == 0 {
            raise_site(&err_sites::X509_PUBKEY_373);
            return set_err_out(pk, x);
        }
        *x = pk;

        if !(*pk).pkey.is_null() {
            EVP_PKEY_free((*pk).pkey);
        }
        (*pk).pkey = pkey;
    }
    1
}

/// The authority's `error:` label of [`X509_PUBKEY_set`] — `x_pubkey.c:394-396`.
///
/// # Safety
///
/// `pk` is NULL or a live object this call owns; `x` is the caller's live slot.
unsafe fn set_err_out(pk: *mut X509Pubkey, _x: *mut *mut X509Pubkey) -> c_int {
    // SAFETY: `pk` is NULL or this call's own live object.
    unsafe { X509_PUBKEY_free(pk) };
    0
}

/// `static int x509_pubkey_decode(EVP_PKEY **ppkey, const X509_PUBKEY *key)` —
/// `crypto/x509/x_pubkey.c:406-455`.
///
/// Returns 1 on success, 0 on a decode failure and -1 on a fatal error. The non-forced-legacy
/// path is the authority's `ENGINE_get_pkey_meth_engine` test; ENGINE is Phase 13's, the crate
/// carries none, and no built-in type has an engine-provided method, so that path answers 0 —
/// which is exactly what the authority answers when no ENGINE is registered for the method.
///
/// On the forced-legacy path the method's `pub_decode` reads the algorithm and the bit string
/// off `key`, and a method with no `pub_decode` raises `X509_R_METHOD_NOT_SUPPORTED`.
///
/// # Safety
///
/// `ppkey` is a live `EVP_PKEY *` slot; `key` is a live `X509_PUBKEY`.
unsafe fn x509_pubkey_decode(ppkey: *mut *mut EvpPkey, key: *const X509Pubkey) -> c_int {
    // SAFETY: `key` is live per the contract.
    let nid = unsafe { OBJ_obj2nid((*(*key).algor).algorithm) };
    // SAFETY: `key` is live.
    if unsafe { (*key).flag_force_legacy } == 0 {
        /* The authority reaches `ENGINE_get_pkey_meth_engine` here and answers 0 when it finds
         * none; ENGINE is Phase 13's and this crate has none, so the answer is 0. */
        return 0;
    }

    // SAFETY: no preconditions.
    let pkey = unsafe { EVP_PKEY_new() };
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_427) };
        return -1;
    }

    // SAFETY: `pkey` is live and `nid` is an integer.
    if unsafe { EVP_PKEY_set_type(pkey, nid) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_432) };
        // SAFETY: `pkey` is this call's own live key.
        unsafe { EVP_PKEY_free(pkey) };
        return 0;
    }

    // SAFETY: `pkey` is live and `EVP_PKEY_set_type` above succeeded, so its `ameth` is set.
    let ameth = unsafe { (*pkey).ameth };
    // SAFETY: `ameth` is the key's own method table.
    let pub_decode = unsafe { (*ameth).pub_decode };
    match pub_decode {
        Some(dec) => {
            // SAFETY: the callback is the key's own; `key` is the caller's live object.
            if unsafe { dec(pkey, key) } == 0 {
                // SAFETY: `pkey` is this call's own live key.
                unsafe { EVP_PKEY_free(pkey) };
                return 0;
            }
        }
        None => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_PUBKEY_445) };
            // SAFETY: `pkey` is this call's own live key.
            unsafe { EVP_PKEY_free(pkey) };
            return 0;
        }
    }

    // SAFETY: `ppkey` is a live slot per the contract.
    unsafe { *ppkey = pkey };
    1
}

/// `EVP_PKEY *X509_PUBKEY_get0(const X509_PUBKEY *key)` — `crypto/x509/x_pubkey.c:457-471`.
///
/// The borrowed answer, and it is NULL with a raise when the object never decoded a key.
///
/// # Safety
///
/// `key` is NULL or a live object.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_get0(key: *const X509Pubkey) -> *mut EvpPkey {
    if key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_460) };
        return ptr::null_mut();
    }
    // SAFETY: `key` is live per the contract.
    let pkey = unsafe { (*key).pkey };
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_466) };
        return ptr::null_mut();
    }
    pkey
}

/// `EVP_PKEY *X509_PUBKEY_get(const X509_PUBKEY *key)` — `crypto/x509/x_pubkey.c:473-482`.
///
/// # Safety
///
/// `key` is NULL or a live object.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_get(key: *const X509Pubkey) -> *mut EvpPkey {
    // SAFETY: `key` is NULL or live per the contract.
    let mut ret = unsafe { X509_PUBKEY_get0(key) };
    if !ret.is_null()
        // SAFETY: `ret` is live.
        && unsafe { EVP_PKEY_up_ref(ret) } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_478) };
        ret = ptr::null_mut();
    }
    ret
}

/// `static EVP_PKEY *d2i_PUBKEY_int(EVP_PKEY **a, const unsigned char **pp, long length,
/// OSSL_LIB_CTX *libctx, const char *propq, unsigned int force_legacy,
/// X509_PUBKEY *(*d2i_x509_pubkey)(X509_PUBKEY **a, const unsigned char **in, long len))` —
/// `crypto/x509/x_pubkey.c:488-532`.
///
/// The three public `d2i_PUBKEY*` routines and `ossl_d2i_PUBKEY_legacy` are this one body with
/// different arguments; the decoder is passed in so the legacy entry can force the object's
/// `flag_force_legacy` while still using `d2i_X509_PUBKEY`.
///
/// The reuse feature is why the object is allocated and configured **before** the decode when
/// `libctx`/`propq`/`force_legacy` are set: the item's decode fills the same storage the
/// configuration wrote, and the two leading columns are the only fields it overwrites.
///
/// # Safety
///
/// `a` is NULL or a writable key slot; `pp` points at a readable cursor for `length` bytes;
/// `libctx` is NULL or live and `propq` NULL or NUL-terminated; `d2i_x509_pubkey` is a live
/// decoder.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(non_snake_case)] // the authority's own spelling, as `src/evp/pkey_ctx.rs` keeps `EVP_PKEY_*`.
unsafe fn d2i_PUBKEY_int(
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
    force_legacy: c_uint,
    d2i_x509_pubkey: unsafe extern "C" fn(
        *mut *mut X509Pubkey,
        *mut *const c_uchar,
        c_long,
    ) -> *mut X509Pubkey,
) -> *mut EvpPkey {
    let mut xpk2: *mut X509Pubkey = ptr::null_mut();
    let mut pxpk: *mut *mut X509Pubkey = ptr::null_mut();
    // SAFETY: `pp` is the caller's readable cursor.
    let mut q = unsafe { *pp };

    if !libctx.is_null() || !propq.is_null() || force_legacy != 0 {
        // SAFETY: the allocator takes the file/line for its mdbg record only.
        xpk2 = CRYPTO_zalloc(
            core::mem::size_of::<X509Pubkey>(),
            FILE.as_ptr(),
            LINE_ZALLOC_D2I_INT,
        )
        .cast::<X509Pubkey>();
        if xpk2.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `xpk2` is this call's own live object; the two strings are the caller's.
        if unsafe { x509_pubkey_set0_libctx(xpk2, libctx, propq) } == 0 {
            // SAFETY: `xpk2` and `a` are this call's and the caller's.
            return unsafe { d2i_pubkey_err_out(xpk2, a) };
        }
        // SAFETY: `xpk2` is this call's own live object.
        unsafe { (*xpk2).flag_force_legacy = c_uint::from(force_legacy != 0) };
        pxpk = &raw mut xpk2;
    }
    // SAFETY: `pxpk` is NULL or this frame's writable slot; `q` is this frame's cursor.
    let xpk = unsafe { d2i_x509_pubkey(pxpk, &raw mut q, length) };
    if xpk.is_null() {
        // SAFETY: `xpk2` and `a` are this call's and the caller's.
        return unsafe { d2i_pubkey_err_out(xpk2, a) };
    }
    // SAFETY: `xpk` is live.
    let pktmp = unsafe { X509_PUBKEY_get(xpk) };
    // SAFETY: `xpk` is this call's own live object.
    unsafe { X509_PUBKEY_free(xpk) };
    xpk2 = ptr::null_mut(); /* We know that xpk == xpk2 */
    if pktmp.is_null() {
        // SAFETY: `xpk2` is NULL here and `a` is the caller's.
        return unsafe { d2i_pubkey_err_out(xpk2, a) };
    }
    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = q };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe {
            EVP_PKEY_free(*a);
            *a = pktmp;
        }
    }
    // SAFETY: `xpk2` is NULL here.
    unsafe { d2i_pubkey_err_out(xpk2, a) };
    pktmp
}

/// The authority's `end:` label of [`d2i_PUBKEY_int`] — `x_pubkey.c:529-531`.
///
/// # Safety
///
/// `xpk2` is NULL or a live object this call owns; `a` is the caller's key slot.
unsafe fn d2i_pubkey_err_out(xpk2: *mut X509Pubkey, _a: *mut *mut EvpPkey) -> *mut EvpPkey {
    // SAFETY: `xpk2` is NULL or this call's own live object.
    unsafe { X509_PUBKEY_free(xpk2) };
    ptr::null_mut()
}

/// `EVP_PKEY *ossl_d2i_PUBKEY_legacy(EVP_PKEY **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_pubkey.c:535-539`. Internal (`include/crypto/x509.h`), and the last callee
/// `crypto/pem/pem_pkey.c`'s `pem_read_bio_key_legacy` was missing.
///
/// # Safety
///
/// `a` is NULL or a writable key slot; `pp` points at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_d2i_PUBKEY_legacy(
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe {
        d2i_PUBKEY_int(
            a,
            pp,
            length,
            ptr::null_mut(),
            ptr::null(),
            1,
            d2i_X509_PUBKEY,
        )
    }
}

/// `EVP_PKEY *d2i_PUBKEY_ex(EVP_PKEY **a, const unsigned char **pp, long length,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/x509/x_pubkey.c:541-545`.
///
/// # Safety
///
/// `a` is NULL or a writable key slot; `pp` points at a readable cursor for `length` bytes;
/// `libctx` is NULL or live and `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn d2i_PUBKEY_ex(
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe { d2i_PUBKEY_int(a, pp, length, libctx, propq, 0, d2i_X509_PUBKEY) }
}

/// `EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_pubkey.c:547-550`.
///
/// # Safety
///
/// `a` is NULL or a writable key slot; `pp` points at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_PUBKEY(
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut EvpPkey {
    // SAFETY: the caller's contract.
    unsafe { d2i_PUBKEY_ex(a, pp, length, ptr::null_mut(), ptr::null()) }
}

/// `int i2d_PUBKEY(const EVP_PKEY *a, unsigned char **pp)` — `crypto/x509/x_pubkey.c:552-600`.
///
/// The legacy arm calls `pub_encode` and encodes through the item; the provider arm goes through
/// the encoder into a memory BIO. On the provider path the ownership rule is the authority's:
/// when `*pp` is NULL the buffer is **transferred** to the caller and the BIO's is cleared,
/// otherwise the caller's buffer is written and advanced.
///
/// # Safety
///
/// `a` is NULL or a live key; `pp` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PUBKEY(a: *const EvpPkey, pp: *mut *mut c_uchar) -> c_int {
    let mut ret: c_int = -1;

    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live per the contract.
    let ameth = unsafe { (*a).ameth };
    // SAFETY: `a` is live per the contract.
    let has_keymgmt = !unsafe { (*a).keymgmt }.is_null();
    if !ameth.is_null() {
        // SAFETY: no preconditions; the constructor builds through the item.
        let xpk = X509_PUBKEY_new();
        if xpk.is_null() {
            return -1;
        }

        /* `pub_encode()` only encodes parameters, not the key itself. */
        // SAFETY: `ameth` is the key's own live method table.
        let pub_encode = unsafe { (*ameth).pub_encode };
        if let Some(enc) = pub_encode {
            // SAFETY: the callback is the key's own; `xpk` and `a` are live.
            if unsafe { enc(xpk, a) } != 0 {
                // SAFETY: `xpk` is this call's own live object; `a` is a borrowed key.
                unsafe {
                    (*xpk).pkey = a as *mut EvpPkey;
                    ret = i2d_X509_PUBKEY(xpk, pp);
                    (*xpk).pkey = ptr::null_mut();
                }
            }
        }
        // SAFETY: `xpk` is this call's own live object.
        unsafe { X509_PUBKEY_free(xpk) };
    } else if has_keymgmt {
        // SAFETY: `a` is live and the three strings are literals.
        let ctx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                a,
                EVP_PKEY_PUBLIC_KEY,
                c"DER".as_ptr(),
                c"SubjectPublicKeyInfo".as_ptr(),
                ptr::null(),
            )
        };
        // SAFETY: `BIO_s_mem` answers a static method.
        let out = unsafe { BIO_new(BIO_s_mem()) };
        let mut buf: *mut BufMem = ptr::null_mut();

        // SAFETY: `ctx` is NULL or live; `out` is NULL or live.
        if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } != 0
            && !out.is_null()
            // SAFETY: `ctx` is live and `out` is a live BIO.
            && unsafe { OSSL_ENCODER_to_bio(ctx, out) } != 0
            // SAFETY: `out` is a live memory BIO and `buf` is this frame's slot.
            && unsafe {
                BIO_ctrl(
                    out,
                    BIO_C_GET_BUF_MEM_PTR,
                    0,
                    (&raw mut buf).cast::<c_void>(),
                )
            } > 0
        {
            // SAFETY: `buf` is the memory BIO's own `BUF_MEM`, kept alive by `out`.
            ret = unsafe { (*buf).length } as c_int;

            if !pp.is_null() {
                // SAFETY: `buf` is live; `pp` is the caller's writable cursor.
                unsafe {
                    if (*pp).is_null() {
                        *pp = (*buf).data.cast::<u8>();
                        (*buf).length = 0;
                        (*buf).data = ptr::null_mut();
                    } else {
                        ptr::copy_nonoverlapping((*buf).data.cast::<u8>(), *pp, ret as usize);
                        *pp = (*pp).add(ret as usize);
                    }
                }
            }
        }
        // SAFETY: `out` is NULL or a live BIO this call owns; `ctx` is NULL or live.
        unsafe {
            BIO_free(out);
            OSSL_ENCODER_CTX_free(ctx);
        }
    }

    ret
}

/// `RSA *d2i_RSA_PUBKEY(RSA **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_pubkey.c:605-625`.
///
/// The legacy decode first, then `EVP_PKEY_get1_RSA`; the cursor is advanced only after both
/// answered, so a failure leaves `*pp` where it was.
///
/// # Safety
///
/// `a` is NULL or a writable `RSA *` slot; `pp` points at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSA_PUBKEY(
    a: *mut *mut Rsa,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut Rsa {
    // SAFETY: `pp` is the caller's readable cursor.
    let mut q = unsafe { *pp };
    // SAFETY: `q` is this frame's cursor.
    let pkey = unsafe { ossl_d2i_PUBKEY_legacy(ptr::null_mut(), &raw mut q, length) };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pkey` is live.
    let key = unsafe { EVP_PKEY_get1_RSA(pkey) };
    // SAFETY: `pkey` is this call's own live key.
    unsafe { EVP_PKEY_free(pkey) };
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = q };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe {
            RSA_free(*a);
            *a = key;
        }
    }
    key
}

/// `int i2d_RSA_PUBKEY(const RSA *a, unsigned char **pp)` — `crypto/x509/x_pubkey.c:627-643`.
///
/// # Safety
///
/// `a` is NULL or a live `RSA`; `pp` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSA_PUBKEY(a: *const Rsa, pp: *mut *mut c_uchar) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let pktmp = unsafe { EVP_PKEY_new() };
    if pktmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_635) };
        return -1;
    }
    /* `EVP_PKEY_assign_RSA(pktmp, (RSA *)a)` — `EVP_PKEY_assign` is what the macro expands to. */
    // SAFETY: `pktmp` is live and `a` is the key being wrapped; the return is deliberately
    // discarded, exactly as the authority's `(void)` cast does.
    unsafe { EVP_PKEY_assign(pktmp, EVP_PKEY_RSA, a as *mut c_void) };
    // SAFETY: `pktmp` is live.
    let ret = unsafe { i2d_PUBKEY(pktmp, pp) };
    // SAFETY: `pktmp` is live; the key is borrowed, so the union member is cleared before free.
    unsafe {
        (*pktmp).pkey = ptr::null_mut();
        EVP_PKEY_free(pktmp);
    }
    ret
}

/// `DH *ossl_d2i_DH_PUBKEY(DH **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_pubkey.c:646-667`. Internal, and it refuses a key whose id is not
/// `EVP_PKEY_DH`.
///
/// # Safety
///
/// `a` is NULL or a writable `DH *` slot; `pp` points at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_d2i_DH_PUBKEY(
    a: *mut *mut Dh,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut Dh {
    // SAFETY: `pp` is the caller's readable cursor.
    let mut q = unsafe { *pp };
    // SAFETY: `q` is this frame's cursor.
    let pkey = unsafe { ossl_d2i_PUBKEY_legacy(ptr::null_mut(), &raw mut q, length) };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    let mut key: *mut Dh = ptr::null_mut();
    // SAFETY: `pkey` is live.
    if unsafe { EVP_PKEY_get_id(pkey) } == EVP_PKEY_DH {
        // SAFETY: `pkey` is live.
        key = unsafe { EVP_PKEY_get1_DH(pkey) };
    }
    // SAFETY: `pkey` is this call's own live key.
    unsafe { EVP_PKEY_free(pkey) };
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = q };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe {
            DH_free(*a);
            *a = key;
        }
    }
    key
}

/// `int ossl_i2d_DH_PUBKEY(const DH *a, unsigned char **pp)` —
/// `crypto/x509/x_pubkey.c:669-685`.
///
/// # Safety
///
/// `a` is NULL or a live `DH`; `pp` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn ossl_i2d_DH_PUBKEY(a: *const Dh, pp: *mut *mut c_uchar) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let pktmp = unsafe { EVP_PKEY_new() };
    if pktmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_677) };
        return -1;
    }
    /* `EVP_PKEY_assign_DH(pktmp, (DH *)a)`. */
    // SAFETY: `pktmp` is live and `a` is the key being wrapped; the return is discarded.
    unsafe { EVP_PKEY_assign(pktmp, EVP_PKEY_DH, a as *mut c_void) };
    // SAFETY: `pktmp` is live.
    let ret = unsafe { i2d_PUBKEY(pktmp, pp) };
    // SAFETY: `pktmp` is live; the borrowed member is cleared before free.
    unsafe {
        (*pktmp).pkey = ptr::null_mut();
        EVP_PKEY_free(pktmp);
    }
    ret
}

/// `DH *ossl_d2i_DHx_PUBKEY(DH **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_pubkey.c:687-708`. The `EVP_PKEY_DHX` twin of [`ossl_d2i_DH_PUBKEY`].
///
/// # Safety
///
/// `a` is NULL or a writable `DH *` slot; `pp` points at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_d2i_DHx_PUBKEY(
    a: *mut *mut Dh,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut Dh {
    // SAFETY: `pp` is the caller's readable cursor.
    let mut q = unsafe { *pp };
    // SAFETY: `q` is this frame's cursor.
    let pkey = unsafe { ossl_d2i_PUBKEY_legacy(ptr::null_mut(), &raw mut q, length) };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    let mut key: *mut Dh = ptr::null_mut();
    // SAFETY: `pkey` is live.
    if unsafe { EVP_PKEY_get_id(pkey) } == EVP_PKEY_DHX {
        // SAFETY: `pkey` is live.
        key = unsafe { EVP_PKEY_get1_DH(pkey) };
    }
    // SAFETY: `pkey` is this call's own live key.
    unsafe { EVP_PKEY_free(pkey) };
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = q };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe {
            DH_free(*a);
            *a = key;
        }
    }
    key
}

/// `int ossl_i2d_DHx_PUBKEY(const DH *a, unsigned char **pp)` —
/// `crypto/x509/x_pubkey.c:710-726`. The authority spells the assignment
/// `EVP_PKEY_assign(pktmp, EVP_PKEY_DHX, (DH *)a)` here rather than the `_DH` macro.
///
/// # Safety
///
/// `a` is NULL or a live `DH`; `pp` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn ossl_i2d_DHx_PUBKEY(a: *const Dh, pp: *mut *mut c_uchar) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let pktmp = unsafe { EVP_PKEY_new() };
    if pktmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_718) };
        return -1;
    }
    // SAFETY: `pktmp` is live and `a` is the key being wrapped; the return is discarded.
    unsafe { EVP_PKEY_assign(pktmp, EVP_PKEY_DHX, a as *mut c_void) };
    // SAFETY: `pktmp` is live.
    let ret = unsafe { i2d_PUBKEY(pktmp, pp) };
    // SAFETY: `pktmp` is live; the borrowed member is cleared before free.
    unsafe {
        (*pktmp).pkey = ptr::null_mut();
        EVP_PKEY_free(pktmp);
    }
    ret
}

/// `DSA *d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_pubkey.c:730-750`.
///
/// # Safety
///
/// `a` is NULL or a writable `DSA *` slot; `pp` points at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_DSA_PUBKEY(
    a: *mut *mut Dsa,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut Dsa {
    // SAFETY: `pp` is the caller's readable cursor.
    let mut q = unsafe { *pp };
    // SAFETY: `q` is this frame's cursor.
    let pkey = unsafe { ossl_d2i_PUBKEY_legacy(ptr::null_mut(), &raw mut q, length) };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pkey` is live.
    let key = unsafe { EVP_PKEY_get1_DSA(pkey) };
    // SAFETY: `pkey` is this call's own live key.
    unsafe { EVP_PKEY_free(pkey) };
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = q };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe {
            DSA_free(*a);
            *a = key;
        }
    }
    key
}

/// `DSA *ossl_d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_pubkey.c:753-774`. "Called from decoders; disallows provided DSA keys without
/// parameters": a key whose `p`/`q`/`g` are not all present is freed and refused, and the
/// cursor is not advanced.
///
/// # Safety
///
/// `a` is NULL or a writable `DSA *` slot; `pp` points at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_d2i_DSA_PUBKEY(
    a: *mut *mut Dsa,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut Dsa {
    // SAFETY: `pp` is the caller's readable cursor.
    let mut data = unsafe { *pp };
    // SAFETY: `data` is this frame's cursor.
    let key = unsafe { d2i_DSA_PUBKEY(ptr::null_mut(), &raw mut data, length) };
    if key.is_null() {
        return ptr::null_mut();
    }
    let mut p: *const BigNum = ptr::null();
    let mut q: *const BigNum = ptr::null();
    let mut g: *const BigNum = ptr::null();
    // SAFETY: `key` is live and the three out-pointers are writable.
    unsafe { DSA_get0_pqg(key, &raw mut p, &raw mut q, &raw mut g) };
    if p.is_null() || q.is_null() || g.is_null() {
        // SAFETY: `key` is this call's own live key.
        unsafe { DSA_free(key) };
        return ptr::null_mut();
    }
    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = data };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe {
            DSA_free(*a);
            *a = key;
        }
    }
    key
}

/// `int i2d_DSA_PUBKEY(const DSA *a, unsigned char **pp)` — `crypto/x509/x_pubkey.c:776-792`.
///
/// # Safety
///
/// `a` is NULL or a live `DSA`; `pp` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_DSA_PUBKEY(a: *const Dsa, pp: *mut *mut c_uchar) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let pktmp = unsafe { EVP_PKEY_new() };
    if pktmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_784) };
        return -1;
    }
    /* `EVP_PKEY_assign_DSA(pktmp, (DSA *)a)`. */
    // SAFETY: `pktmp` is live and `a` is the key being wrapped; the return is discarded.
    unsafe { EVP_PKEY_assign(pktmp, EVP_PKEY_DSA, a as *mut c_void) };
    // SAFETY: `pktmp` is live.
    let ret = unsafe { i2d_PUBKEY(pktmp, pp) };
    // SAFETY: `pktmp` is live; the borrowed member is cleared before free.
    unsafe {
        (*pktmp).pkey = ptr::null_mut();
        EVP_PKEY_free(pktmp);
    }
    ret
}

/// `EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length)` —
/// `crypto/x509/x_pubkey.c:796-819`. The id test accepts both `EVP_PKEY_EC` and
/// `EVP_PKEY_SM2`, which is the only difference from the RSA/DSA siblings.
///
/// # Safety
///
/// `a` is NULL or a writable `EC_KEY *` slot; `pp` points at a readable cursor for `length`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_EC_PUBKEY(
    a: *mut *mut EcKey,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut EcKey {
    // SAFETY: `pp` is the caller's readable cursor.
    let mut q = unsafe { *pp };
    // SAFETY: `q` is this frame's cursor.
    let pkey = unsafe { ossl_d2i_PUBKEY_legacy(ptr::null_mut(), &raw mut q, length) };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    let mut key: *mut EcKey = ptr::null_mut();
    // SAFETY: `pkey` is live.
    let type_ = unsafe { EVP_PKEY_get_id(pkey) };
    if type_ == EVP_PKEY_EC || type_ == EVP_PKEY_SM2 {
        // SAFETY: `pkey` is live.
        key = unsafe { EVP_PKEY_get1_EC_KEY(pkey) };
    }
    // SAFETY: `pkey` is this call's own live key.
    unsafe { EVP_PKEY_free(pkey) };
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pp` is the caller's writable cursor.
    unsafe { *pp = q };
    if !a.is_null() {
        // SAFETY: `a` is a live slot.
        unsafe {
            EC_KEY_free(*a);
            *a = key;
        }
    }
    key
}

/// `int i2d_EC_PUBKEY(const EC_KEY *a, unsigned char **pp)` — `crypto/x509/x_pubkey.c:821-837`.
///
/// # Safety
///
/// `a` is NULL or a live `EC_KEY`; `pp` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_EC_PUBKEY(a: *const EcKey, pp: *mut *mut c_uchar) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let pktmp = unsafe { EVP_PKEY_new() };
    if pktmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_PUBKEY_829) };
        return -1;
    }
    /* `EVP_PKEY_assign_EC_KEY(pktmp, (EC_KEY *)a)`. */
    // SAFETY: `pktmp` is live and `a` is the key being wrapped; the return is discarded.
    unsafe { EVP_PKEY_assign(pktmp, EVP_PKEY_EC, a as *mut c_void) };
    // SAFETY: `pktmp` is live.
    let ret = unsafe { i2d_PUBKEY(pktmp, pp) };
    // SAFETY: `pktmp` is live; the borrowed member is cleared before free.
    unsafe {
        (*pktmp).pkey = ptr::null_mut();
        EVP_PKEY_free(pktmp);
    }
    ret
}

// ---------------------------------------------------------------------------------------------
// The accessors D349 landed, and the remaining `X509_PUBKEY` reader
// ---------------------------------------------------------------------------------------------

/// `void X509_PUBKEY_set0_public_key(X509_PUBKEY *pub, unsigned char *penc, int penclen)`
/// — `crypto/x509/x_pubkey.c:1010-1015`.
///
/// The bit string adopts `penc`, and `ossl_asn1_string_set_bits_left(..., 0)` records that
/// its last octet is whole. The authority does not test `pub` or `penc` for NULL; a caller
/// that does is [`X509_PUBKEY_set0_param`], which may be handed a NULL `penc` and skips this
/// call.
///
/// # Safety
///
/// `pub` is a live `X509_PUBKEY` whose `public_key` is live; `penc` is NULL or a buffer of
/// `penclen` bytes the caller transfers ownership of.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_set0_public_key(
    pub_: *mut X509Pubkey,
    penc: *mut u8,
    penclen: c_int,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for both reads.
    unsafe {
        ASN1_STRING_set0((*pub_).public_key, penc.cast::<c_void>(), penclen);
        set_bits_left((*pub_).public_key, 0);
    }
}

/// `int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj, int ptype, void *pval,
/// unsigned char *penc, int penclen)` — `crypto/x509/x_pubkey.c:1017-1026`.
///
/// The algorithm is set first and owns the decision: a failed `X509_ALGOR_set0` leaves the
/// bit string untouched and answers 0. A NULL `penc` means "keep the existing bit string",
/// which is why the second call is guarded rather than unconditional.
///
/// # Safety
///
/// `pub` is a live `X509_PUBKEY` with live `algor` and `public_key` members; `aobj` and
/// `pval` are the values `X509_ALGOR_set0` may adopt; `penc` is NULL or a buffer of
/// `penclen` bytes transferred to the object.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_set0_param(
    pub_: *mut X509Pubkey,
    aobj: *mut Asn1Object,
    ptype: c_int,
    pval: *mut c_void,
    penc: *mut u8,
    penclen: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        if X509_ALGOR_set0((*pub_).algor, aobj, ptype, pval) == 0 {
            return 0;
        }
        if !penc.is_null() {
            X509_PUBKEY_set0_public_key(pub_, penc, penclen);
        }
    }
    1
}

/// `int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen,
/// X509_ALGOR **pa, const X509_PUBKEY *pub)` — `crypto/x509/x_pubkey.c:1028-1041`.
///
/// Each of the four out-parameters is optional and independently skipped. `ppkalg` is
/// `ASN1_OBJECT **`, **not** `const ASN1_OBJECT **` — the authority writes a non-const
/// pointer through it, and the `const` on the two `get0` answers below is the *caller's*
/// reading, not this signature's. The bit string's answer is its `data`/`length` pair
/// **borrowed**, which is the authority's `get0` naming and what a caller must not free.
///
/// # Safety
///
/// `pub` is a live `X509_PUBKEY` whose `algor` and `public_key` are live. Each out-pointer
/// is NULL or writable for its type; `ppkalg` receives a borrowed OID, `pk` a borrowed
/// buffer of `*ppklen` bytes, `pa` a borrowed identifier.
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_get0_param(
    ppkalg: *mut *mut Asn1Object,
    pk: *mut *const u8,
    ppklen: *mut c_int,
    pa: *mut *mut X509Algor,
    pub_: *const X509Pubkey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read and write.
    unsafe {
        if !ppkalg.is_null() {
            *ppkalg = (*(*pub_).algor).algorithm;
        }
        if !pk.is_null() {
            *pk = (*(*pub_).public_key).data;
            *ppklen = (*(*pub_).public_key).length;
        }
        if !pa.is_null() {
            *pa = (*pub_).algor;
        }
    }
    1
}

/**
 * `X509_PUBKEY_eq(const X509_PUBKEY *a, const X509_PUBKEY *b)` — `crypto/x509/x_pubkey.c:1051-1069`.
 *
 * `1` for equal, `0` for non-equal, a negative for "cannot compare": the algorithm is compared
 * first, then the two decoded keys. **The two `get0` calls short-circuit**, which is the
 * authority's `||` and is observable: an object with no decoded key raises once, not twice.
 *
 * # Safety
 *
 * `a` and `b` are NULL or live objects.
 */
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_eq(a: *const X509Pubkey, b: *const X509Pubkey) -> c_int {
    if a == b {
        return 1;
    }
    if a.is_null() || b.is_null() {
        return 0;
    }
    let mut alg_a: *mut X509Algor = ptr::null_mut();
    let mut alg_b: *mut X509Algor = ptr::null_mut();
    // SAFETY: `a` and `b` are live and every other out-pointer is NULL, which is skipped.
    unsafe {
        if X509_PUBKEY_get0_param(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut alg_a,
            a,
        ) == 0
            || alg_a.is_null()
            || X509_PUBKEY_get0_param(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut alg_b,
                b,
            ) == 0
            || alg_b.is_null()
        {
            return -2;
        }
        if X509_ALGOR_cmp(alg_a, alg_b) != 0 {
            return 0;
        }
        /* The authority's `(pA = ...) == NULL || (pB = ...) == NULL` short-circuits, so an
         * absent key on `a` raises once rather than once per operand. */
        let pa = X509_PUBKEY_get0(a);
        if pa.is_null() {
            return -2;
        }
        let pb = X509_PUBKEY_get0(b);
        if pb.is_null() {
            return -2;
        }
        EVP_PKEY_eq(pa, pb)
    }
}

/// `int ossl_x509_PUBKEY_get0_libctx(OSSL_LIB_CTX **plibctx, const char **ppropq,
/// const X509_PUBKEY *key)` — `crypto/x509/x_pubkey.c:1071-1079`. Internal
/// (`include/crypto/x509.h:333`), so `pub(crate)`.
///
/// Both out-parameters are optional and independently skipped, and both answers are
/// borrowed. Its two authority callers are `crypto/ec/ec_ameth.c:109` and
/// `crypto/x509/v3_skid.c:69`, both unlanded.
///
/// # Safety
///
/// `key` is a live `X509_PUBKEY`. Each out-pointer is NULL or writable for its type.
#[allow(dead_code)] // read by `crypto/ec/ec_ameth.c:109` and `crypto/x509/v3_skid.c:69`, both unlanded.
#[allow(non_snake_case)] // the authority's own spelling, as `src/ec/mont.rs` keeps `ossl_ec_GFp_*`.
pub(crate) unsafe extern "C" fn ossl_x509_PUBKEY_get0_libctx(
    plibctx: *mut *mut c_void,
    ppropq: *mut *const c_char,
    key: *const X509Pubkey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read and write.
    unsafe {
        if !plibctx.is_null() {
            *plibctx = (*key).libctx;
        }
        if !ppropq.is_null() {
            *ppropq = (*key).propq;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::layout::V_ASN1_UNDEF;
    use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_BIT_STRING_new};
    use crate::asn1::x_algor::{X509_ALGOR_free, X509_ALGOR_new};
    use crate::runtime::obj::{NID_rsaEncryption, OBJ_nid2obj, OBJ_obj2nid};

    /// A key whose two ASN.1 members are live, built from this module's own definitions.
    fn blank_pubkey() -> X509Pubkey {
        X509Pubkey {
            algor: X509_ALGOR_new(),
            public_key: ASN1_BIT_STRING_new(),
            pkey: ptr::null_mut(),
            libctx: ptr::null_mut(),
            propq: ptr::null_mut(),
            flag_force_legacy: 0,
        }
    }

    unsafe fn free_pubkey(pub_: &mut X509Pubkey) {
        // SAFETY: the two members were allocated by the `_new` constructors above.
        unsafe {
            X509_ALGOR_free(pub_.algor);
            ASN1_BIT_STRING_free(pub_.public_key);
        }
    }

    /// The three accessors round-trip the identifier and the bit string they were given.
    #[test]
    fn set0_and_get0_are_the_same_identifier_and_bytes() {
        let mut pub_ = blank_pubkey();
        // The bytes are handed to the object, which owns them.
        let enc = vec![0x04u8, 0xaa, 0xbb];
        let penc = enc.as_ptr() as *mut u8;
        core::mem::forget(enc);

        // SAFETY: the object's two members are live; `penc` is a fresh heap buffer.
        let rc = unsafe {
            X509_PUBKEY_set0_param(
                &raw mut pub_,
                OBJ_nid2obj(NID_rsaEncryption),
                V_ASN1_UNDEF,
                core::ptr::null_mut(),
                penc,
                3,
            )
        };
        assert_eq!(rc, 1);

        let mut o: *mut Asn1Object = core::ptr::null_mut();
        let mut pk: *const u8 = core::ptr::null();
        let mut pklen = -1;
        let mut pa: *mut X509Algor = core::ptr::null_mut();
        // SAFETY: the object is live and every out-pointer is writable.
        let rc = unsafe {
            X509_PUBKEY_get0_param(&raw mut o, &raw mut pk, &raw mut pklen, &raw mut pa, &pub_)
        };
        assert_eq!(rc, 1);
        // SAFETY: `o` and `pk` were filled by the call and are owned by the object.
        unsafe {
            assert_eq!(OBJ_obj2nid(o), NID_rsaEncryption);
            assert_eq!(pklen, 3);
            assert_eq!(core::slice::from_raw_parts(pk, 3), &[0x04, 0xaa, 0xbb]);
            assert_eq!(pa, pub_.algor);
            free_pubkey(&mut pub_);
        }
    }

    /// A NULL out-pointer is skipped, and a NULL `penc` leaves the bit string alone.
    #[test]
    fn absent_arguments_are_skipped() {
        let mut pub_ = blank_pubkey();
        // SAFETY: the object's members are live; `penc` NULL is the "keep" arm.
        let rc = unsafe {
            X509_PUBKEY_set0_param(
                &raw mut pub_,
                OBJ_nid2obj(NID_rsaEncryption),
                V_ASN1_UNDEF,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 1);
        // SAFETY: every out-pointer is NULL, which the function skips.
        let rc = unsafe {
            X509_PUBKEY_get0_param(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &pub_,
            )
        };
        assert_eq!(rc, 1);
        // SAFETY: the bit string was never written, so it is still empty.
        unsafe {
            assert_eq!((*pub_.public_key).length, 0);
            free_pubkey(&mut pub_);
        }
    }

    /// The libctx accessor hands back what the object holds, borrowed.
    #[test]
    fn libctx_and_propq_are_borrowed_back() {
        let mut sentinel = 0u8;
        let propq = c"test-property-query";
        let mut pub_ = blank_pubkey();
        pub_.libctx = (&raw mut sentinel).cast::<c_void>();
        pub_.propq = propq.as_ptr() as *mut c_char;

        let mut seen_ctx: *mut c_void = core::ptr::null_mut();
        let mut seen_propq: *const c_char = core::ptr::null();
        // SAFETY: the object is live and both out-pointers are writable.
        let rc =
            unsafe { ossl_x509_PUBKEY_get0_libctx(&raw mut seen_ctx, &raw mut seen_propq, &pub_) };
        assert_eq!(rc, 1);
        assert_eq!(seen_ctx, pub_.libctx);
        assert_eq!(seen_propq, propq.as_ptr());
        // SAFETY: the object's two members are live.
        unsafe { free_pubkey(&mut pub_) };
    }

    /// A `X509_PUBKEY` built through its own constructor, filled by `set0_param` and encoded
    /// through its `EXTERN` hooks, decodes back to the same algorithm and bytes — the round trip
    /// `i2d_X509_PUBKEY`/`d2i_X509_PUBKEY` is, and the item the rest of the unit stands on.
    #[test]
    fn the_item_round_trips_through_its_own_hooks() {
        // SAFETY: the constructor builds through the item; the encoder/decoder are the item's.
        unsafe {
            let built = X509_PUBKEY_new();
            assert!(!built.is_null());
            let enc = vec![0x04u8, 0x11, 0x22];
            let penc = enc.as_ptr() as *mut u8;
            core::mem::forget(enc);
            assert_eq!(
                X509_PUBKEY_set0_param(
                    built,
                    OBJ_nid2obj(NID_rsaEncryption),
                    V_ASN1_UNDEF,
                    core::ptr::null_mut(),
                    penc,
                    3,
                ),
                1
            );

            let mut der: *mut c_uchar = core::ptr::null_mut();
            let len = i2d_X509_PUBKEY(built, &raw mut der);
            assert!(len > 0);
            // SAFETY: `der` owns `len` bytes, produced by the encoder above.
            let bytes = core::slice::from_raw_parts(der, len as usize).to_vec();
            CRYPTO_free(der.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_PUBKEY);

            let mut cursor: *const c_uchar = bytes.as_ptr();
            let decoded = d2i_X509_PUBKEY(ptr::null_mut(), &raw mut cursor, len as c_long);
            assert!(!decoded.is_null());
            let mut o: *mut Asn1Object = core::ptr::null_mut();
            let mut pk: *const u8 = core::ptr::null();
            let mut pklen = -1;
            assert_eq!(
                X509_PUBKEY_get0_param(
                    &raw mut o,
                    &raw mut pk,
                    &raw mut pklen,
                    core::ptr::null_mut(),
                    decoded,
                ),
                1
            );
            assert_eq!(OBJ_obj2nid(o), NID_rsaEncryption);
            assert_eq!(pklen, 3);
            assert_eq!(core::slice::from_raw_parts(pk, 3), &[0x04, 0x11, 0x22]);

            // The copy reads the same algorithm and bytes. Both objects decoded no key -- the
            // crate publishes no provider decoder, so the `OSSL_DECODER` arm found none -- and
            // `X509_PUBKEY_eq` answers -2 for a pair whose keys are absent, which is the
            // authority's own answer for two algorithm-identical objects with no decoded key.
            let copy = X509_PUBKEY_dup(decoded);
            assert!(!copy.is_null());
            assert_eq!(X509_PUBKEY_eq(decoded, copy), -2);
            assert_eq!(X509_PUBKEY_eq(decoded, ptr::null()), 0);
            X509_PUBKEY_free(copy);
            X509_PUBKEY_free(decoded);
            X509_PUBKEY_free(built);
        }
    }
}
