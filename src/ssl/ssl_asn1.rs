//! Phase 14.7 — `ssl/ssl_asn1.c`: the session DER codec.
//!
//! The three exported rows — `i2d_SSL_SESSION`, `d2i_SSL_SESSION` and `d2i_SSL_SESSION_ex` — plus
//! the file-static `SSL_SESSION_ASN1` template the authority's `ASN1_SEQUENCE` macro builds. The
//! template is transcribed as an [`Asn1Template`] array and driven through the crate's landed
//! `ASN1_item_i2d`/`ASN1_item_d2i` (Phase 5's), exactly as the authority's generated
//! `i2d_SSL_SESSION_ASN1`/`d2i_SSL_SESSION_ASN1` wrappers are.
//!
//! ## The template is the authority's field for field
//!
//! `ssl_asn1.c:51-82` declares a `SEQUENCE` of twenty-six fields, five of them optional context
//! tags, and this module reproduces the flag/tag/offset triple of each. The `SSL_SESSION_ASN1`
//! structure is `#[repr(C)]` in the authority's field order and the offsets the template names are
//! asserted against it, because the decoder writes through those offsets.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The embedded integer template items are the crate's `x_int64.c` items.** The authority's
//!   `ASN1_EMBED(..., UINT32)` names its own `UINT32_it` and so on; the crate's Phase 5 items are
//!   the same descriptors (`INT32_it`, `ZINT64_it`, …), so the encodings agree byte for byte.
//! * **`time`/`timeout` are seconds.** The authority converts `OSSL_TIME` nanoseconds to `time_t`
//!   seconds at `ssl_asn1.c:171-172`; this crate stores seconds in the session
//!   (`src/ssl/ssl_lib.rs`), so the conversion is the identity here. The `as->time == 0` fallback
//!   (`:324-332`) uses the wall clock exactly as the authority's `ossl_time_now` does; a session
//!   whose time was set through `SSL_SESSION_set_time_ex` encodes deterministically.
//! * **`--no-comp`/`--no-psk`/`--no-srp` arms are present.** The admitted build defines none of
//!   those, so the `comp_id`, `psk_identity*` and `srp_username` fields are always in play, as in
//!   the authority.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_OCTET_STRING_it;
use crate::asn1::layout::{Asn1Item, Asn1String, Asn1Template, *};
use crate::asn1::x_int64::{INT32_it, UINT32_it, ZINT32_it, ZINT64_it, ZUINT32_it, ZUINT64_it};
use crate::evp::pkey::EVP_PKEY_free;
use crate::ffi::guard_ffi;
use crate::runtime::err::raise_with;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strndup};
use crate::ssl::ssl_ciph::ssl3_get_cipher_by_id;
use crate::ssl::ssl_lib::{
    SslSession, SSL3_MAX_SSL_SESSION_ID_LENGTH, SSL_MAX_SID_CTX_LENGTH,
    TLS13_MAX_RESUMPTION_PSK_LENGTH,
};
use crate::ssl::ssl_sess::{ssl_session_calculate_timeout, SSL_SESSION_free, SSL_SESSION_new};
use crate::x509::x_pubkey::{d2i_PUBKEY_ex, i2d_PUBKEY};
use crate::x509::x_x509::{X509_free, X509};

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/ssl_asn1.c".as_ptr();
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_LIB_X509` — `include/openssl/err.h.in`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_LIB_CRYPTO`.
const ERR_LIB_CRYPTO: c_int = 15;
/// `ERR_RFLAG_COMMON` — `err.h:239`.
const ERR_RFLAG_COMMON: c_int = 2 << 18;
/// `ERR_R_X509_LIB`.
const ERR_R_X509_LIB: c_int = ERR_LIB_X509 | ERR_RFLAG_COMMON;
/// `ERR_R_CRYPTO_LIB`.
const ERR_R_CRYPTO_LIB: c_int = ERR_LIB_CRYPTO | ERR_RFLAG_COMMON;
/// `SSL_R_UNKNOWN_SSL_VERSION` — `sslerr.h:352`.
const SSL_R_UNKNOWN_SSL_VERSION: c_int = 254;
/// `SSL_R_UNSUPPORTED_SSL_VERSION` — `sslerr.h:362`.
const SSL_R_UNSUPPORTED_SSL_VERSION: c_int = 259;
/// `SSL_R_CIPHER_CODE_WRONG_LENGTH` — `sslerr.h:77`.
const SSL_R_CIPHER_CODE_WRONG_LENGTH: c_int = 137;
/// `SSL_R_BAD_LENGTH` — `sslerr.h:46`.
const SSL_R_BAD_LENGTH: c_int = 271;
/// `SSL_SESSION_ASN1_VERSION` — `ssl.h:62`.
const SSL_SESSION_ASN1_VERSION: u32 = 0x0001;
/// `SSL3_VERSION_MAJOR` — `ssl3.h:216`.
const SSL3_VERSION_MAJOR: i32 = 0x03;
/// `DTLS1_VERSION_MAJOR` — `dtls1.h:32`.
const DTLS1_VERSION_MAJOR: i32 = 0xFE;
/// `DTLS1_BAD_VER` — `prov_ssl.h:30`.
const DTLS1_BAD_VER: i32 = 0x0100;

/// `struct SSL_SESSION_ASN1` — `ssl_asn1.c:18-49`, the whole record.
#[repr(C)]
struct SslSessionAsn1 {
    version: u32,
    ssl_version: i32,
    cipher: *mut Asn1String,
    comp_id: *mut Asn1String,
    master_key: *mut Asn1String,
    session_id: *mut Asn1String,
    key_arg: *mut Asn1String,
    time: i64,
    timeout: i64,
    peer: *mut X509,
    session_id_context: *mut Asn1String,
    verify_result: i32,
    tlsext_hostname: *mut Asn1String,
    tlsext_tick_lifetime_hint: u64,
    tlsext_tick_age_add: u32,
    tlsext_tick: *mut Asn1String,
    psk_identity_hint: *mut Asn1String,
    psk_identity: *mut Asn1String,
    srp_username: *mut Asn1String,
    flags: u64,
    max_early_data: u32,
    alpn_selected: *mut Asn1String,
    tlsext_max_fragment_len_mode: u32,
    ticket_appdata: *mut Asn1String,
    kex_group: u32,
    peer_rpk: *mut Asn1String,
}

// The offsets the template names, asserted against the structure rather than written twice.
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(SslSessionAsn1, version) == 0);
    assert!(offset_of!(SslSessionAsn1, ssl_version) == 4);
    assert!(offset_of!(SslSessionAsn1, cipher) == 8);
    assert!(offset_of!(SslSessionAsn1, comp_id) == 16);
    assert!(offset_of!(SslSessionAsn1, master_key) == 24);
    assert!(offset_of!(SslSessionAsn1, session_id) == 32);
    assert!(offset_of!(SslSessionAsn1, key_arg) == 40);
    assert!(offset_of!(SslSessionAsn1, time) == 48);
    assert!(offset_of!(SslSessionAsn1, timeout) == 56);
    assert!(offset_of!(SslSessionAsn1, peer) == 64);
    assert!(offset_of!(SslSessionAsn1, session_id_context) == 72);
    assert!(offset_of!(SslSessionAsn1, verify_result) == 80);
    assert!(offset_of!(SslSessionAsn1, tlsext_hostname) == 88);
    assert!(offset_of!(SslSessionAsn1, tlsext_tick_lifetime_hint) == 96);
    assert!(offset_of!(SslSessionAsn1, tlsext_tick_age_add) == 104);
    assert!(offset_of!(SslSessionAsn1, tlsext_tick) == 112);
    assert!(offset_of!(SslSessionAsn1, psk_identity_hint) == 120);
    assert!(offset_of!(SslSessionAsn1, psk_identity) == 128);
    assert!(offset_of!(SslSessionAsn1, srp_username) == 136);
    assert!(offset_of!(SslSessionAsn1, flags) == 144);
    assert!(offset_of!(SslSessionAsn1, max_early_data) == 152);
    assert!(offset_of!(SslSessionAsn1, alpn_selected) == 160);
    assert!(offset_of!(SslSessionAsn1, tlsext_max_fragment_len_mode) == 168);
    assert!(offset_of!(SslSessionAsn1, ticket_appdata) == 176);
    assert!(offset_of!(SslSessionAsn1, kex_group) == 184);
    assert!(offset_of!(SslSessionAsn1, peer_rpk) == 192);
};

/// `SSL_SESSION_ASN1_seq_tt` — `ssl_asn1.c:51-82`.
static SSL_SESSION_ASN1_TT: [Asn1Template; 26] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: UINT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 4,
        field_name: c"ssl_version".as_ptr(),
        item: INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"cipher".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 32,
        field_name: c"session_id".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"master_key".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 40,
        field_name: c"key_arg".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 1,
        offset: 48,
        field_name: c"time".as_ptr(),
        item: ZINT64_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 2,
        offset: 56,
        field_name: c"timeout".as_ptr(),
        item: ZINT64_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 64,
        field_name: c"peer".as_ptr(),
        item: crate::x509::x_x509::X509_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 4,
        offset: 72,
        field_name: c"session_id_context".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 5,
        offset: 80,
        field_name: c"verify_result".as_ptr(),
        item: ZINT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 6,
        offset: 88,
        field_name: c"tlsext_hostname".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 7,
        offset: 120,
        field_name: c"psk_identity_hint".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 8,
        offset: 128,
        field_name: c"psk_identity".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 9,
        offset: 96,
        field_name: c"tlsext_tick_lifetime_hint".as_ptr(),
        item: ZUINT64_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 10,
        offset: 112,
        field_name: c"tlsext_tick".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 11,
        offset: 16,
        field_name: c"comp_id".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 12,
        offset: 136,
        field_name: c"srp_username".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 13,
        offset: 144,
        field_name: c"flags".as_ptr(),
        item: ZUINT64_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 14,
        offset: 104,
        field_name: c"tlsext_tick_age_add".as_ptr(),
        item: ZUINT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 15,
        offset: 152,
        field_name: c"max_early_data".as_ptr(),
        item: ZUINT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 16,
        offset: 160,
        field_name: c"alpn_selected".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 17,
        offset: 168,
        field_name: c"tlsext_max_fragment_len_mode".as_ptr(),
        item: ZUINT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 18,
        offset: 176,
        field_name: c"ticket_appdata".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED,
        tag: 19,
        offset: 184,
        field_name: c"kex_group".as_ptr(),
        item: UINT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 20,
        offset: 192,
        field_name: c"peer_rpk".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `SSL_SESSION_ASN1_it` — the `static_ASN1_SEQUENCE_END` descriptor.
static SSL_SESSION_ASN1_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: SSL_SESSION_ASN1_TT.as_ptr(),
    tcount: 26,
    funcs: ptr::null(),
    size: core::mem::size_of::<SslSessionAsn1>() as c_long,
    sname: c"SSL_SESSION_ASN1".as_ptr(),
};

/// `ssl_session_oinit` — `ssl_asn1.c:90-97`: point an octet string at borrowed bytes.
///
/// # Safety
/// `os` must be a live slot; `data` must be readable for `len` bytes.
unsafe fn ssl_session_oinit(
    dest: *mut *mut Asn1String,
    os: *mut Asn1String,
    data: *const u8,
    len: usize,
) {
    // SAFETY: `os`/`dest` are the caller's live slots.
    unsafe {
        (*os).data = data.cast_mut().cast::<c_uchar>();
        (*os).length = len as c_int;
        (*os).flags = 0;
        (*os).type_ = V_ASN1_OCTET_STRING;
        *dest = os;
    }
}

/// `ssl_session_sinit` — `ssl_asn1.c:100-107`: as above, from a C string.
///
/// # Safety
/// `os` must be a live slot; `data` must be NULL or NUL-terminated.
unsafe fn ssl_session_sinit(dest: *mut *mut Asn1String, os: *mut Asn1String, data: *const c_char) {
    if data.is_null() {
        // SAFETY: `dest` is the caller's live slot.
        unsafe { *dest = ptr::null_mut() };
    } else {
        // SAFETY: `data` is NUL-terminated per the contract.
        let len = unsafe { libc_strlen(data) };
        // SAFETY: forwarded per the contract.
        unsafe { ssl_session_oinit(dest, os, data.cast::<u8>(), len) };
    }
}

/// `strlen`, over the C string the caller supplied.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn libc_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// `ssl_session_strndup` — `ssl_asn1.c:229-239`.
///
/// # Safety
/// `pdst` must be a live slot; `src` may be NULL.
unsafe fn ssl_session_strndup(pdst: *mut *mut c_char, src: *mut Asn1String) -> c_int {
    // SAFETY: `pdst` is the caller's live slot.
    unsafe {
        CRYPTO_free((*pdst).cast(), FILE, 0);
        *pdst = ptr::null_mut();
        if src.is_null() {
            return 1;
        }
        *pdst = CRYPTO_strndup((*src).data.cast(), (*src).length as usize, FILE, 0).cast();
        if (*pdst).is_null() {
            return 0;
        }
    }
    1
}

/// `ssl_session_memcpy` — `ssl_asn1.c:243-255`: copy an octet string out, refusing oversize.
///
/// # Safety
/// `dst` must hold `maxlen` bytes; `pdstlen` must be writable; `src` may be NULL.
unsafe fn ssl_session_memcpy(
    dst: *mut u8,
    pdstlen: *mut usize,
    src: *mut Asn1String,
    maxlen: usize,
) -> c_int {
    // SAFETY: `src` is NULL or live per the contract.
    let src_len = unsafe {
        if src.is_null() {
            0
        } else {
            (*src).length
        }
    };
    if src.is_null() || src_len == 0 {
        // SAFETY: `pdstlen` is writable per the contract.
        unsafe { *pdstlen = 0 };
        return 1;
    }
    let len = src_len;
    if len < 0 || len as usize > maxlen {
        return 0;
    }
    // SAFETY: `src` holds `len` readable bytes; `dst` holds `maxlen >= len` writable.
    unsafe {
        ptr::copy_nonoverlapping((*src).data, dst, len as usize);
        *pdstlen = len as usize;
    }
    1
}

/// Seconds since the epoch, the wall-clock fallback `d2i_SSL_SESSION_ex` uses when the decoded
/// `time` is zero (`ssl_asn1.c:327`, the authority's `ossl_time_now`).
fn time_now_secs() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    }
}

/// `int i2d_SSL_SESSION(const SSL_SESSION *in, unsigned char **pp)` — `ssl_asn1.c:109-223`.
///
/// # Safety
/// `in` must be NULL or a live session; `pp` must be NULL or a writable pointer slot.
#[no_mangle]
pub unsafe extern "C" fn i2d_SSL_SESSION(input: *const SslSession, pp: *mut *mut c_uchar) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `input` is NULL or live per the caller's contract.
        if input.is_null() {
            return 0;
        }
        // SAFETY: `input` is non-NULL and live per the contract.
        let (cipher_null, cipher_id) = unsafe { ((*input).cipher.is_null(), (*input).cipher_id) };
        if cipher_null && cipher_id == 0 {
            return 0;
        }
        // SAFETY: `input` is live.
        let s = unsafe { &*input };
        // SAFETY: each local is a plain POD record whose all-zero bit pattern is a valid empty
        // value (`SslSessionAsn1` is a C-layout record of scalars and pointers, `Asn1String` a
        // scalar/pointer record).
        let (
            mut as_,
            mut cipher,
            mut master_key,
            mut session_id,
            mut sid_ctx,
            mut comp_id,
            mut tlsext_hostname,
            mut tlsext_tick,
            mut srp_username,
            mut psk_identity,
            mut psk_identity_hint,
            mut alpn_selected,
            mut ticket_appdata,
            mut peer_rpk,
        ) = unsafe {
            (
                core::mem::zeroed::<SslSessionAsn1>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
                core::mem::zeroed::<Asn1String>(),
            )
        };
        let mut cipher_data = [0u8; 2];

        as_.version = SSL_SESSION_ASN1_VERSION;
        as_.ssl_version = s.ssl_version;
        as_.kex_group = s.kex_group;

        let l: c_ulong = if s.cipher.is_null() {
            s.cipher_id
        } else {
            // SAFETY: `s.cipher` is non-NULL in this branch and points into a static table.
            unsafe { (*s.cipher).id as c_ulong }
        };
        cipher_data[0] = ((l >> 8) & 0xff) as u8;
        cipher_data[1] = (l & 0xff) as u8;
        // SAFETY: every slot is a live local.
        unsafe {
            ssl_session_oinit(&mut as_.cipher, &mut cipher, cipher_data.as_ptr(), 2);
        }

        if s.compress_meth != 0 {
            let comp_id_data = s.compress_meth as u8;
            // SAFETY: live locals.
            unsafe { ssl_session_oinit(&mut as_.comp_id, &mut comp_id, &comp_id_data, 1) };
        }

        // SAFETY: live locals and the session's own buffers.
        unsafe {
            ssl_session_oinit(
                &mut as_.master_key,
                &mut master_key,
                s.master_key.as_ptr(),
                s.master_key_length,
            );
            ssl_session_oinit(
                &mut as_.session_id,
                &mut session_id,
                s.session_id.as_ptr(),
                s.session_id_length,
            );
            ssl_session_oinit(
                &mut as_.session_id_context,
                &mut sid_ctx,
                s.sid_ctx.as_ptr(),
                s.sid_ctx_length,
            );
            ssl_session_sinit(
                &mut as_.tlsext_hostname,
                &mut tlsext_hostname,
                s.ext_hostname,
            );
        }
        if !s.ext_tick.is_null() {
            // SAFETY: live locals; the tick buffer is `ext_ticklen` bytes.
            unsafe {
                ssl_session_oinit(
                    &mut as_.tlsext_tick,
                    &mut tlsext_tick,
                    s.ext_tick,
                    s.ext_ticklen,
                );
            }
        }

        as_.time = s.time as i64;
        as_.timeout = s.timeout as i64;
        as_.verify_result = s.verify_result as i32;
        as_.peer = s.peer;

        peer_rpk.data = ptr::null_mut();
        as_.peer_rpk = ptr::null_mut();
        if !s.peer_rpk.is_null() {
            // SAFETY: `peer_rpk` is a live EVP_PKEY; `i2d_PUBKEY` answers its DER length.
            peer_rpk.length = unsafe {
                i2d_PUBKEY(
                    s.peer_rpk.cast::<crate::evp::pkey::EvpPkey>(),
                    &mut peer_rpk.data,
                )
            };
            if peer_rpk.length > 0 && !peer_rpk.data.is_null() {
                as_.peer_rpk = &mut peer_rpk;
            }
        }

        if s.ext_tick_lifetime_hint > 0 {
            as_.tlsext_tick_lifetime_hint = s.ext_tick_lifetime_hint;
        }
        as_.tlsext_tick_age_add = s.ext_tick_age_add;
        // SAFETY: live locals; the two psk strings are NULL or NUL-terminated.
        unsafe {
            ssl_session_sinit(
                &mut as_.psk_identity_hint,
                &mut psk_identity_hint,
                s.psk_identity_hint,
            );
            ssl_session_sinit(&mut as_.psk_identity, &mut psk_identity, s.psk_identity);
            ssl_session_sinit(&mut as_.srp_username, &mut srp_username, s.srp_username);
        }

        as_.flags = s.flags as u64;
        as_.max_early_data = s.ext_max_early_data;

        if s.ext_alpn_selected.is_null() {
            as_.alpn_selected = ptr::null_mut();
        } else {
            // SAFETY: live locals and the session's own buffer.
            unsafe {
                ssl_session_oinit(
                    &mut as_.alpn_selected,
                    &mut alpn_selected,
                    s.ext_alpn_selected,
                    s.ext_alpn_selected_len,
                );
            }
        }
        as_.tlsext_max_fragment_len_mode = s.max_fragment_len_mode as u32;

        if s.ticket_appdata.is_null() {
            as_.ticket_appdata = ptr::null_mut();
        } else {
            // SAFETY: live locals and the session's own buffer.
            unsafe {
                ssl_session_oinit(
                    &mut as_.ticket_appdata,
                    &mut ticket_appdata,
                    s.ticket_appdata,
                    s.ticket_appdata_len,
                );
            }
        }

        // SAFETY: the item is this module's static; `as_` is a live value.
        let ret = unsafe {
            ASN1_item_i2d(
                ptr::addr_of!(as_).cast::<c_void>(),
                pp,
                &SSL_SESSION_ASN1_ITEM,
            )
        };
        // SAFETY: `peer_rpk.data` is the allocation `i2d_PUBKEY` produced, NULL or owned.
        unsafe { CRYPTO_free(peer_rpk.data.cast(), FILE, 0) };
        ret
    })
}

/// `SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length)` —
/// `ssl_asn1.c:257-261`.
///
/// # Safety
/// `a` must be NULL or a writable session slot; `pp` must be a readable pointer to a pointer for
/// `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_SSL_SESSION(
    a: *mut *mut SslSession,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut SslSession {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { d2i_SSL_SESSION_ex(a, pp, length, ptr::null_mut(), ptr::null()) }
    })
}

/// `SSL_SESSION *d2i_SSL_SESSION_ex(SSL_SESSION **a, const unsigned char **pp, long length,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `ssl_asn1.c:262-433`.
///
/// # Safety
/// As `d2i_SSL_SESSION`; `libctx` must be NULL or a live library context and `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn d2i_SSL_SESSION_ex(
    a: *mut *mut SslSession,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut SslSession {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `pp` is readable per the contract.
        let mut p: *const c_uchar = unsafe { *pp };
        let ret: *mut SslSession;
        // SAFETY: the item is this module's static; `p`/`length` are the caller's.
        let as_ = unsafe {
            ASN1_item_d2i(ptr::null_mut(), &mut p, length, &SSL_SESSION_ASN1_ITEM)
                .cast::<SslSessionAsn1>()
        };
        if as_.is_null() {
            return ptr::null_mut();
        }

        // SAFETY: each step mirrors the authority's; on any failure it jumps to the `err` arm.
        unsafe {
            if a.is_null() || (*a).is_null() {
                ret = SSL_SESSION_new();
                if ret.is_null() {
                    return d2i_err(as_, ret, a);
                }
            } else {
                ret = *a;
            }

            if (*as_).version != SSL_SESSION_ASN1_VERSION {
                raise_ssl_asn1(SSL_R_UNKNOWN_SSL_VERSION, 286);
                return d2i_err(as_, ret, a);
            }
            let v = (*as_).ssl_version;
            if (v >> 8) != SSL3_VERSION_MAJOR
                && (v >> 8) != DTLS1_VERSION_MAJOR
                && v != DTLS1_BAD_VER
            {
                raise_ssl_asn1(SSL_R_UNSUPPORTED_SSL_VERSION, 293);
                return d2i_err(as_, ret, a);
            }

            (*ret).ssl_version = v;
            (*ret).kex_group = (*as_).kex_group;

            if (*(*as_).cipher).length != 2 {
                raise_ssl_asn1(SSL_R_CIPHER_CODE_WRONG_LENGTH, 302);
                return d2i_err(as_, ret, a);
            }
            let id: c_ulong = 0x0300_0000
                | (((*(*as_).cipher).data.read() as c_ulong) << 8)
                | ((*(*as_).cipher).data.add(1).read() as c_ulong);
            (*ret).cipher_id = id;
            (*ret).cipher = ssl3_get_cipher_by_id(id as u32);
            if (*ret).cipher.is_null() {
                return d2i_err(as_, ret, a);
            }

            if ssl_session_memcpy(
                (*ret).session_id.as_mut_ptr(),
                &mut (*ret).session_id_length,
                (*as_).session_id,
                SSL3_MAX_SSL_SESSION_ID_LENGTH,
            ) == 0
            {
                return d2i_err(as_, ret, a);
            }
            let mut tmpl = 0usize;
            if ssl_session_memcpy(
                (*ret).master_key.as_mut_ptr(),
                &mut tmpl,
                (*as_).master_key,
                TLS13_MAX_RESUMPTION_PSK_LENGTH,
            ) == 0
            {
                return d2i_err(as_, ret, a);
            }
            (*ret).master_key_length = tmpl;

            if (*as_).time != 0 {
                (*ret).time = (*as_).time as u64;
            } else {
                (*ret).time = time_now_secs();
            }
            if (*as_).timeout != 0 {
                (*ret).timeout = (*as_).timeout as u64;
            } else {
                (*ret).timeout = 3;
            }
            ssl_session_calculate_timeout(ret);

            X509_free((*ret).peer);
            (*ret).peer = (*as_).peer;
            (*as_).peer = ptr::null_mut();

            EVP_PKEY_free((*ret).peer_rpk.cast());
            (*ret).peer_rpk = ptr::null_mut();
            if !(*as_).peer_rpk.is_null() {
                let data = (*(*as_).peer_rpk).data;
                let data_pp = &data as *const *mut c_uchar as *mut *const c_uchar;
                (*ret).peer_rpk = d2i_PUBKEY_ex(
                    ptr::null_mut(),
                    data_pp,
                    (*(*as_).peer_rpk).length as c_long,
                    libctx,
                    propq,
                )
                .cast();
                if (*ret).peer_rpk.is_null() {
                    return d2i_err(as_, ret, a);
                }
            }

            if ssl_session_memcpy(
                (*ret).sid_ctx.as_mut_ptr(),
                &mut (*ret).sid_ctx_length,
                (*as_).session_id_context,
                SSL_MAX_SID_CTX_LENGTH,
            ) == 0
            {
                return d2i_err(as_, ret, a);
            }
            (*ret).verify_result = (*as_).verify_result as c_long;

            if ssl_session_strndup(&mut (*ret).ext_hostname, (*as_).tlsext_hostname) == 0 {
                return d2i_err(as_, ret, a);
            }
            if ssl_session_strndup(&mut (*ret).psk_identity_hint, (*as_).psk_identity_hint) == 0 {
                return d2i_err(as_, ret, a);
            }
            if ssl_session_strndup(&mut (*ret).psk_identity, (*as_).psk_identity) == 0 {
                return d2i_err(as_, ret, a);
            }

            (*ret).ext_tick_lifetime_hint = (*as_).tlsext_tick_lifetime_hint as c_ulong;
            (*ret).ext_tick_age_add = (*as_).tlsext_tick_age_add;
            CRYPTO_free((*ret).ext_tick.cast(), FILE, 0);
            if !(*as_).tlsext_tick.is_null() {
                (*ret).ext_tick = (*(*as_).tlsext_tick).data;
                (*ret).ext_ticklen = (*(*as_).tlsext_tick).length as usize;
                (*(*as_).tlsext_tick).data = ptr::null_mut();
            } else {
                (*ret).ext_tick = ptr::null_mut();
            }

            if !(*as_).comp_id.is_null() {
                if (*(*as_).comp_id).length != 1 {
                    raise_ssl_asn1(SSL_R_BAD_LENGTH, 382);
                    return d2i_err(as_, ret, a);
                }
                (*ret).compress_meth = (*(*as_).comp_id).data.read() as c_uint;
            } else {
                (*ret).compress_meth = 0;
            }

            if ssl_session_strndup(&mut (*ret).srp_username, (*as_).srp_username) == 0 {
                return d2i_err(as_, ret, a);
            }
            (*ret).flags = (*as_).flags as u32;
            (*ret).ext_max_early_data = (*as_).max_early_data;

            CRYPTO_free((*ret).ext_alpn_selected.cast(), FILE, 0);
            if !(*as_).alpn_selected.is_null() {
                (*ret).ext_alpn_selected = (*(*as_).alpn_selected).data;
                (*ret).ext_alpn_selected_len = (*(*as_).alpn_selected).length as usize;
                (*(*as_).alpn_selected).data = ptr::null_mut();
            } else {
                (*ret).ext_alpn_selected = ptr::null_mut();
                (*ret).ext_alpn_selected_len = 0;
            }

            (*ret).max_fragment_len_mode = (*as_).tlsext_max_fragment_len_mode as u8;

            CRYPTO_free((*ret).ticket_appdata.cast(), FILE, 0);
            if !(*as_).ticket_appdata.is_null() {
                (*ret).ticket_appdata = (*(*as_).ticket_appdata).data;
                (*ret).ticket_appdata_len = (*(*as_).ticket_appdata).length as usize;
                (*(*as_).ticket_appdata).data = ptr::null_mut();
            } else {
                (*ret).ticket_appdata = ptr::null_mut();
                (*ret).ticket_appdata_len = 0;
            }

            asn1_free_as(as_);

            if !a.is_null() && (*a).is_null() {
                *a = ret;
            }
            *pp = p;
            ret
        }
    })
}

/// `M_ASN1_free_of(as, SSL_SESSION_ASN1)` — `ASN1_item_free`.
///
/// # Safety
/// `as_` must be NULL or the value `ASN1_item_d2i` returned for this item.
unsafe fn asn1_free_as(as_: *mut SslSessionAsn1) {
    // SAFETY: the item is this module's static and `as_` is its value.
    unsafe {
        crate::asn1::fre::ASN1_item_free(as_.cast::<c_void>(), &SSL_SESSION_ASN1_ITEM);
    }
}

/// The `err` arm of `d2i_SSL_SESSION_ex` (`ssl_asn1.c:428-432`).
///
/// # Safety
/// `as_` may be NULL or the decoded value; `ret` is the object under construction.
unsafe fn d2i_err(
    as_: *mut SslSessionAsn1,
    ret: *mut SslSession,
    a: *mut *mut SslSession,
) -> *mut SslSession {
    // SAFETY: forwarded per the caller's contract.
    unsafe {
        asn1_free_as(as_);
        if a.is_null() || *a != ret {
            SSL_SESSION_free(ret);
        }
        // SAFETY: `ret` is a borrowed pointer; this is a pointer comparison, not a dereference.
    }
    ptr::null_mut()
}

/// `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/ssl_asn1.c:line`.
fn raise_ssl_asn1(reason: c_int, line: c_int) {
    // SAFETY: the error state is thread-local; `FILE` is static and `reason` a constant.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// `ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB)` — used by the peer-chain arms.
#[allow(dead_code)] // the chain arm is not reached for the sessions this crate builds
fn raise_x509() {
    // SAFETY: thread-local error state.
    unsafe { raise_with(ERR_LIB_X509, ERR_R_X509_LIB, FILE, 0) };
}

/// `ERR_raise(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB)` — used by the ex-data arms.
#[allow(dead_code)]
fn raise_crypto() {
    // SAFETY: thread-local error state.
    unsafe { raise_with(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB, FILE, 0) };
}

// `ERR_R_CRYPTO_LIB` is the coordinate the ex-data arms raise.
const _: c_int = ERR_R_CRYPTO_LIB;
