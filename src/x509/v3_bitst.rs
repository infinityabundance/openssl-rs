//! `crypto/x509/v3_bitst.c` — the `keyUsage` and `nsCertType` tables. Phase 10.14.6's table
//! layer, landed whole.
//!
//! `crypto/x509/v3_bitst.c` is 100 lines and transcribes whole: the two bit-name tables
//! (`ns_cert_type_table` `:16-26`, `key_usage_type_table` `:28-40`), the two `EXT_BITSTRING`
//! rows [`ossl_v3_nscert`] (`:42`) and [`ossl_v3_key_usage`] (`:43`), and the two shared
//! callbacks [`i2v_ASN1_BIT_STRING`] (`:45-65`) and [`v2i_ASN1_BIT_STRING`] (`:67-100`), which
//! are exports of their own (`x509v3.h`).
//!
//! ## The `EXT_BITSTRING` shape, and where the table goes
//!
//! `EXT_BITSTRING(nid, table)` is an `X509V3_EXT_METHOD` whose `it` is `ASN1_BIT_STRING_it` and
//! whose **`usr_data`** is the caller's `BIT_STRING_BITNAME` array; both callbacks read it back
//! through `method->usr_data`. The array is `-1`/NULL-terminated, and `key_usage_type_table` has
//! two rows for bit 1 (`nonRepudiation` canonical, `contentCommitment` an alias) — so the `i2v`
//! loop's "same bit number as the last row" test is what makes the first name canonical.
//!
//! ## Withheld by name
//!
//! `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in `v3_lib.rs` it feeds.
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456). The two
//! rows are unnameable from the admitted DSO; the item (`ASN1_BIT_STRING_it`) and the two
//! exported callbacks are the drivable surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_bitst.c` is **not** an entry in `gen_err_raise_sites.py` (the generator's
//! covered set is the closed-stratum file list), so its three coordinates are **declared
//! locally** with the `err_sites::ErrSite` shape, as `v3_conf.rs` does.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::bitstr::{ASN1_BIT_STRING_get_bit, ASN1_BIT_STRING_set_bit};
use crate::asn1::items::ASN1_BIT_STRING_it;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_BIT_STRING_new};
use crate::runtime::bio::sys::strcmp;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::obj::{NID_key_usage, NID_netscape_cert_type};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{X509V3ExtI2v, X509V3ExtMethod, X509V3ExtV2i};
use crate::x509::v3_utl::X509V3_add_value;

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_bitst.c` raise coordinate, declared locally (see the module doc).
const fn v3_bitst_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_bitst.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_ASN1_BIT_STRING`'s allocation failure at `v3_bitst.c:76`.
const V3_BITST_76: crate::runtime::err::err_sites::ErrSite =
    v3_bitst_site(76, c"v2i_ASN1_BIT_STRING", ERR_R_ASN1_LIB);
/// `v2i_ASN1_BIT_STRING`'s failed bit set at `v3_bitst.c:85`.
const V3_BITST_85: crate::runtime::err::err_sites::ErrSite =
    v3_bitst_site(85, c"v2i_ASN1_BIT_STRING", ERR_R_ASN1_LIB);
/// `v2i_ASN1_BIT_STRING`'s unknown argument at `v3_bitst.c:93`.
const V3_BITST_93: crate::runtime::err::err_sites::ErrSite = v3_bitst_site(
    93,
    c"v2i_ASN1_BIT_STRING",
    X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT,
);

/// `typedef struct { int bitnum; const char *lname; const char *sname; } BIT_STRING_BITNAME`
/// — `include/openssl/x509v3.h`.
///
/// One row of a bit-name table: the bit, its long (canonical) name and its short name.
#[repr(C)]
pub struct BitStringBitname {
    /// `int bitnum` — the bit index, or `-1` for the terminator.
    pub(crate) bitnum: c_int,
    /// `const char *lname` — NULL terminates the array.
    pub(crate) lname: *const c_char,
    /// `const char *sname`.
    pub(crate) sname: *const c_char,
}

const _: () = {
    assert!(core::mem::size_of::<BitStringBitname>() == 24);
    assert!(core::mem::offset_of!(BitStringBitname, bitnum) == 0);
    assert!(core::mem::offset_of!(BitStringBitname, lname) == 8);
    assert!(core::mem::offset_of!(BitStringBitname, sname) == 16);
};

// SAFETY: a bit-name row is fully initialised at compile time and never written; its two pointers
// borrow `'static` string literals. Claiming `Sync` is what lets the tables be `static` so the
// method rows can hold their addresses, the same reason `Asn1Item`/`Asn1Template` claim it.
unsafe impl Sync for BitStringBitname {}

/// `static BIT_STRING_BITNAME ns_cert_type_table[]` — `crypto/x509/v3_bitst.c:16-26`.
static NS_CERT_TYPE_TABLE: [BitStringBitname; 9] = [
    BitStringBitname {
        bitnum: 0,
        lname: c"SSL Client".as_ptr(),
        sname: c"client".as_ptr(),
    },
    BitStringBitname {
        bitnum: 1,
        lname: c"SSL Server".as_ptr(),
        sname: c"server".as_ptr(),
    },
    BitStringBitname {
        bitnum: 2,
        lname: c"S/MIME".as_ptr(),
        sname: c"email".as_ptr(),
    },
    BitStringBitname {
        bitnum: 3,
        lname: c"Object Signing".as_ptr(),
        sname: c"objsign".as_ptr(),
    },
    BitStringBitname {
        bitnum: 4,
        lname: c"Unused".as_ptr(),
        sname: c"reserved".as_ptr(),
    },
    BitStringBitname {
        bitnum: 5,
        lname: c"SSL CA".as_ptr(),
        sname: c"sslCA".as_ptr(),
    },
    BitStringBitname {
        bitnum: 6,
        lname: c"S/MIME CA".as_ptr(),
        sname: c"emailCA".as_ptr(),
    },
    BitStringBitname {
        bitnum: 7,
        lname: c"Object Signing CA".as_ptr(),
        sname: c"objCA".as_ptr(),
    },
    BitStringBitname {
        bitnum: -1,
        lname: ptr::null(),
        sname: ptr::null(),
    },
];

/// `static BIT_STRING_BITNAME key_usage_type_table[]` — `crypto/x509/v3_bitst.c:28-40`.
///
/// The two bit-1 rows are the authority's; `nonRepudiation` is canonical and
/// `contentCommitment` its alias, which the `i2v` "last seen bit" test depends on.
static KEY_USAGE_TYPE_TABLE: [BitStringBitname; 11] = [
    BitStringBitname {
        bitnum: 0,
        lname: c"Digital Signature".as_ptr(),
        sname: c"digitalSignature".as_ptr(),
    },
    BitStringBitname {
        bitnum: 1,
        lname: c"Non Repudiation".as_ptr(),
        sname: c"nonRepudiation".as_ptr(),
    },
    BitStringBitname {
        bitnum: 1,
        lname: c"Content Commitment".as_ptr(),
        sname: c"contentCommitment".as_ptr(),
    },
    BitStringBitname {
        bitnum: 2,
        lname: c"Key Encipherment".as_ptr(),
        sname: c"keyEncipherment".as_ptr(),
    },
    BitStringBitname {
        bitnum: 3,
        lname: c"Data Encipherment".as_ptr(),
        sname: c"dataEncipherment".as_ptr(),
    },
    BitStringBitname {
        bitnum: 4,
        lname: c"Key Agreement".as_ptr(),
        sname: c"keyAgreement".as_ptr(),
    },
    BitStringBitname {
        bitnum: 5,
        lname: c"Certificate Sign".as_ptr(),
        sname: c"keyCertSign".as_ptr(),
    },
    BitStringBitname {
        bitnum: 6,
        lname: c"CRL Sign".as_ptr(),
        sname: c"cRLSign".as_ptr(),
    },
    BitStringBitname {
        bitnum: 7,
        lname: c"Encipher Only".as_ptr(),
        sname: c"encipherOnly".as_ptr(),
    },
    BitStringBitname {
        bitnum: 8,
        lname: c"Decipher Only".as_ptr(),
        sname: c"decipherOnly".as_ptr(),
    },
    BitStringBitname {
        bitnum: -1,
        lname: ptr::null(),
        sname: ptr::null(),
    },
];

/// `STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method, ASN1_BIT_STRING *bits,
/// STACK_OF(CONF_VALUE) *ret)` — `crypto/x509/v3_bitst.c:45-65`.
///
/// One `CONF_VALUE` per **set** bit, named by the table row's long name, with a NULL value. The
/// "same bit number as the last row" skip is what keeps a name with an alias from emitting twice.
///
/// # Safety
///
/// `method` must be a live row whose `usr_data` is a `-1`-terminated `BIT_STRING_BITNAME`
/// array; `bits` is NULL or a live `ASN1_BIT_STRING`; `ret` is NULL or a live `CONF_VALUE` stack.
#[no_mangle]
pub unsafe extern "C" fn i2v_ASN1_BIT_STRING(
    method: *mut X509V3ExtMethod,
    bits: *mut c_void,
    ret: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let mut ret = ret;
    let mut last_seen_bit: c_int = -1;
    let bits = bits.cast::<Asn1String>();
    // SAFETY: `method` is live per the contract; `usr_data` is its own table.
    let mut bnam = unsafe { (*method).usr_data.cast::<BitStringBitname>() };
    // SAFETY: the table is NULL-`lname`-terminated per the contract.
    while !unsafe { (*bnam).lname }.is_null() {
        // SAFETY: `bnam` is a live row.
        let bitnum = unsafe { (*bnam).bitnum };
        if last_seen_bit != bitnum {
            last_seen_bit = bitnum;
            // SAFETY: `bits` is NULL or live per the contract.
            if unsafe { ASN1_BIT_STRING_get_bit(bits, bitnum) } != 0 {
                // SAFETY: `lname` is a static string; `ret` is this call's own sink.
                unsafe { X509V3_add_value((*bnam).lname, ptr::null(), &mut ret) };
            }
        }
        // SAFETY: advancing within the caller's table.
        bnam = unsafe { bnam.add(1) };
    }
    ret
}

/// Append the bytes of a NUL-terminated C string to a buffer (a `%s` operand).
///
/// # Safety
///
/// `s` must be NULL or NUL-terminated.
unsafe fn push_cstr(buf: &mut Vec<u8>, s: *const c_char) {
    if s.is_null() {
        buf.extend_from_slice(b"(null)");
        return;
    }
    // SAFETY: `s` is NUL-terminated per the contract.
    buf.extend_from_slice(unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes());
}

/// `ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_bitst.c:67-100`.
///
/// One config entry per bit, matched by short **or** long name; an unknown name is
/// `X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT`. The `v2i` slot's return type is `void *`, so the
/// built `ASN1_BIT_STRING` leaves as one.
///
/// # Safety
///
/// `method` must be a live row whose `usr_data` is a `-1`-terminated table; `nval` must be a live
/// stack of `CONF_VALUE` pointers.
#[no_mangle]
pub unsafe extern "C" fn v2i_ASN1_BIT_STRING(
    method: *mut X509V3ExtMethod,
    _ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    // SAFETY: no preconditions.
    let bs = ASN1_BIT_STRING_new();
    if bs.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_BITST_76) };
        return ptr::null_mut();
    }
    // SAFETY: `nval` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut i = 0;
    while i < num {
        // SAFETY: `nval` is live and `i` is in bounds.
        let val = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        // SAFETY: `method` is live per the contract.
        let mut bnam = unsafe { (*method).usr_data.cast::<BitStringBitname>() };
        // SAFETY: the table is NULL-`lname`-terminated per the contract.
        while !unsafe { (*bnam).lname }.is_null() {
            // SAFETY: `val` is a live `CONF_VALUE`; `bnam` a live row. Each comparison is
            // `strcmp` over NUL-terminated strings.
            let matched = unsafe {
                strcmp((*bnam).sname, (*val).name) == 0 || strcmp((*bnam).lname, (*val).name) == 0
            };
            if matched {
                // SAFETY: `bs` is a live bit string and `bnam` is a live row.
                if unsafe { ASN1_BIT_STRING_set_bit(bs, (*bnam).bitnum, 1) } == 0 {
                    // SAFETY: the site is a declared constant.
                    unsafe { raise_site(&V3_BITST_85) };
                    // SAFETY: `bs` is a live value this call owns.
                    unsafe { ASN1_BIT_STRING_free(bs) };
                    return ptr::null_mut();
                }
                break;
            }
            // SAFETY: advancing within the caller's table.
            bnam = unsafe { bnam.add(1) };
        }
        // SAFETY: `bnam` is at the matched row or the terminator.
        if unsafe { (*bnam).lname }.is_null() {
            // `ERR_raise_data(ERR_LIB_X509V3, X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT, "%s", val->name)`.
            let mut msg = Vec::new();
            // SAFETY: `val` is live and its `name` is NUL-terminated.
            unsafe { push_cstr(&mut msg, (*val).name) };
            msg.push(0);
            // SAFETY: `msg` is NUL-terminated; the site is a declared constant.
            unsafe { raise_site_data(&V3_BITST_93, msg.as_ptr().cast()) };
            // SAFETY: `bs` is a live value this call owns.
            unsafe { ASN1_BIT_STRING_free(bs) };
            return ptr::null_mut();
        }
        i += 1;
    }
    // The authority's `ASN1_BIT_STRING *` return, read as the `v2i` slot's `void *`.
    bs.cast::<c_void>()
}

/// The `i2v` slot for the `EXT_BITSTRING` rows, cast from [`i2v_ASN1_BIT_STRING`]'s `*mut` method
/// prototype to the slot's `*const` one.
const fn bitst_i2v() -> X509V3ExtI2v {
    // SAFETY: both function types take three pointer arguments and answer a pointer; the
    // authority writes exactly this cast in the `EXT_BITSTRING` macro.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(
                *mut X509V3ExtMethod,
                *mut c_void,
                *mut OpenSslStack,
            ) -> *mut OpenSslStack,
            unsafe extern "C" fn(
                *const X509V3ExtMethod,
                *mut c_void,
                *mut OpenSslStack,
            ) -> *mut OpenSslStack,
        >(i2v_ASN1_BIT_STRING)
    })
}

/// The `v2i` slot for the `EXT_BITSTRING` rows, cast the same way.
const fn bitst_v2i() -> X509V3ExtV2i {
    // SAFETY: both function types take three pointer arguments and answer a pointer; the
    // authority writes exactly this cast in the `EXT_BITSTRING` macro.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(
                *mut X509V3ExtMethod,
                *mut c_void,
                *mut OpenSslStack,
            ) -> *mut c_void,
            unsafe extern "C" fn(
                *const X509V3ExtMethod,
                *mut c_void,
                *mut OpenSslStack,
            ) -> *mut c_void,
        >(v2i_ASN1_BIT_STRING)
    })
}

/// `const X509V3_EXT_METHOD ossl_v3_nscert` — `crypto/x509/v3_bitst.c:42`, from
/// `EXT_BITSTRING(NID_netscape_cert_type, ns_cert_type_table)`.
pub static ossl_v3_nscert: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_netscape_cert_type,
    ext_flags: 0,
    it: Some(ASN1_BIT_STRING_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: bitst_i2v(),
    v2i: bitst_v2i(),
    i2r: None,
    r2i: None,
    usr_data: ptr::addr_of!(NS_CERT_TYPE_TABLE).cast_mut().cast(),
};

/// `const X509V3_EXT_METHOD ossl_v3_key_usage` — `crypto/x509/v3_bitst.c:43`, from
/// `EXT_BITSTRING(NID_key_usage, key_usage_type_table)`.
pub static ossl_v3_key_usage: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_key_usage,
    ext_flags: 0,
    it: Some(ASN1_BIT_STRING_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: bitst_i2v(),
    v2i: bitst_v2i(),
    i2r: None,
    r2i: None,
    usr_data: ptr::addr_of!(KEY_USAGE_TYPE_TABLE).cast_mut().cast(),
};
