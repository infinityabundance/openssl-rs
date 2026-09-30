//! Phase 10.1 — `providers/implementations/encode_decode/ml_common_codecs.c`: the shared
//! ASN.1 format tables and the one helper the ML-KEM and ML-DSA codec units stand on.
//!
//! This unit publishes **no provider row**. It is a *closure* unit of the two PQC codec units the
//! plan's §2 ordering correction names (D435): `ml_kem_codecs.c` and `ml_dsa_codecs.c` are the
//! eleven row-publishers' first blockers, and this is the helper they share. Its whole observable
//! content is `ossl_ml_common_pkcs8_fmt_order` — the format-name preference ordering — plus the
//! `ML_COMMON_PKCS8_FMT`/`ML_COMMON_SPKI_FMT` shapes the per-variant tables of both units are.
//!
//! ## The format order is selection, and its refusal is observable
//!
//! A PKCS#8 `PrivateKeyInfo` for an ML-KEM or ML-DSA key may be any of six shapes (`seed-priv`,
//! `priv-only`, `oqskeypair`, `seed-only`, `bare-priv`, `bare-seed`), and the `input-formats`/
//! `output-formats` provider parameters select which are tried and in what order. The order is
//! observable through which shape a decode accepts and which an encode emits, and the *refusal* —
//! `PROV_R_ML_DSA_NO_FORMAT` with `no %s private key %s formats are enabled` — is a coordinate the
//! court reads. Zero preferences sort last, which is what makes the compile-time table order the
//! default.
//!
//! ## The byte-order helpers are here rather than in `byteorder.h`
//!
//! The two codec units read and write the DER wrappers' tag/length words through
//! `<openssl/byteorder.h>`'s `OPENSSL_load_u32_be`/`_u16_be` and their `store` siblings. The crate
//! has no shared transcription of that header (each unit that needs one writes the two or four
//! functions it uses, as `src/ml_dsa/encoders.rs` does for the little-endian pair), so the four
//! big-endian forms live here, beside the tables whose `p8_magic`/`seed_magic`/`priv_magic` words
//! they decode.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// `ossl_ml_common_pkcs8_fmt_order` and the four byte-order helpers are reached from the codec
// units' `d2i`/`i2d` half, which `decode_der2key.c` and `encode_key2any.c` will call once they land.
#![allow(dead_code)]

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::runtime::err::{err_sites, raise_site_data};
use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_free};
use crate::runtime::str::OPENSSL_strncasecmp;

/// `ML_COMMON_SPKI_OVERHEAD` — `ml_common_codecs.h:29`. The 22 bytes every ML-KEM/ML-DSA
/// `SubjectPublicKeyInfo` prepends to the raw public key: a 4-byte outer sequence tag/length, a
/// 2-byte algorithm sequence tag/length, a 2-byte OID tag/length, the 9-byte NIST CSOR OID, a
/// 4-byte bit-string tag/length and the one bit-string lead byte.
pub(crate) const ML_COMMON_SPKI_OVERHEAD: usize = 22;

/// `NUM_PKCS8_FORMATS` — `ml_common_codecs.h:67`. Six shapes per parameter set: `seed-priv`,
/// `priv-only`, `oqskeypair`, `seed-only`, `bare-priv` and `bare-seed`.
pub(crate) const NUM_PKCS8_FORMATS: usize = 6;

/// The unit's own `__FILE__`. `ml_common_codecs.c` is a plain `.c`, so the compiler records the
/// source-tree path with the build's relative prefix (D235).
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/encode_decode/ml_common_codecs.c".as_ptr();
/// `ml_common_codecs.c:45`, `OPENSSL_calloc(NUM_PKCS8_FORMATS + 1, sizeof(*ret))`.
const LINE_CALLOC: c_int = 45;
/// `ml_common_codecs.c:82`, the no-format arm's `OPENSSL_free(ret)`.
const LINE_FREE: c_int = 82;

/// `ML_COMMON_SPKI_FMT` — `ml_common_codecs.h:30-32`: the fixed 22-byte prefix of one parameter
/// set's `SubjectPublicKeyInfo`.
#[repr(C)]
pub(crate) struct MlCommonSpkiFmt {
    /// `const uint8_t asn1_prefix[ML_COMMON_SPKI_OVERHEAD]`.
    pub(crate) asn1_prefix: [u8; ML_COMMON_SPKI_OVERHEAD],
}

// SAFETY: the prefix is plain bytes; a `static` of this type is immutable and shared read-only.
unsafe impl Sync for MlCommonSpkiFmt {}

/// `ML_COMMON_PKCS8_FMT` — `ml_common_codecs.h:69-82`, field for field. A length of zero means the
/// field is absent; `p8_shift` is 0 when the top-level tag+length occupy four bytes, 2 when two,
/// and 4 when no tag is used at all.
#[repr(C)]
pub(crate) struct MlCommonPkcs8Fmt {
    /// `const char *p8_name` — the format name.
    pub(crate) p8_name: *const c_char,
    /// `size_t p8_bytes` — total P8 encoding length.
    pub(crate) p8_bytes: usize,
    /// `int p8_shift` — `4 - (top-level tag + len)`.
    pub(crate) p8_shift: c_int,
    /// `uint32_t p8_magic` — the tag + len value.
    pub(crate) p8_magic: u32,
    /// `uint16_t seed_magic` — interior tag + len for the seed.
    pub(crate) seed_magic: u16,
    /// `size_t seed_offset` — seed offset from start.
    pub(crate) seed_offset: usize,
    /// `size_t seed_length` — seed bytes.
    pub(crate) seed_length: usize,
    /// `uint32_t priv_magic` — interior tag + len for the key.
    pub(crate) priv_magic: u32,
    /// `size_t priv_offset` — key offset from start.
    pub(crate) priv_offset: usize,
    /// `size_t priv_length` — key bytes.
    pub(crate) priv_length: usize,
    /// `size_t pub_offset` — pubkey offset.
    pub(crate) pub_offset: usize,
    /// `size_t pub_length` — pubkey bytes.
    pub(crate) pub_length: usize,
}

// SAFETY: every pointer is to a `'static` C string literal; the tables are immutable and shared.
unsafe impl Sync for MlCommonPkcs8Fmt {}

/// `ML_COMMON_CODEC` — `ml_common_codecs.h:84-87`: one variant's SPKI prefix and PKCS#8 table.
#[repr(C)]
pub(crate) struct MlCommonCodec {
    /// `const ML_COMMON_SPKI_FMT *spkifmt`.
    pub(crate) spkifmt: *const MlCommonSpkiFmt,
    /// `const ML_COMMON_PKCS8_FMT *p8fmt`.
    pub(crate) p8fmt: *const MlCommonPkcs8Fmt,
}

// SAFETY: both pointers are to `'static` tables of plain data; the table is shared read-only.
unsafe impl Sync for MlCommonCodec {}

/// `ML_COMMON_PKCS8_FMT_PREF` — `ml_common_codecs.h:89-92`: a table slot and its preference. A
/// preference of 0 sorts last (the slot is not selected).
#[repr(C)]
pub(crate) struct MlCommonPkcs8FmtPref {
    /// `const ML_COMMON_PKCS8_FMT *fmt`.
    pub(crate) fmt: *const MlCommonPkcs8Fmt,
    /// `int pref`.
    pub(crate) pref: c_int,
}

/// `OPENSSL_load_u16_be(&accum, in)` — `<openssl/byteorder.h>`, returns `in + 2`.
///
/// # Safety
/// `in_` must be readable for two bytes.
#[inline]
pub(crate) unsafe fn load_u16_be(in_: *const u8, accum: &mut u16) -> *const u8 {
    let mut bytes = [0u8; 2];
    // SAFETY: `in_` is readable for two bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(in_, bytes.as_mut_ptr(), 2) };
    *accum = u16::from_be_bytes(bytes);
    // SAFETY: the pointer arithmetic stays within the object `in_` names.
    unsafe { in_.add(2) }
}

/// `OPENSSL_load_u32_be(&accum, in)` — `<openssl/byteorder.h>`, returns `in + 4`.
///
/// # Safety
/// `in_` must be readable for four bytes.
#[inline]
pub(crate) unsafe fn load_u32_be(in_: *const u8, accum: &mut u32) -> *const u8 {
    let mut bytes = [0u8; 4];
    // SAFETY: `in_` is readable for four bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(in_, bytes.as_mut_ptr(), 4) };
    *accum = u32::from_be_bytes(bytes);
    // SAFETY: the pointer arithmetic stays within the object `in_` names.
    unsafe { in_.add(4) }
}

/// `OPENSSL_store_u16_be(out, v)` — `<openssl/byteorder.h>`, returns `out + 2`.
///
/// # Safety
/// `out` must be writable for two bytes.
#[inline]
pub(crate) unsafe fn store_u16_be(out: *mut u8, v: u16) -> *mut u8 {
    let bytes = v.to_be_bytes();
    // SAFETY: `out` is writable for two bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, 2) };
    // SAFETY: the pointer arithmetic stays within the object `out` names.
    unsafe { out.add(2) }
}

/// `OPENSSL_store_u32_be(out, v)` — `<openssl/byteorder.h>`, returns `out + 4`.
///
/// # Safety
/// `out` must be writable for four bytes.
#[inline]
pub(crate) unsafe fn store_u32_be(out: *mut u8, v: u32) -> *mut u8 {
    let bytes = v.to_be_bytes();
    // SAFETY: `out` is writable for four bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, 4) };
    // SAFETY: the pointer arithmetic stays within the object `out` names.
    unsafe { out.add(4) }
}

/// `static int pref_cmp(const void *va, const void *vb)` — `ml_common_codecs.c:16-32`.
///
/// Zeros sort last; otherwise the sort is by increasing preference. The authority's own comment
/// notes the comparator is transitive only because the preferences are small enough, and the
/// equivalent total order is the one used here: a preference of 0 is mapped above every nonzero one.
fn pref_order_key(pref: c_int) -> i64 {
    if pref > 0 {
        i64::from(pref)
    } else {
        i64::MAX
    }
}

/// `strspn(fmt, "\t ,")` — the length of the leading run of separator characters.
///
/// # Safety
/// `p` must point into a NUL-terminated string.
unsafe fn span_separators(p: *const c_char) -> usize {
    let separators = b"\t ,";
    let mut i = 0usize;
    // SAFETY: `p` is inside a NUL-terminated string per the contract.
    unsafe {
        while *p.add(i) != 0 && separators.contains(&(*p.add(i) as u8)) {
            i += 1;
        }
    }
    i
}

/// `strcspn(fmt, "\t ,")` — the length of the leading run of non-separator characters.
///
/// # Safety
/// `p` must point into a NUL-terminated string.
unsafe fn span_non_separators(p: *const c_char) -> usize {
    let separators = b"\t ,";
    let mut i = 0usize;
    // SAFETY: `p` is inside a NUL-terminated string per the contract.
    unsafe {
        while *p.add(i) != 0 && !separators.contains(&(*p.add(i) as u8)) {
            i += 1;
        }
    }
    i
}

/// Raise the no-format refusal of `ml_common_codecs.c:83-86`, whose message interpolates the
/// algorithm name and the direction.
///
/// # Safety
/// `algorithm_name` and `direction` must be NUL-terminated.
unsafe fn raise_no_format(algorithm_name: *const c_char, direction: *const c_char) {
    // SAFETY: both arguments are NUL-terminated per the contract.
    let alg = unsafe { core::ffi::CStr::from_ptr(algorithm_name) }.to_bytes();
    // SAFETY: as above.
    let dir = unsafe { core::ffi::CStr::from_ptr(direction) }.to_bytes();
    let mut msg = Vec::with_capacity(alg.len() + dir.len() + 40);
    msg.extend_from_slice(b"no ");
    msg.extend_from_slice(alg);
    msg.extend_from_slice(b" private key ");
    msg.extend_from_slice(dir);
    msg.extend_from_slice(b" formats are enabled");
    msg.push(0);
    // SAFETY: `msg` is NUL-terminated just above.
    unsafe { raise_site_data(&err_sites::ML_COMMON_CODECS_83, msg.as_ptr().cast()) };
}

/// `ML_COMMON_PKCS8_FMT_PREF *ossl_ml_common_pkcs8_fmt_order(const char *algorithm_name,`
/// `const ML_COMMON_PKCS8_FMT *p8fmt, const char *direction, const char *formats)` —
/// `ml_common_codecs.c:34-93`.
///
/// The returned array has `NUM_PKCS8_FORMATS` slots plus one reserved terminator; the selected
/// slots come first in preference order and the list is terminated by a NULL `fmt` at the first
/// unselected slot. The caller frees it with `OPENSSL_free`. A `formats` of NULL keeps the
/// compile-time table order.
///
/// # Safety
/// `algorithm_name` and `direction` are NUL-terminated; `p8fmt` is a live `NUM_PKCS8_FORMATS`-element
/// table; `formats` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_ml_common_pkcs8_fmt_order(
    algorithm_name: *const c_char,
    p8fmt: *const MlCommonPkcs8Fmt,
    direction: *const c_char,
    formats: *const c_char,
) -> *mut MlCommonPkcs8FmtPref {
    // SAFETY: the allocation's arguments are the authority's own.
    let ret = CRYPTO_calloc(
        NUM_PKCS8_FORMATS + 1,
        core::mem::size_of::<MlCommonPkcs8FmtPref>(),
        FILE,
        LINE_CALLOC,
    )
    .cast::<MlCommonPkcs8FmtPref>();
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ret` has NUM_PKCS8_FORMATS + 1 slots; `p8fmt` has NUM_PKCS8_FORMATS entries.
    unsafe {
        for i in 0..NUM_PKCS8_FORMATS {
            (*ret.add(i)).fmt = p8fmt.add(i);
            (*ret.add(i)).pref = 0;
        }
    }

    // Default to compile-time table order when none specified.
    if formats.is_null() {
        return ret;
    }

    let mut fmt = formats;
    let mut count = 0usize;
    // SAFETY: `ret` has NUM_PKCS8_FORMATS slots and `fmt` walks a NUL-terminated string.
    unsafe {
        loop {
            fmt = fmt.add(span_separators(fmt));
            if *fmt == 0 {
                break;
            }
            let end = fmt.add(span_non_separators(fmt));
            let len = end.offset_from(fmt) as usize;
            for i in 0..NUM_PKCS8_FORMATS {
                // Skip slots already selected or with a different name.
                if (*ret.add(i)).pref > 0
                    || OPENSSL_strncasecmp((*(*ret.add(i)).fmt).p8_name, fmt, len) != 0
                {
                    continue;
                }
                // First time match.
                count += 1;
                (*ret.add(i)).pref = count as c_int;
                break;
            }
            fmt = end;
            if count >= NUM_PKCS8_FORMATS {
                break;
            }
        }
    }

    // No formats matched, raise an error.
    if count == 0 {
        // SAFETY: `ret` is this frame's allocation.
        unsafe { CRYPTO_free(ret.cast(), FILE, LINE_FREE) };
        // SAFETY: both strings are NUL-terminated per the contract.
        unsafe { raise_no_format(algorithm_name, direction) };
        return ptr::null_mut();
    }

    // Sort by preference, with 0's last.
    // SAFETY: `ret`'s first NUM_PKCS8_FORMATS slots are initialised.
    let selected = unsafe { core::slice::from_raw_parts_mut(ret, NUM_PKCS8_FORMATS) };
    selected.sort_by_key(|slot| pref_order_key(slot.pref));
    // Terminate the list at first unselected entry, perhaps reserved slot.
    // SAFETY: `count < NUM_PKCS8_FORMATS + 1`, so `ret.add(count)` is within the allocation.
    unsafe { (*ret.add(count)).fmt = ptr::null() };
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The six-row table the tests order; only the names matter to `ossl_ml_common_pkcs8_fmt_order`.
    static NAMES: [&core::ffi::CStr; NUM_PKCS8_FORMATS] = [
        c"seed-priv",
        c"priv-only",
        c"oqskeypair",
        c"seed-only",
        c"bare-priv",
        c"bare-seed",
    ];

    fn table() -> [MlCommonPkcs8Fmt; NUM_PKCS8_FORMATS] {
        core::array::from_fn(|i| MlCommonPkcs8Fmt {
            p8_name: NAMES[i].as_ptr(),
            p8_bytes: 0,
            p8_shift: 0,
            p8_magic: 0,
            seed_magic: 0,
            seed_offset: 0,
            seed_length: 0,
            priv_magic: 0,
            priv_offset: 0,
            priv_length: 0,
            pub_offset: 0,
            pub_length: 0,
        })
    }

    /// Collect the selected names from a returned list, stopping at the NULL terminator.
    ///
    /// # Safety
    /// `list` must be a list `ossl_ml_common_pkcs8_fmt_order` returned.
    unsafe fn names(list: *const MlCommonPkcs8FmtPref) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if list.is_null() {
            return out;
        }
        // SAFETY: the list is terminated just past the selected slots.
        unsafe {
            let mut i = 0usize;
            loop {
                let fmt = (*list.add(i)).fmt;
                if fmt.is_null() {
                    break;
                }
                out.push(
                    core::ffi::CStr::from_ptr((*fmt).p8_name)
                        .to_bytes()
                        .to_vec(),
                );
                i += 1;
            }
        }
        out
    }

    /// No `formats` string leaves the compile-time table order: all six slots, in order.
    #[test]
    fn a_null_format_list_keeps_the_table_order() {
        let _g = crate::test_support::lock_global_state();
        let t = table();
        // SAFETY: the table and the two strings are live for the call.
        let list = unsafe {
            ossl_ml_common_pkcs8_fmt_order(
                c"ML-KEM-512".as_ptr(),
                t.as_ptr(),
                c"input".as_ptr(),
                core::ptr::null(),
            )
        };
        assert!(!list.is_null());
        assert_eq!(
            // SAFETY: `names` reads a list this call returned.
            unsafe { names(list) },
            vec![
                b"seed-priv".to_vec(),
                b"priv-only".to_vec(),
                b"oqskeypair".to_vec(),
                b"seed-only".to_vec(),
                b"bare-priv".to_vec(),
                b"bare-seed".to_vec()
            ]
        );
        // SAFETY: `list` is this frame's allocation.
        unsafe { CRYPTO_free(list.cast(), FILE, LINE_FREE) };
    }

    /// A selection string picks the named formats in the order they are listed, and the unselected
    /// ones sort after them (the terminator is at the first unselected slot).
    #[test]
    fn a_format_list_selects_in_order_and_zeroes_sort_last() {
        let _g = crate::test_support::lock_global_state();
        let t = table();
        // SAFETY: the table and the string are live for the call.
        let list = unsafe {
            ossl_ml_common_pkcs8_fmt_order(
                c"ML-DSA-44".as_ptr(),
                t.as_ptr(),
                c"output".as_ptr(),
                c"bare-seed seed-only".as_ptr(),
            )
        };
        assert!(!list.is_null());
        // SAFETY: `names` reads a list this call returned.
        let got = unsafe { names(list) };
        assert_eq!(got, vec![b"bare-seed".to_vec(), b"seed-only".to_vec()]);
        // SAFETY: `list` is this frame's allocation.
        unsafe { CRYPTO_free(list.cast(), FILE, LINE_FREE) };
    }

    /// A selection string naming nothing raises `PROV_R_ML_DSA_NO_FORMAT` and answers NULL.
    #[test]
    fn an_unmatched_format_list_refuses() {
        let _g = crate::test_support::lock_global_state();
        let t = table();
        crate::runtime::err::ERR_clear_error();
        // SAFETY: the table and the string are live for the call.
        let list = unsafe {
            ossl_ml_common_pkcs8_fmt_order(
                c"ML-KEM-768".as_ptr(),
                t.as_ptr(),
                c"input".as_ptr(),
                c"nosuchformat".as_ptr(),
            )
        };
        assert!(list.is_null());
        // The queue's last entry is the refusal, at `ERR_LIB_PROV` (`proverr.h`) and
        // `PROV_R_ML_DSA_NO_FORMAT`.
        assert_eq!(crate::runtime::err::peek_last_lib(), 57);
        assert_eq!(
            crate::runtime::err::peek_last_reason(),
            crate::runtime::err::err_reasons::PROV_R_ML_DSA_NO_FORMAT as u64
        );
        crate::runtime::err::ERR_clear_error();
    }

    /// The big-endian helpers round-trip and advance by their width.
    #[test]
    fn the_big_endian_helpers_round_trip() {
        let mut buf = [0u8; 6];
        // SAFETY: `buf` is writable for six bytes and each helper stays within it.
        unsafe {
            let p = store_u32_be(buf.as_mut_ptr(), 0x3082_06a6);
            let p = store_u16_be(p, 0x0440);
            assert_eq!(p.offset_from(buf.as_ptr()), 6);
        }
        assert_eq!(buf, [0x30, 0x82, 0x06, 0xa6, 0x04, 0x40]);
        // SAFETY: `buf` is readable for six bytes.
        unsafe {
            let mut v32 = 0u32;
            let mut v16 = 0u16;
            let mut p = load_u32_be(buf.as_ptr(), &mut v32);
            p = load_u16_be(p, &mut v16);
            assert_eq!(p.offset_from(buf.as_ptr()), 6);
            assert_eq!(v32, 0x3082_06a6);
            assert_eq!(v16, 0x0440);
        }
    }
}
