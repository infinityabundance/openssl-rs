//! `crypto/ec/eck_prn.c` — the deprecated `ECPKParameters` printers — and `ec_ameth.c`'s
//! `ECParameters_print`, Phase 8.7 (D347).
//!
//! **Four exports and one file-local helper, and one withheld function named rather than
//! stubbed.** `crypto/ec/eck_prn.c` is 259 lines whose whole body sits inside
//! `#ifndef OPENSSL_NO_DEPRECATED_3_0`; it defines `ECPKParameters_print` (`:70-221`) and its
//! three `FILE *`/key wrappers `ECPKParameters_print_fp` (`:21-34`), `EC_KEY_print_fp`
//! (`:36-49`) and `ECParameters_print_fp` (`:51-64`), plus the file-local `print_bin`
//! (`:223-258`). The four landed here are those minus `EC_KEY_print_fp`:
//!
//! * [`ECPKParameters_print`] — `crypto/ec/eck_prn.c:70-221`;
//! * [`ECPKParameters_print_fp`] — `:21-34`;
//! * [`ECParameters_print_fp`] — `:51-64`, which wraps the `FILE *` and calls the next;
//! * [`ECParameters_print`] — `crypto/ec/ec_ameth.c:717-720`, the `EC_KEY_PRINT_PARAM` arm of
//!   that unit's `static do_EC_KEY_print` (`:283-345`).
//!
//! ## `EC_KEY_print_fp` is withheld, and why
//!
//! `EC_KEY_print_fp` (`eck_prn.c:36-49`) calls `EC_KEY_print` (`ec_ameth.c:709-714`), which is
//! the `EC_KEY_PRINT_PRIVATE` arm of `do_EC_KEY_print`. That export is **not** this module's and
//! is withheld with the rest of `ec_ameth.c`'s `EVP_PKEY_ASN1_METHOD` surface (D341): the object
//! whose callbacks reach it is the one Phase 11 unblocks. It is named here rather than
//! transcribed as a wrapper for a symbol the crate does not define.
//!
//! ## `ECParameters_print` is `ec_ameth.c`'s, and it is transcribed where it can be reached
//!
//! Its authority body is `return do_EC_KEY_print(bp, x, 4, EC_KEY_PRINT_PARAM);`, and the
//! `PARAM` arm reads **no** private or public buffer — the two `EC_KEY_key2buf`/`EC_KEY_priv2buf`
//! reads are guarded by `ktype != EC_KEY_PRINT_PARAM` and `ktype == EC_KEY_PRINT_PRIVATE`
//! (`ec_ameth.c:296`, `:302`), so the arm this export selects is the print of the group's
//! parameters and nothing else. It is written out as that arm rather than as a three-way
//! `do_EC_KEY_print`, because the other two arms belong to `EC_KEY_print` above.
//!
//! ## The raise coordinates are generated, not reconstructed
//!
//! `eck_prn.c` and `ec_ameth.c` both joined `gen_err_raise_sites.py`'s `COVERED_FILES` with this
//! module (D347), so the four `eck_prn.c` sites (`:27`, `:42`, `:57`, the dynamic `:214`) and the
//! two `ec_ameth.c` sites (`:292`, `:341`) are the generator's own constants rather than the
//! hand-written expansion [`crate::dh::prn`] had to use for `dh_prn.c`. `ECParameters_print`'s
//! null refusal is `ERR_R_PASSED_NULL_PARAMETER` and its failure tail `ERR_R_EC_LIB`, both at
//! `ec_ameth.c`, exactly as the authority writes them.
//!
//! ## The court: `RT-EC`
//!
//! `RT-EC` prints a named curve's parameters into a memory BIO and observes the first bytes
//! (the four-space indent and `ASN1 OID:`), drives `ECParameters_print` on a key built from a
//! named curve, and drains the null refusal at its authority coordinate. **No arm prints a key**
//! — the parameters of a named curve are a public constant, and no arm calls a printer on a key
//! with a private scalar.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::t_pkey::ASN1_bn_print;
use crate::bn::bignum::{BN_free, BN_new, BigNum};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new, BnCtx};
use crate::ec::curve::EC_curve_nid2nist;
use crate::ec::key::EC_KEY_get0_group;
use crate::ec::lib::{
    EC_GROUP_get0_cofactor, EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_GROUP_get0_seed,
    EC_GROUP_get_asn1_flag, EC_GROUP_get_basis_type, EC_GROUP_get_curve, EC_GROUP_get_curve_name,
    EC_GROUP_get_field_type, EC_GROUP_get_point_conversion_form, EC_GROUP_get_seed_len,
    EC_GROUP_order_bits,
};
use crate::ec::oct::EC_POINT_point2buf;
use crate::ec::{EcGroup, EcKey, POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_UNCOMPRESSED};
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR, BIO_NOCLOSE};
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic};
use crate::runtime::mem::CRYPTO_clear_free;
use crate::runtime::obj::{NID_X9_62_characteristic_two_field, OBJ_nid2sn};

/// `print_bin(BIO *fp, const char *name, const unsigned char *buf, size_t len, int off)` —
/// `crypto/ec/eck_prn.c:223-258`.
///
/// A NULL `buf` answers success without writing — which is why the two callers can guard with
/// `gen_buf != NULL`/`seed != NULL` and still be transcription-faithful. The layout is the
/// authority's: the name, then a newline and `off + 4` spaces every fifteen octets, each octet as
/// two lower-case hex digits separated by `:` except the last. The `memset(&str[1], ' ', off + 4)`
/// means the **first** line's bytes are written from the buffer even when `off == 0`, which is why
/// the write length is `off + 1 + 4` and not `off`.
///
/// # Safety
///
/// `fp` is a live BIO; `name` is a NUL-terminated string; `buf` is NULL or readable for `len`
/// bytes.
unsafe fn print_bin(
    fp: *mut Bio,
    name: *const c_char,
    buf: *const c_uchar,
    len: usize,
    mut off: c_int,
) -> c_int {
    // `char str[128 + 1 + 4];` — the authority's own buffer width, and `off` is clamped to 128 so
    // a full line never overruns it.
    let mut str_buf = [0u8; 128 + 1 + 4];
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if buf.is_null() {
            return 1;
        }
        if off > 0 {
            if off > 128 {
                off = 128;
            }
            ptr::write_bytes(str_buf.as_mut_ptr(), b' ', off as usize);
            if BIO_write(fp, str_buf.as_ptr().cast::<c_void>(), off) <= 0 {
                return 0;
            }
        } else {
            off = 0;
        }

        if BIO_printf(fp, c"%s".as_ptr(), name) <= 0 {
            return 0;
        }

        let mut i: usize = 0;
        while i < len {
            if i.is_multiple_of(15) {
                str_buf[0] = b'\n';
                ptr::write_bytes(str_buf.as_mut_ptr().add(1), b' ', (off + 4) as usize);
                if BIO_write(fp, str_buf.as_ptr().cast::<c_void>(), off + 1 + 4) <= 0 {
                    return 0;
                }
            }
            let sep: *const c_char = if i + 1 == len {
                c"".as_ptr()
            } else {
                c":".as_ptr()
            };
            if BIO_printf(fp, c"%02x%s".as_ptr(), c_int::from(buf.add(i).read()), sep) <= 0 {
                return 0;
            }
            i += 1;
        }
        if BIO_write(fp, c"\n".as_ptr().cast::<c_void>(), 1) <= 0 {
            return 0;
        }
        1
    }
}

/// `int ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off)` —
/// `crypto/ec/eck_prn.c:70-221`.
///
/// Two arms: an `OPENSSL_EC_NAMED_CURVE` group prints its OID and, when it has one, its NIST
/// short name; any other prints the explicit parameters — field type, the polynomial or prime,
/// `a`, `b`, the generator in the group's conversion form, the order, the optional cofactor and
/// the optional seed. Every refusal is collected into `reason` and raised **once** at the tail;
/// the `EC_R_*` values some arms leave unset are the initial `ERR_R_BIO_LIB`.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is a live group.
#[no_mangle]
pub unsafe extern "C" fn ECPKParameters_print(
    bp: *mut Bio,
    x: *const EcGroup,
    off: c_int,
) -> c_int {
    let mut ret: c_int = 0;
    let mut reason: c_int = ERR_R_BIO_LIB;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut p: *mut BigNum = ptr::null_mut();
    let mut a: *mut BigNum = ptr::null_mut();
    let mut b: *mut BigNum = ptr::null_mut();
    let mut gen_buf: *mut c_uchar = ptr::null_mut();
    let mut gen_buf_len: usize = 0;
    let mut seed: *mut c_uchar = ptr::null_mut();
    let mut seed_len: usize = 0;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            if x.is_null() {
                // `reason = ERR_R_PASSED_NULL_PARAMETER` — the site's dynamic arm carries it.
                reason = ERR_R_PASSED_NULL_PARAMETER;
                break 'err;
            }

            ctx = BN_CTX_new();
            if ctx.is_null() {
                reason = ERR_R_BN_LIB;
                break 'err;
            }

            if EC_GROUP_get_asn1_flag(x) != 0 {
                // The parameters are given by an ASN.1 OID.
                if BIO_indent(bp, off, 128) == 0 {
                    break 'err;
                }
                let nid = EC_GROUP_get_curve_name(x);
                if nid == 0 {
                    break 'err;
                }
                if BIO_printf(bp, c"ASN1 OID: %s".as_ptr(), OBJ_nid2sn(nid)) <= 0 {
                    break 'err;
                }
                if BIO_printf(bp, c"\n".as_ptr()) <= 0 {
                    break 'err;
                }
                let nname = EC_curve_nid2nist(nid);
                if !nname.is_null() {
                    if BIO_indent(bp, off, 128) == 0 {
                        break 'err;
                    }
                    if BIO_printf(bp, c"NIST CURVE: %s\n".as_ptr(), nname) <= 0 {
                        break 'err;
                    }
                }
            } else {
                // Explicit parameters.
                let is_char_two =
                    c_int::from(EC_GROUP_get_field_type(x) == NID_X9_62_characteristic_two_field);

                p = BN_new();
                a = BN_new();
                b = BN_new();
                if p.is_null() || a.is_null() || b.is_null() {
                    reason = ERR_R_BN_LIB;
                    break 'err;
                }
                if EC_GROUP_get_curve(x, p, a, b, ctx) == 0 {
                    reason = ERR_R_EC_LIB;
                    break 'err;
                }
                let point = EC_GROUP_get0_generator(x);
                if point.is_null() {
                    reason = ERR_R_EC_LIB;
                    break 'err;
                }
                let order = EC_GROUP_get0_order(x);
                let cofactor = EC_GROUP_get0_cofactor(x);
                if order.is_null() {
                    reason = ERR_R_EC_LIB;
                    break 'err;
                }

                let form = EC_GROUP_get_point_conversion_form(x);
                gen_buf_len = EC_POINT_point2buf(x, point, form, &mut gen_buf, ctx);
                if gen_buf_len == 0 {
                    reason = ERR_R_EC_LIB;
                    break 'err;
                }

                let s = EC_GROUP_get0_seed(x);
                if !s.is_null() {
                    seed = s;
                    seed_len = EC_GROUP_get_seed_len(x);
                }

                if BIO_indent(bp, off, 128) == 0 {
                    break 'err;
                }
                if BIO_printf(
                    bp,
                    c"Field Type: %s\n".as_ptr(),
                    OBJ_nid2sn(EC_GROUP_get_field_type(x)),
                ) <= 0
                {
                    break 'err;
                }

                if is_char_two != 0 {
                    let basis_type = EC_GROUP_get_basis_type(x);
                    if basis_type == 0 {
                        break 'err;
                    }
                    if BIO_indent(bp, off, 128) == 0 {
                        break 'err;
                    }
                    if BIO_printf(bp, c"Basis Type: %s\n".as_ptr(), OBJ_nid2sn(basis_type)) <= 0 {
                        break 'err;
                    }
                    if !p.is_null()
                        && ASN1_bn_print(bp, c"Polynomial:".as_ptr(), p, ptr::null_mut(), off) == 0
                    {
                        break 'err;
                    }
                } else if !p.is_null()
                    && ASN1_bn_print(bp, c"Prime:".as_ptr(), p, ptr::null_mut(), off) == 0
                {
                    break 'err;
                }
                if !a.is_null()
                    && ASN1_bn_print(bp, c"A:   ".as_ptr(), a, ptr::null_mut(), off) == 0
                {
                    break 'err;
                }
                if !b.is_null()
                    && ASN1_bn_print(bp, c"B:   ".as_ptr(), b, ptr::null_mut(), off) == 0
                {
                    break 'err;
                }

                let form_str: *const c_char = if form == POINT_CONVERSION_COMPRESSED {
                    c"Generator (compressed):".as_ptr()
                } else if form == POINT_CONVERSION_UNCOMPRESSED {
                    c"Generator (uncompressed):".as_ptr()
                } else {
                    c"Generator (hybrid):".as_ptr()
                };
                if !gen_buf.is_null() && print_bin(bp, form_str, gen_buf, gen_buf_len, off) == 0 {
                    break 'err;
                }

                if !order.is_null()
                    && ASN1_bn_print(bp, c"Order: ".as_ptr(), order, ptr::null_mut(), off) == 0
                {
                    break 'err;
                }
                if !cofactor.is_null()
                    && ASN1_bn_print(bp, c"Cofactor: ".as_ptr(), cofactor, ptr::null_mut(), off)
                        == 0
                {
                    break 'err;
                }
                if !seed.is_null() && print_bin(bp, c"Seed:".as_ptr(), seed, seed_len, off) == 0 {
                    break 'err;
                }
            }
            ret = 1;
        }

        if ret == 0 {
            // SAFETY: `ECK_PRN_214` is the generated dynamic-reason site at `eck_prn.c:214`.
            raise_site_dynamic(&err_sites::ECK_PRN_214, reason);
        }
        BN_free(p);
        BN_free(a);
        BN_free(b);
        CRYPTO_clear_free(gen_buf.cast::<c_void>(), gen_buf_len, FILE, 218);
        BN_CTX_free(ctx);
        ret
    }
}

/// The translation unit the two `ECK_PRN` printer sites below are attributed to, with the
/// admitted build record's `../../src/openssl-3.6.4/` prefix that its compiled `__FILE__`
/// carries.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/eck_prn.c".as_ptr();

/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h`, `258 | ERR_R_FATAL`, where
/// `ERR_R_FATAL` is `ERR_RFLAG_FATAL | ERR_RFLAG_COMMON`. The value the `reason` variable holds
/// when `ECPKParameters_print` refuses a NULL group.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | ((0x1 << 18) | (0x2 << 18));

/// `ERR_R_BIO_LIB` — `include/openssl/err.h`, `ERR_LIB_BIO (2) | ERR_RFLAG_COMMON (0x2 << 18)`.
/// The initial value of `reason`, so every refusal a `goto err` skips past without setting one
/// reports the BIO library.
const ERR_R_BIO_LIB: c_int = 2 | (0x2 << 18);

/// `ERR_R_BN_LIB` — `include/openssl/err.h`, `ERR_LIB_BN (3) | ERR_RFLAG_COMMON (0x2 << 18)`.
const ERR_R_BN_LIB: c_int = 3 | (0x2 << 18);

/// `ERR_R_EC_LIB` — `include/openssl/err.h`, `ERR_LIB_EC (16) | ERR_RFLAG_COMMON (0x2 << 18)`.
const ERR_R_EC_LIB: c_int = 16 | (0x2 << 18);

/// `int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off)` — `crypto/ec/eck_prn.c:21-34`.
///
/// # Safety
///
/// `fp` is a live `FILE *`; `x` is a live group.
#[no_mangle]
pub unsafe extern "C" fn ECPKParameters_print_fp(
    fp: *mut c_void,
    x: *const EcGroup,
    off: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        // `b = BIO_new(BIO_s_file())`, line 26.
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            // SAFETY: `ECK_PRN_27` is the generated site at `eck_prn.c:27`.
            raise_site(&err_sites::ECK_PRN_27);
            return 0;
        }
        // `BIO_set_fp(b, fp, BIO_NOCLOSE)`, line 30.
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE as c_long, fp);
        let ret = ECPKParameters_print(b, x, off);
        BIO_free(b);
        ret
    }
}

/// `int ECParameters_print_fp(FILE *fp, const EC_KEY *x)` — `crypto/ec/eck_prn.c:51-64`.
///
/// # Safety
///
/// `fp` is a live `FILE *`; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn ECParameters_print_fp(fp: *mut c_void, x: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        // `b = BIO_new(BIO_s_file())`, line 56.
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            // SAFETY: `ECK_PRN_57` is the generated site at `eck_prn.c:57`.
            raise_site(&err_sites::ECK_PRN_57);
            return 0;
        }
        // `BIO_set_fp(b, fp, BIO_NOCLOSE)`, line 60.
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE as c_long, fp);
        let ret = ECParameters_print(b, x);
        BIO_free(b);
        ret
    }
}

/// `int ECParameters_print(BIO *bp, const EC_KEY *x)` — `crypto/ec/ec_ameth.c:717-720`.
///
/// The `EC_KEY_PRINT_PARAM` arm of the unit's `static do_EC_KEY_print(bp, x, 4,
/// EC_KEY_PRINT_PARAM)`: `ecstr` is `"ECDSA-Parameters"`, the indent is 4, the private and public
/// buffers are **not** read, and `ECPKParameters_print` prints the group. The two refusals are
/// the authority's: the NULL key/group at `:292` and the failure tail at `:341`.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a live key.
#[no_mangle]
pub unsafe extern "C" fn ECParameters_print(bp: *mut Bio, x: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if x.is_null() {
            // SAFETY: `EC_AMETH_292` is the generated site at `ec_ameth.c:292`.
            raise_site(&err_sites::EC_AMETH_292);
            return 0;
        }
        let group = EC_KEY_get0_group(x);
        if group.is_null() {
            raise_site(&err_sites::EC_AMETH_292);
            return 0;
        }

        let mut ret: c_int = 0;
        'err: {
            if BIO_indent(bp, 4, 128) == 0 {
                break 'err;
            }
            if BIO_printf(
                bp,
                c"%s: (%d bit)\n".as_ptr(),
                c"ECDSA-Parameters".as_ptr(),
                EC_GROUP_order_bits(group),
            ) <= 0
            {
                break 'err;
            }
            if ECPKParameters_print(bp, group, 4) == 0 {
                break 'err;
            }
            ret = 1;
        }
        if ret == 0 {
            // SAFETY: `EC_AMETH_341` is the generated site at `ec_ameth.c:341`.
            raise_site(&err_sites::EC_AMETH_341);
        }
        ret
    }
}
