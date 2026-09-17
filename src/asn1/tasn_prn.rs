//! Phase 5 — `crypto/asn1/tasn_prn.c`: the structural printer.
//!
//! One export, `ASN1_item_print`, and it is the *derivation* counterpart of the
//! template decoder: where `ASN1_item_d2i` walks a template over bytes,
//! `ASN1_item_print` walks the same template over a decoded value and writes a
//! human-readable tree. Every arm is therefore keyed on the same `itype` the
//! decoder is, and every field it reaches is reached through the same
//! `tt->offset` arithmetic — so a caller-built template of the authority's shape
//! prints through this code, not only the crate's own items.
//!
//! What is observable, and therefore what is reproduced exactly:
//!
//! * the **`<ABSENT>` rule**. A null field prints as `<ABSENT>` only when
//!   `ASN1_PCTX_FLAGS_SHOW_ABSENT` is set (it is, in the default context), and
//!   only when the field is not a `BOOLEAN` primitive — a boolean's value lives
//!   *in* the slot, so a zero-valued boolean is present, not absent.
//! * the **indentation arithmetic**. `asn1_print_fsname` writes in blocks of
//!   twenty spaces and treats each `BIO_write` as a check, so a sink that reports
//!   a short count truncates the indent and fails the print. A *negative* indent
//!   is not clamped: `BIO_write` answers 0 for a non-positive length, and `0` does
//!   not equal a negative indent, so the call fails.
//! * the **`BOOLEAN` read**. `*(int *)fld` reads the low four bytes of the
//!   *pointer slot itself*, because for a boolean the caller's `ASN1_VALUE *` is
//!   the integer. A value of `-1` means "use `it->size`", which the crate's
//!   `ASN1_BOOLEAN` item sets to `-1` so that an absent optional field prints as
//!   `BOOL ABSENT`.
//! * the **`ANY` repointing**. For `V_ASN1_ANY` the printer replaces `fld` with
//!   the address of the `ASN1_TYPE`'s union and reads the payload from there, so a
//!   `type == V_ASN1_BOOLEAN` inside an `ANY` is read from the union rather than
//!   from the outer slot.
//! * the **integer rendering**, which is `i2s_ASN1_INTEGER`: decimal below 128
//!   bits and `0x`-prefixed hex above, with the sign before the `0x`.
//! * the **`SET OF`/`SEQUENCE OF` empty case**, which distinguishes an empty stack
//!   (`<EMPTY>`) from a missing one (`<ABSENT>`), prints the `OF` line only when
//!   `ASN1_PCTX_FLAGS_SHOW_SSOF` is set, and lets `OPENSSL_sk_num(NULL) == -1`
//!   make the loop body never run.
//! * the **`EXTERN` arm's two answer codes**. A hook that answers `2` asks for a
//!   newline, which the printer writes; a hook that answers `1` is success with no
//!   newline.
//! * the **`default` arm's `-1`**. `ASN1_STRING_print_ex` answers `-1` on a write
//!   failure, and `if (!ret)` is false for it, so a failed string print still lets
//!   the printer write its newline and answer 1.
//!
//! The switch keeps the authority's fall-through from `ASN1_ITYPE_PRIMITIVE` to
//! `ASN1_ITYPE_MSTRING`, expressed as a guarded arm followed by a combined one
//! because the `templates` test sits between them.
//!
//! ## `i2s_ASN1_INTEGER`, whose behaviour this stratum needs and whose name it does not own
//!
//! `asn1_print_integer` calls `i2s_ASN1_INTEGER`, defined in
//! `crypto/x509/v3_utl.c` and declared in `x509v3.h` — a Phase 11 symbol. Phase 5
//! needs the *behaviour* but does not own the export, so it is reproduced here as
//! [`i2s_asn1_integer`], `pub(crate)` and deliberately without `#[no_mangle]`: the
//! atlas assigns `i2s_ASN1_INTEGER` to Phase 11, and exporting a second definition
//! of it from this stratum would both double-define the symbol and claim an
//! obligation this stratum does not own. The two `ERR_raise` sites `v3_utl.c`
//! contributes are nonetheless covered by `gen_err_raise_sites.py` for the same
//! reason `a_object.c` is covered by Phase 4: the coordinate is observable through
//! a Phase 5 export, so leaving it out would lose it. See `docs/DECISIONS.md` D90.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::asn1::a_strex::ASN1_STRING_print_ex;
use crate::asn1::der::{ASN1_parse_dump, ASN1_tag2str};
use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_INTEGER_to_BN;
use crate::asn1::time::{ASN1_GENERALIZEDTIME_print, ASN1_UTCTIME_print};
use crate::asn1::utl::{call_item_exp, do_adb, get_choice_selector_const, get_const_field_ptr};
use crate::bn::bignum::{BN_bn2dec, BN_bn2hex, BN_free, BN_num_bits};
use crate::ffi::guard_ffi;
use crate::runtime::bio::dump::BIO_dump_indent;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{Asn1Object, OBJ_nid2ln, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::runtime::str::OPENSSL_strnlen;

/// The authority translation unit, for the `CRYPTO_malloc`/`CRYPTO_free` records
/// this module makes.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/tasn_prn.c";
/// `__LINE__` is inert under this build profile, as it is for every other site.
pub(crate) const LINE: c_int = 0;

/// `static ASN1_PCTX default_pctx` — the context `ASN1_item_print` substitutes for
/// a null one. The authority sets only `flags` and leaves the other four zero.
static DEFAULT_PCTX: Asn1Pctx = Asn1Pctx {
    flags: ASN1_PCTX_FLAGS_SHOW_ABSENT,
    nm_flags: 0,
    cert_flags: 0,
    oid_flags: 0,
    str_flags: 0,
};

/// The width of the authority's space block in `asn1_print_fsname`.
const NSPACES: c_int = 20;

/// The width of the authority's stack buffer in `asn1_print_oid`.
const OID_BUF: usize = 80;

/// `int ASN1_item_print(BIO *out, const ASN1_VALUE *ifld, int indent,
/// const ASN1_ITEM *it, const ASN1_PCTX *pctx)`
///
/// The entry point hands `&ifld` — the address of its own parameter — to
/// `asn1_item_print_ctx`, which is what lets a top-level `BOOLEAN` item read its
/// value out of that slot.
///
/// # Safety
///
/// `out` must be a live BIO. `it` must point at a live `ASN1_ITEM`; the authority
/// dereferences it unconditionally, so a null one faults there rather than being
/// rejected, and this function documents it as a caller contract instead of
/// reproducing the fault (`docs/SECURITY_DIVERGENCE_POLICY.md`). `ifld` must be a
/// value of `it`'s type, or null. `pctx` must be null or a live `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_print(
    out: *mut Bio,
    mut ifld: *const c_void,
    indent: c_int,
    it: *const Asn1Item,
    pctx: *const Asn1Pctx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract makes `it` live.
        let item = unsafe { &*it };
        let pctx = if pctx.is_null() {
            &DEFAULT_PCTX
        } else {
            // SAFETY: the caller's contract makes `pctx` live when non-null.
            unsafe { &*pctx }
        };
        let sname = if pctx.flags & ASN1_PCTX_FLAGS_NO_STRUCT_NAME != 0 {
            core::ptr::null()
        } else {
            item.sname
        };
        // SAFETY: `fld` is the address of this frame's parameter, which outlives the
        // call; `it` is live per the caller's contract and `pctx` is a live Rust
        // reference.
        unsafe {
            asn1_item_print_ctx(
                out,
                core::ptr::addr_of_mut!(ifld),
                indent,
                item,
                core::ptr::null(),
                sname,
                0,
                pctx,
            )
        }
    })
}

/// The `asn1_cb` slot of an `ASN1_AUX`, reinterpreted as the const-correct variant.
///
/// # Safety
///
/// `aux` must be a live `ASN1_AUX` with `flags`/`asn1_cb`/`asn1_const_cb` readable.
unsafe fn aux_const_cb(aux: *const Asn1Aux) -> Option<Asn1AuxConstCb> {
    // SAFETY: the caller's contract.
    let aux_ref = unsafe { &*aux };
    if aux_ref.flags & ASN1_AFLG_CONST_CB != 0 {
        aux_ref.asn1_const_cb
    } else {
        // SAFETY: the authority reinterprets the non-const callback as the const
        // one; the two differ only in the constness of the second parameter, which
        // is not part of the calling convention, so the values are ABI-identical
        // function pointers.
        aux_ref
            .asn1_cb
            .map(|f| unsafe { core::mem::transmute::<Asn1AuxCb, Asn1AuxConstCb>(f) })
    }
}

/// `asn1_item_print_ctx` — the template walk.
///
/// # Safety
///
/// `out` must be a live BIO. `fld` must be the address of a slot holding either a
/// null or a live value of `it`'s type, and the value must stay valid for the call.
/// `it` must be live. `fname` and `sname` must be null or NUL-terminated. `pctx`
/// must be live.
#[allow(clippy::too_many_arguments)] // mirrors the authority's own signature exactly
unsafe fn asn1_item_print_ctx(
    out: *mut Bio,
    fld: *mut *const c_void,
    indent: c_int,
    it: &Asn1Item,
    fname: *const c_char,
    sname: *const c_char,
    nohdr: c_int,
    pctx: &Asn1Pctx,
) -> c_int {
    let aux = it.funcs as *const Asn1Aux;
    let mut asn1_cb: Option<Asn1AuxConstCb> = None;
    let mut parg = Asn1PrintArg {
        out,
        indent,
        pctx: core::ptr::addr_of!(*pctx),
    };
    if !aux.is_null() {
        // The authority fills `parg` in whenever `funcs` is non-null, whatever the
        // item type, and derives `asn1_cb` the same way; for a `PRIMITIVE` or
        // `EXTERN` item the slot holds that type's own block and the derived callback
        // is never called.
        // SAFETY: `it.funcs` is non-null and points at the item's own behaviour block.
        asn1_cb = unsafe { aux_const_cb(aux) };
    }

    // SAFETY: `fld` is the caller's live slot.
    let present = !unsafe { *fld }.is_null();
    if (it.itype != ASN1_ITYPE_PRIMITIVE || it.utype != c_long::from(V_ASN1_BOOLEAN)) && !present {
        if pctx.flags & ASN1_PCTX_FLAGS_SHOW_ABSENT != 0 {
            if nohdr == 0 {
                // SAFETY: `out` is live and the names are null-or-NUL-terminated.
                if unsafe { asn1_print_fsname(out, indent, fname, sname, pctx) } == 0 {
                    return 0;
                }
            }
            // SAFETY: `out` is live.
            if unsafe { BIO_puts(out, c"<ABSENT>\n".as_ptr()) } <= 0 {
                return 0;
            }
        }
        return 1;
    }

    match it.itype {
        ASN1_ITYPE_PRIMITIVE if !it.templates.is_null() => {
            // SAFETY: `fld` and `it` are live and `it.templates` is non-null.
            if unsafe { asn1_template_print_ctx(out, fld, indent, &*it.templates, pctx) } == 0 {
                return 0;
            }
        }

        // The authority's fall-through: a primitive with no templates is printed by
        // the same code as a multi-string.
        ASN1_ITYPE_PRIMITIVE | ASN1_ITYPE_MSTRING => {
            // SAFETY: `out` and `fld` are live and `it` is a primitive or multi-string
            // item; the names are null-or-NUL-terminated.
            if unsafe { asn1_primitive_print(out, fld, it, indent, fname, sname, pctx) } == 0 {
                return 0;
            }
        }

        ASN1_ITYPE_EXTERN => {
            if nohdr == 0 {
                // SAFETY: `out` is live and the names are null-or-NUL-terminated.
                if unsafe { asn1_print_fsname(out, indent, fname, sname, pctx) } == 0 {
                    return 0;
                }
            }
            let ef = it.funcs as *const Asn1ExternFuncs;
            // SAFETY: a non-null `funcs` on an `EXTERN` item is that item's
            // `ASN1_EXTERN_FUNCS`; this only reads the hook slot.
            let ef_print = if ef.is_null() {
                None
            } else {
                // SAFETY: a non-null `funcs` on an `EXTERN` item is that item's
                // `ASN1_EXTERN_FUNCS`; this only reads the hook slot.
                unsafe { (*ef).asn1_ex_print }
            };
            if let Some(print) = ef_print {
                // SAFETY: the hook is the item's own, with the authority's signature;
                // `fld` is the caller's live slot and `pctx` is live.
                let i = unsafe { print(out, fld, indent, c"".as_ptr(), pctx) };
                if i == 0 {
                    return 0;
                }
                if i == 2 {
                    // SAFETY: `out` is live.
                    if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
                        return 0;
                    }
                }
                return 1;
            }
            if !sname.is_null() {
                // SAFETY: `out` is live and `sname` is NUL-terminated.
                if unsafe { BIO_printf(out, c":EXTERNAL TYPE %s\n".as_ptr(), sname) } <= 0 {
                    return 0;
                }
            }
        }

        ASN1_ITYPE_CHOICE => {
            // SAFETY: `fld` and `it` are live.
            let i = unsafe { get_choice_selector_const(fld, it) };
            if i < 0 || c_long::from(i) >= it.tcount {
                // SAFETY: `out` is live.
                if unsafe { BIO_printf(out, c"ERROR: selector [%d] invalid\n".as_ptr(), i) } <= 0 {
                    return 0;
                }
                return 1;
            }
            // SAFETY: `i` is in `0..it.tcount`, so the template is in the array.
            let tt = unsafe { &*it.templates.add(i as usize) };
            // SAFETY: `fld` is a live choice value and `tt` a template of it.
            let tmpfld = unsafe { get_const_field_ptr(fld, tt) };
            // SAFETY: as above.
            if unsafe { asn1_template_print_ctx(out, tmpfld, indent, tt, pctx) } == 0 {
                return 0;
            }
        }

        ASN1_ITYPE_SEQUENCE | ASN1_ITYPE_NDEF_SEQUENCE => {
            if nohdr == 0 {
                // SAFETY: `out` is live and the names are null-or-NUL-terminated.
                if unsafe { asn1_print_fsname(out, indent, fname, sname, pctx) } == 0 {
                    return 0;
                }
            }
            if !fname.is_null() || !sname.is_null() {
                if pctx.flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE != 0 {
                    // SAFETY: `out` is live.
                    if unsafe { BIO_puts(out, c" {\n".as_ptr()) } <= 0 {
                        return 0;
                    }
                } else {
                    // SAFETY: `out` is live.
                    if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
                        return 0;
                    }
                }
            }

            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the item's own, with the authority's
                // signature; `fld` is a live slot and `parg` is this frame's.
                let i = unsafe {
                    cb(
                        ASN1_OP_PRINT_PRE,
                        fld,
                        it as *const Asn1Item,
                        core::ptr::addr_of_mut!(parg).cast::<c_void>(),
                    )
                };
                if i == 0 {
                    return 0;
                }
                if i == 2 {
                    return 1;
                }
            }

            for i in 0..it.tcount {
                // SAFETY: `i` is in `0..it.tcount`, so the template is in the array.
                let tt = unsafe { &*it.templates.add(i as usize) };
                // SAFETY: `fld` is a live sequence value and `tt` a template of it.
                let seqtt = unsafe { do_adb(*fld, tt, 1) };
                if seqtt.is_null() {
                    return 0;
                }
                // SAFETY: `seqtt` is the resolved template for this field.
                let seqtt_ref = unsafe { &*seqtt };
                // SAFETY: as above.
                let tmpfld = unsafe { get_const_field_ptr(fld, seqtt_ref) };
                // SAFETY: `tmpfld` is this field's slot and `seqtt_ref` its template.
                if unsafe { asn1_template_print_ctx(out, tmpfld, indent + 2, seqtt_ref, pctx) } == 0
                {
                    return 0;
                }
            }
            if pctx.flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE != 0 {
                // SAFETY: `out` is live.
                if unsafe { BIO_printf(out, c"%*s}\n".as_ptr(), indent, c"".as_ptr()) } < 0 {
                    return 0;
                }
            }

            if let Some(cb) = asn1_cb {
                // SAFETY: as the pre-callback above.
                let i = unsafe {
                    cb(
                        ASN1_OP_PRINT_POST,
                        fld,
                        it as *const Asn1Item,
                        core::ptr::addr_of_mut!(parg).cast::<c_void>(),
                    )
                };
                if i == 0 {
                    return 0;
                }
            }
        }

        _ => {
            // SAFETY: `out` is live.
            unsafe {
                BIO_printf(
                    out,
                    c"Unprocessed type %d\n".as_ptr(),
                    c_int::from(it.itype),
                )
            };
            return 0;
        }
    }

    1
}

/// `asn1_template_print_ctx` — one field of a sequence, or one alternative of a
/// choice.
///
/// # Safety
///
/// `out` must be a live BIO. `fld` must be the address of a slot holding the
/// field's value (or, for an `EMBED` template, the value's own address). `tt` must
/// be a live template. `pctx` must be live.
unsafe fn asn1_template_print_ctx(
    out: *mut Bio,
    fld: *mut *const c_void,
    indent: c_int,
    tt: &Asn1Template,
    pctx: &Asn1Pctx,
) -> c_int {
    // The authority stores `tt->flags` in an `int`, so a flag at or above bit 31 is
    // truncated before every test below. Reproduced by the cast rather than by a
    // note, because the `EMBED` and `SK_MASK` tests read this very value.
    let flags = tt.flags as c_int;
    let sname = if pctx.flags & ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME != 0 {
        // SAFETY: `tt.item` is this field's `ASN1_ITEM_EXP`, so the call answers its
        // live item and the item's `sname` is readable.
        unsafe { (*call_item_exp(tt.item).cast::<Asn1Item>()).sname }
    } else {
        core::ptr::null()
    };
    let fname = if pctx.flags & ASN1_PCTX_FLAGS_NO_FIELD_NAME != 0 {
        core::ptr::null()
    } else {
        tt.field_name
    };

    // "If field is embedded then fld needs fixing so it is a pointer to a pointer to
    // a field." The slot already holds the value itself, so the address of that
    // address is what the walk below needs — and `tfld` must outlive the branch,
    // because the recursive call below reads through `&tfld`. The authority
    // declares it at function scope for exactly that reason; as `i2d.rs` does for
    // its own `tval`.
    let mut tfld: *const c_void = fld.cast::<c_void>();
    let fld = if flags & (ASN1_TFLG_EMBED as c_int) != 0 {
        core::ptr::addr_of_mut!(tfld).cast::<*const c_void>()
    } else {
        fld
    };

    if flags & (ASN1_TFLG_SK_MASK as c_int) != 0 {
        // SET OF, SEQUENCE OF.
        if !fname.is_null() {
            if pctx.flags & ASN1_PCTX_FLAGS_SHOW_SSOF != 0 {
                let tname = if flags & (ASN1_TFLG_SET_OF as c_int) != 0 {
                    c"SET".as_ptr()
                } else {
                    c"SEQUENCE".as_ptr()
                };
                // SAFETY: `out` is live and `tt.field_name` is NUL-terminated.
                if unsafe {
                    BIO_printf(
                        out,
                        c"%*s%s OF %s {\n".as_ptr(),
                        indent,
                        c"".as_ptr(),
                        tname,
                        tt.field_name,
                    )
                } <= 0
                {
                    return 0;
                }
            } else {
                // SAFETY: `out` is live and `fname` is NUL-terminated.
                if unsafe { BIO_printf(out, c"%*s%s:\n".as_ptr(), indent, c"".as_ptr(), fname) }
                    <= 0
                {
                    return 0;
                }
            }
        }
        // SAFETY: `fld` is the caller's live slot and for an `SK_MASK` template it
        // holds the stack pointer.
        let stack = unsafe { *fld } as *mut OpenSslStack;
        let mut num: c_int = -1;
        if !stack.is_null() {
            // SAFETY: `stack` is a live stack of `ASN1_VALUE *`.
            num = unsafe { OPENSSL_sk_num(stack) };
        }
        let mut i: c_int = 0;
        while i < num {
            if i > 0 {
                // SAFETY: `out` is live.
                if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
                    return 0;
                }
            }
            // SAFETY: `stack` is non-null here and `i` is in `0..num`.
            let mut skitem: *const c_void = unsafe { OPENSSL_sk_value(stack, i) };
            // SAFETY: `tt.item` is the element type's `ASN1_ITEM_EXP`, so the call
            // answers its live item; `skitem` is this frame's slot and outlives it.
            if unsafe {
                asn1_item_print_ctx(
                    out,
                    core::ptr::addr_of_mut!(skitem),
                    indent + 2,
                    &*call_item_exp(tt.item).cast::<Asn1Item>(),
                    core::ptr::null(),
                    core::ptr::null(),
                    1,
                    pctx,
                )
            } == 0
            {
                return 0;
            }
            i += 1;
        }
        if i == 0 {
            let empty = if stack.is_null() {
                c"ABSENT".as_ptr()
            } else {
                c"EMPTY".as_ptr()
            };
            // SAFETY: `out` is live.
            if unsafe { BIO_printf(out, c"%*s<%s>\n".as_ptr(), indent + 2, c"".as_ptr(), empty) }
                <= 0
            {
                return 0;
            }
        }
        if pctx.flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE != 0 {
            // SAFETY: `out` is live.
            if unsafe { BIO_printf(out, c"%*s}\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
                return 0;
            }
        }
        return 1;
    }
    // SAFETY: `tt.item` is the field's `ASN1_ITEM_EXP`, so the call answers its live
    // item; `fld` is the field's slot.
    unsafe {
        asn1_item_print_ctx(
            out,
            fld,
            indent,
            &*call_item_exp(tt.item).cast::<Asn1Item>(),
            fname,
            sname,
            0,
            pctx,
        )
    }
}

/// `asn1_print_fsname` — the indent, then the field name and the struct name.
///
/// # Safety
///
/// `out` must be a live BIO; `fname` and `sname` must be null or NUL-terminated.
unsafe fn asn1_print_fsname(
    out: *mut Bio,
    mut indent: c_int,
    fname: *const c_char,
    sname: *const c_char,
    pctx: &Asn1Pctx,
) -> c_int {
    let spaces: &[u8; NSPACES as usize] = b"                    ";

    while indent > NSPACES {
        // SAFETY: `out` is live and `spaces` is a static of exactly `NSPACES` bytes.
        if unsafe { BIO_write(out, spaces.as_ptr().cast(), NSPACES) } != NSPACES {
            return 0;
        }
        indent -= NSPACES;
    }
    // A negative `indent` is deliberately not clamped: `BIO_write` answers 0 for a
    // non-positive length and `0 != indent`, so the call fails.
    // SAFETY: `out` is live.
    if unsafe { BIO_write(out, spaces.as_ptr().cast(), indent) } != indent {
        return 0;
    }
    let mut sname = sname;
    let mut fname = fname;
    if pctx.flags & ASN1_PCTX_FLAGS_NO_STRUCT_NAME != 0 {
        sname = core::ptr::null();
    }
    if pctx.flags & ASN1_PCTX_FLAGS_NO_FIELD_NAME != 0 {
        fname = core::ptr::null();
    }
    if sname.is_null() && fname.is_null() {
        return 1;
    }
    if !fname.is_null() {
        // SAFETY: `out` is live and `fname` is NUL-terminated.
        if unsafe { BIO_puts(out, fname) } <= 0 {
            return 0;
        }
    }
    if !sname.is_null() {
        if !fname.is_null() {
            // SAFETY: `out` is live and `sname` is NUL-terminated.
            if unsafe { BIO_printf(out, c" (%s)".as_ptr(), sname) } <= 0 {
                return 0;
            }
        } else {
            // SAFETY: as above.
            if unsafe { BIO_puts(out, sname) } <= 0 {
                return 0;
            }
        }
    }
    // SAFETY: `out` is live and this is a two-byte static.
    if unsafe { BIO_write(out, c": ".as_ptr().cast(), 2) } != 2 {
        return 0;
    }
    1
}

/// `asn1_print_boolean` — three-valued, because a boolean can be absent.
///
/// # Safety
///
/// `out` must be a live BIO.
unsafe fn asn1_print_boolean(out: *mut Bio, boolval: c_int) -> c_int {
    let str_ = match boolval {
        -1 => c"BOOL ABSENT".as_ptr(),
        0 => c"FALSE".as_ptr(),
        _ => c"TRUE".as_ptr(),
    };
    // SAFETY: `out` is live and the string is a static literal.
    if unsafe { BIO_puts(out, str_) } <= 0 {
        return 0;
    }
    1
}

/// `bignum_to_string` — decimal below 128 bits, `0x`-prefixed hex above.
///
/// # Safety
///
/// `bn` must be a live `BIGNUM`.
unsafe fn bignum_to_string(bn: *const crate::bn::bignum::BigNum) -> *mut c_char {
    // SAFETY: `bn` is live per the caller's contract.
    if unsafe { BN_num_bits(bn) } < 128 {
        // SAFETY: as above.
        return unsafe { BN_bn2dec(bn) };
    }
    // SAFETY: as above.
    let tmp = unsafe { BN_bn2hex(bn) };
    if tmp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `tmp` is a NUL-terminated string allocated by `BN_bn2hex`, and this
    // function takes it over.
    unsafe { prepend_radix(tmp) }
}

/// The `"0x"` prefix, placed after the sign.
///
/// The authority computes `len = strlen(tmp) + 3`, which is exactly enough for
/// either `"0x" + tmp` or `"-0x" + tmp + 1`, and copies with `OPENSSL_strlcpy`.
///
/// # Safety
///
/// `tmp` must be a NUL-terminated string this function may take ownership of, held
/// in storage `CRYPTO_free` accepts.
unsafe fn prepend_radix(tmp: *mut c_char) -> *mut c_char {
    // SAFETY: `tmp` is NUL-terminated by the caller's contract.
    let len = unsafe { OPENSSL_strnlen(tmp, usize::MAX) };
    // SAFETY: `OPENSSL_strnlen` measured at least one byte, so `tmp[0]` is a live
    // byte of that string.
    let neg = unsafe { *tmp.cast::<u8>() } == b'-';
    let out_len = len + 3;
    // SAFETY: a strictly positive size is requested and the file/line are statics.
    let ret = CRYPTO_malloc(out_len, FILE.as_ptr(), LINE);
    if ret.is_null() {
        // SAFETY: this function owns `tmp`.
        unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), LINE) };
        return core::ptr::null_mut();
    }
    // SAFETY: `ret` owns `out_len` written bytes, `tmp` holds `len + 1` readable
    // ones, and the copies below stay inside both: `3 + (len - 1)` and `2 + len` are
    // each `len + 2 <= out_len - 1`.
    unsafe {
        let d = ret.cast::<u8>();
        if neg {
            core::ptr::copy_nonoverlapping(b"-0x".as_ptr(), d, 3);
            core::ptr::copy_nonoverlapping(tmp.cast::<u8>().add(1), d.add(3), len - 1);
        } else {
            core::ptr::copy_nonoverlapping(b"0x".as_ptr(), d, 2);
            core::ptr::copy_nonoverlapping(tmp.cast::<u8>(), d.add(2), len);
        }
        *d.add(out_len - 1) = 0;
    }
    // SAFETY: this function owns `tmp`.
    unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), LINE) };
    ret.cast::<c_char>()
}

/// `i2s_ASN1_INTEGER(NULL, str)`, as `asn1_print_integer` reaches it.
///
/// Answers an owned, NUL-terminated, `CRYPTO_malloc`'d string the caller releases
/// with `CRYPTO_free`, or null on failure. See the module header for why this is
/// `pub(crate)` rather than the Phase 11 export of the same behaviour.
///
/// # Safety
///
/// `str_` must be null or a live `ASN1_INTEGER`.
pub(crate) unsafe fn i2s_asn1_integer(str_: *const Asn1String) -> *mut c_char {
    if str_.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: null-or-live per this function's contract.
    let bn = unsafe { ASN1_INTEGER_to_BN(str_, core::ptr::null_mut()) };
    if bn.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/x509/v3_utl.c:189`).
        unsafe { raise_site(&err_sites::V3_UTL_189) };
        return core::ptr::null_mut();
    }
    // SAFETY: `bn` is live; `bignum_to_string` only reads it and its result is
    // owned by this function.
    let s = unsafe { bignum_to_string(bn) };
    // SAFETY: `bn` is live and this function owns it.
    unsafe { BN_free(bn) };
    if s.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/x509/v3_utl.c:191`).
        unsafe { raise_site(&err_sites::V3_UTL_191) };
    }
    s
}

/// `asn1_print_integer` — an integer through `i2s_asn1_integer`.
///
/// # Safety
///
/// `out` must be a live BIO; `str_` must be null or a live `ASN1_INTEGER`.
unsafe fn asn1_print_integer(out: *mut Bio, str_: *const Asn1String) -> c_int {
    // SAFETY: the caller's contract makes `str_` null-or-live.
    let s = unsafe { i2s_asn1_integer(str_) };
    if s.is_null() {
        return 0;
    }
    let mut ret = 1;
    // SAFETY: `out` is live and `s` is NUL-terminated.
    if unsafe { BIO_puts(out, s) } <= 0 {
        ret = 0;
    }
    // SAFETY: `s` was allocated by `i2s_asn1_integer` and is released here.
    unsafe { CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), LINE) };
    ret
}

/// `asn1_print_oid` — the long name, then the dotted decimal in parentheses.
///
/// The dotted form goes into a fixed 80-byte buffer and is printed without a
/// truncation check, which is the authority's behaviour and is courted.
///
/// # Safety
///
/// `out` must be a live BIO; `oid` must be a live `ASN1_OBJECT`.
unsafe fn asn1_print_oid(out: *mut Bio, oid: *const Asn1Object) -> c_int {
    let mut objbuf = [0 as c_char; OID_BUF];
    // SAFETY: `oid` is live, so `OBJ_obj2nid` only reads it.
    let nid = unsafe { OBJ_obj2nid(oid) };
    // SAFETY: `nid` came from the object database.
    let ln = OBJ_nid2ln(nid);
    let ln = if ln.is_null() { c"".as_ptr() } else { ln };
    // SAFETY: the buffer holds `OID_BUF` bytes and `oid` is live.
    unsafe { OBJ_obj2txt(objbuf.as_mut_ptr(), OID_BUF as c_int, oid, 1) };
    // SAFETY: `out` is live and both strings are NUL-terminated.
    if unsafe { BIO_printf(out, c"%s (%s)".as_ptr(), ln, objbuf.as_ptr()) } <= 0 {
        return 0;
    }
    1
}

/// `asn1_print_obstring` — an octet- or bit-string's header line and its hex dump.
///
/// # Safety
///
/// `out` must be a live BIO; `str_` must be a live `ASN1_STRING`.
unsafe fn asn1_print_obstring(out: *mut Bio, str_: *const Asn1String, indent: c_int) -> c_int {
    // SAFETY: `str_` is live per the caller's contract.
    let st = unsafe { &*str_ };
    if st.type_ == V_ASN1_BIT_STRING {
        // SAFETY: `out` is live.
        if unsafe { BIO_printf(out, c" (%ld unused bits)\n".as_ptr(), st.flags & 0x7) } <= 0 {
            return 0;
        }
    } else {
        // SAFETY: `out` is live.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
    }
    if st.length > 0 {
        // SAFETY: `out` is live and the string's own contract makes `data` readable
        // for `length` bytes.
        if unsafe { BIO_dump_indent(out, st.data.cast(), st.length, indent + 2) } <= 0 {
            return 0;
        }
    }
    1
}

/// `asn1_primitive_print` — the primitive leaf of the walk.
///
/// # Safety
///
/// `out` must be a live BIO. `fld` must be the address of a slot holding a null or
/// live value of `it`'s type. `it` must be live and of a primitive or multi-string
/// `itype`. `fname` and `sname` must be null or NUL-terminated. `pctx` must be
/// live.
#[allow(clippy::too_many_arguments)] // mirrors the authority's own signature exactly
unsafe fn asn1_primitive_print(
    out: *mut Bio,
    fld: *mut *const c_void,
    it: &Asn1Item,
    indent: c_int,
    fname: *const c_char,
    sname: *const c_char,
    pctx: &Asn1Pctx,
) -> c_int {
    let pf = it.funcs as *const Asn1PrimitiveFuncs;
    // SAFETY: `out` is live and the names are null-or-NUL-terminated.
    if unsafe { asn1_print_fsname(out, indent, fname, sname, pctx) } == 0 {
        return 0;
    }
    if !pf.is_null() {
        // SAFETY: a non-null `funcs` on a primitive item is that item's
        // `ASN1_PRIMITIVE_FUNCS`; this only reads the hook slot.
        if let Some(print) = unsafe { (*pf).prim_print } {
            // SAFETY: the hook is the item's own, with the authority's signature;
            // `fld` is the caller's live slot and `pctx` is live.
            return unsafe { print(out, fld, it as *const Asn1Item, indent, pctx) };
        }
    }

    let mut fld = fld;
    let utype: c_long;
    let mut str_: *mut Asn1String;
    if it.itype == ASN1_ITYPE_MSTRING {
        // SAFETY: the slot holds an `ASN1_STRING` for a multi-string item, and the
        // caller's guard established that it is non-null.
        str_ = unsafe { *fld }.cast_mut().cast::<Asn1String>();
        // SAFETY: `str_` is non-null, so its `type` is readable.
        utype = c_long::from(unsafe { (*str_).type_ } & !V_ASN1_NEG);
    } else {
        utype = it.utype;
        if utype == c_long::from(V_ASN1_BOOLEAN) {
            str_ = core::ptr::null_mut();
        } else {
            // SAFETY: the slot holds an `ASN1_STRING` for a string-valued item.
            str_ = unsafe { *fld }.cast_mut().cast::<Asn1String>();
        }
    }
    let pname: *const c_char;
    let mut utype = utype;
    if utype == c_long::from(V_ASN1_ANY) {
        // SAFETY: for `ANY` the slot holds an `ASN1_TYPE`, and the caller's guard
        // established that it is non-null.
        let atype = unsafe { *fld } as *const Asn1Type;
        // SAFETY: `atype` is non-null, so its `type` is readable.
        utype = c_long::from(unsafe { (*atype).type_ });
        // SAFETY: the union of a live `ASN1_TYPE` is readable.
        fld = unsafe { core::ptr::addr_of!((*atype).value) }
            .cast::<*const c_void>()
            .cast_mut();
        // SAFETY: `fld` now points at the union, which is the payload slot.
        str_ = unsafe { *fld }.cast_mut().cast::<Asn1String>();
        pname = if pctx.flags & ASN1_PCTX_FLAGS_NO_ANY_TYPE != 0 {
            core::ptr::null()
        } else {
            // A `V_ASN1_*` tag, which is what `ASN1_tag2str` takes.
            ASN1_tag2str(utype as c_int)
        };
    } else {
        pname = if pctx.flags & ASN1_PCTX_FLAGS_SHOW_TYPE != 0 {
            // A `V_ASN1_*` tag.
            ASN1_tag2str(utype as c_int)
        } else {
            core::ptr::null()
        };
    }

    if utype == c_long::from(V_ASN1_NULL) {
        // SAFETY: `out` is live.
        if unsafe { BIO_puts(out, c"NULL\n".as_ptr()) } <= 0 {
            return 0;
        }
        return 1;
    }

    if !pname.is_null() {
        // SAFETY: `out` is live and `pname` is a static string.
        if unsafe { BIO_puts(out, pname) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live.
        if unsafe { BIO_puts(out, c":".as_ptr()) } <= 0 {
            return 0;
        }
    }

    let ret: c_int;
    let mut needlf = 1;
    match utype as c_int {
        V_ASN1_BOOLEAN => {
            // The boolean's value is the low four bytes of the slot itself, not what
            // the slot points at.
            // SAFETY: `fld` points at the slot the caller declared as the boolean's
            // storage, so four readable bytes are there.
            let mut boolval = unsafe { *fld.cast::<c_int>() };
            if boolval == -1 {
                boolval = it.size as c_int;
            }
            // SAFETY: `out` is live.
            ret = unsafe { asn1_print_boolean(out, boolval) };
        }

        V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
            // SAFETY: `out` is live and `str_` is a live integer here.
            ret = unsafe { asn1_print_integer(out, str_) };
        }

        V_ASN1_UTCTIME => {
            // SAFETY: `out` is live and `str_` is a live string here.
            ret = unsafe { ASN1_UTCTIME_print(out, str_) };
        }

        V_ASN1_GENERALIZEDTIME => {
            // SAFETY: as above.
            ret = unsafe { ASN1_GENERALIZEDTIME_print(out, str_) };
        }

        V_ASN1_OBJECT => {
            // SAFETY: for an object-valued item the slot holds the `ASN1_OBJECT`, and
            // `out` is live.
            let oid = unsafe { *fld }.cast::<Asn1Object>();
            // SAFETY: `out` is live and `oid` is live here.
            ret = unsafe { asn1_print_oid(out, oid) };
        }

        V_ASN1_OCTET_STRING | V_ASN1_BIT_STRING => {
            // SAFETY: `out` is live and `str_` is a live string here.
            ret = unsafe { asn1_print_obstring(out, str_, indent) };
            needlf = 0;
        }

        V_ASN1_SEQUENCE | V_ASN1_SET | V_ASN1_OTHER => {
            // SAFETY: `out` is live.
            if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
                return 0;
            }
            // SAFETY: `out` is live and `str_` is a live string whose `data`/`length`
            // describe readable bytes.
            ret = if unsafe {
                ASN1_parse_dump(out, (*str_).data, c_long::from((*str_).length), indent, 0)
            } <= 0
            {
                0
            } else {
                1
            };
            needlf = 0;
        }

        _ => {
            // `ASN1_STRING_print_ex` answers -1 on a write failure, and `if (!ret)`
            // below is false for it — so a failed string print still succeeds here.
            // SAFETY: `out` is live, `str_` is a live string, and the flags are the
            // caller's.
            ret = unsafe { ASN1_STRING_print_ex(out, str_, pctx.str_flags) };
        }
    }
    if ret == 0 {
        return 0;
    }
    if needlf != 0 {
        // SAFETY: `out` is live.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
    }
    1
}
