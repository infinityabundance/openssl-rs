//! Phase 8.2 — `crypto/aria/aria.c`, the ARIA block cipher.
//!
//! **Provider-only.** The authority exports no `ARIA_*` symbol: `nm -D libcrypto.so.3` lists none, and
//! `forensics/atlas/symbol-ownership.json` records no `ARIA_*` or `ossl_aria_*` row — the only ARIA
//! names it carries are the public `EVP_aria_*` cipher constructors declared in `evp.h`. So there is
//! no low-level public API to keep and this unit exists entirely for the default provider's ARIA
//! rows. `include/crypto/aria.h` is an internal header, and the three functions it declares —
//! `ossl_aria_encrypt`, `ossl_aria_set_encrypt_key`, `ossl_aria_set_decrypt_key` — are internal.
//!
//! **This unit *is* compiled in this profile, and there is no assembly to prefer over it.** The build
//! tree holds `libcrypto-lib-aria.o` and `libcrypto-shlib-aria.o`, and `crypto/aria/build.info` lists
//! `aria.c` alone; no `.S`, `.s` or `.pl` source and no second object exist anywhere under the pinned
//! `crypto/aria/` tree. Where SM4 and AES decline a runtime-selected assembly path in favour of the
//! compiled C, ARIA has only the compiled C to take.
//!
//! **The compiled branch is the table branch.** `aria.c` is two implementations behind one
//! `#ifndef OPENSSL_SMALL_FOOTPRINT`; this profile does not define `OPENSSL_SMALL_FOOTPRINT`, so the
//! `S1`/`S2`/`X1`/`X2` `uint32_t[256]` tables and the register macros are what runs, and the
//! byte-S-box reference (`sb1`..`sb4`, `sl1`, `sl2`, `a`, `FO`, `FE`) in the `#else` is not compiled.
//! This unit transcribes the compiled branch and deliberately does not carry the dead reference.
//! Two spellings the task expected do **not** exist in this authority: there is no `FL`/`FL_inv` and
//! no `ossl_aria_decrypt`/`ARIA_decrypt` — those belong to other ARIA implementations. Decryption is
//! the *same* `ossl_aria_encrypt` run over the schedule `ossl_aria_set_decrypt_key` builds, which is
//! why the header declares no decrypt entry point.
//!
//! **Every table is literal, and the expansion is checked.** `S1`..`X2` and `Key_RC` are read from the
//! authority's own initialisers by `court/gen-aria.py`. The four 32-bit tables are the four 8-bit
//! S-boxes of the `#else` branch (`sb1`..`sb4`) expanded into complementary byte lanes, so the unit
//! test binds that expansion for all 256 entries — the tables the compiled code indexes are the
//! authority's, not a typist's recollection of them.
//!
//! SPDX-License-Identifier: Apache-2.0

// The authority's spellings, kept: `ossl_aria_encrypt`, `ossl_aria_set_encrypt_key`,
// `ossl_aria_set_decrypt_key`, the `ARIA_*` macro names and the `S1`/`S2`/`X1`/`X2` tables are how
// the prerequisite gate joins a definition to its translation unit, and a name the tooling cannot
// join is indistinguishable from a name that is absent (D259).
// **Every item in this module is read by the provider rows and by nothing else, and those rows land
// in the commit after this one.** `cipher_aria.c`'s six `ARIA-*` rows install
// `ossl_aria_set_encrypt_key`/`ossl_aria_set_decrypt_key` as their `initkey` and reach
// `ossl_aria_encrypt` through `ctx->block`, exactly as the `SM4-*` rows reach `src/sm4.rs`'s three
// entry points. Until then no *non-test* build reads any of it, so the module carries one allow
// rather than twenty per-item ones -- and the allow is the statement that the caller is named and
// coming, not that the item is dead. A test-only use is not a use for this purpose, which is why the
// five tests below do not silence it.
#![allow(dead_code)]
#![allow(non_snake_case)]

use core::ffi::{c_int, c_uchar, c_uint};

/// `ARIA_BLOCK_SIZE` — `include/crypto/aria.h:26`.
pub(crate) const ARIA_BLOCK_SIZE: usize = 16;

/// `ARIA_MAX_KEYS` — `include/crypto/aria.h:27`.
pub(crate) const ARIA_MAX_KEYS: usize = 17;

/// `static const uint32_t Key_RC[5][4]` — `aria.c:60-66`. The ARIA `CK` constants. The authority's
/// comment records the reuse: 128-bit keys take rows 0,1,2; 192-bit rows 1,2,3(=0); 256-bit rows
/// 2,3(=0),4(=1). Rows 3 and 4 are written out as copies of 0 and 1, and the unit test asserts that
/// repetition as the table's own property. The schedule reaches rows past the first through the
/// flattened layout, exactly as `&Key_RC[(bits - 128) / 64][0]` does in C.
static KEY_RC: [[u32; 4]; 5] = [
    [0x517CC1B7, 0x27220A94, 0xFE13ABE8, 0xFA9A6EE0],
    [0x6DB14ACC, 0x9E21C820, 0xFF28B1D5, 0xEF5DE2B0],
    [0xDB92371D, 0x2126E970, 0x03249775, 0x04E8C90E],
    [0x517CC1B7, 0x27220A94, 0xFE13ABE8, 0xFA9A6EE0],
    [0x6DB14ACC, 0x9E21C820, 0xFF28B1D5, 0xEF5DE2B0],
];

/// `static const uint32_t S1[256]` — `aria.c:69-134`. The odd round's first table, one of the four
/// that together hold the S-box layer plus its `M` mixing. `S1[j]` is `sb1[j]` in the low three byte
/// lanes with a zero top lane.
static S1: [u32; 256] = [
    0x00636363, 0x007C7C7C, 0x00777777, 0x007B7B7B, 0x00F2F2F2, 0x006B6B6B, 0x006F6F6F, 0x00C5C5C5,
    0x00303030, 0x00010101, 0x00676767, 0x002B2B2B, 0x00FEFEFE, 0x00D7D7D7, 0x00ABABAB, 0x00767676,
    0x00CACACA, 0x00828282, 0x00C9C9C9, 0x007D7D7D, 0x00FAFAFA, 0x00595959, 0x00474747, 0x00F0F0F0,
    0x00ADADAD, 0x00D4D4D4, 0x00A2A2A2, 0x00AFAFAF, 0x009C9C9C, 0x00A4A4A4, 0x00727272, 0x00C0C0C0,
    0x00B7B7B7, 0x00FDFDFD, 0x00939393, 0x00262626, 0x00363636, 0x003F3F3F, 0x00F7F7F7, 0x00CCCCCC,
    0x00343434, 0x00A5A5A5, 0x00E5E5E5, 0x00F1F1F1, 0x00717171, 0x00D8D8D8, 0x00313131, 0x00151515,
    0x00040404, 0x00C7C7C7, 0x00232323, 0x00C3C3C3, 0x00181818, 0x00969696, 0x00050505, 0x009A9A9A,
    0x00070707, 0x00121212, 0x00808080, 0x00E2E2E2, 0x00EBEBEB, 0x00272727, 0x00B2B2B2, 0x00757575,
    0x00090909, 0x00838383, 0x002C2C2C, 0x001A1A1A, 0x001B1B1B, 0x006E6E6E, 0x005A5A5A, 0x00A0A0A0,
    0x00525252, 0x003B3B3B, 0x00D6D6D6, 0x00B3B3B3, 0x00292929, 0x00E3E3E3, 0x002F2F2F, 0x00848484,
    0x00535353, 0x00D1D1D1, 0x00000000, 0x00EDEDED, 0x00202020, 0x00FCFCFC, 0x00B1B1B1, 0x005B5B5B,
    0x006A6A6A, 0x00CBCBCB, 0x00BEBEBE, 0x00393939, 0x004A4A4A, 0x004C4C4C, 0x00585858, 0x00CFCFCF,
    0x00D0D0D0, 0x00EFEFEF, 0x00AAAAAA, 0x00FBFBFB, 0x00434343, 0x004D4D4D, 0x00333333, 0x00858585,
    0x00454545, 0x00F9F9F9, 0x00020202, 0x007F7F7F, 0x00505050, 0x003C3C3C, 0x009F9F9F, 0x00A8A8A8,
    0x00515151, 0x00A3A3A3, 0x00404040, 0x008F8F8F, 0x00929292, 0x009D9D9D, 0x00383838, 0x00F5F5F5,
    0x00BCBCBC, 0x00B6B6B6, 0x00DADADA, 0x00212121, 0x00101010, 0x00FFFFFF, 0x00F3F3F3, 0x00D2D2D2,
    0x00CDCDCD, 0x000C0C0C, 0x00131313, 0x00ECECEC, 0x005F5F5F, 0x00979797, 0x00444444, 0x00171717,
    0x00C4C4C4, 0x00A7A7A7, 0x007E7E7E, 0x003D3D3D, 0x00646464, 0x005D5D5D, 0x00191919, 0x00737373,
    0x00606060, 0x00818181, 0x004F4F4F, 0x00DCDCDC, 0x00222222, 0x002A2A2A, 0x00909090, 0x00888888,
    0x00464646, 0x00EEEEEE, 0x00B8B8B8, 0x00141414, 0x00DEDEDE, 0x005E5E5E, 0x000B0B0B, 0x00DBDBDB,
    0x00E0E0E0, 0x00323232, 0x003A3A3A, 0x000A0A0A, 0x00494949, 0x00060606, 0x00242424, 0x005C5C5C,
    0x00C2C2C2, 0x00D3D3D3, 0x00ACACAC, 0x00626262, 0x00919191, 0x00959595, 0x00E4E4E4, 0x00797979,
    0x00E7E7E7, 0x00C8C8C8, 0x00373737, 0x006D6D6D, 0x008D8D8D, 0x00D5D5D5, 0x004E4E4E, 0x00A9A9A9,
    0x006C6C6C, 0x00565656, 0x00F4F4F4, 0x00EAEAEA, 0x00656565, 0x007A7A7A, 0x00AEAEAE, 0x00080808,
    0x00BABABA, 0x00787878, 0x00252525, 0x002E2E2E, 0x001C1C1C, 0x00A6A6A6, 0x00B4B4B4, 0x00C6C6C6,
    0x00E8E8E8, 0x00DDDDDD, 0x00747474, 0x001F1F1F, 0x004B4B4B, 0x00BDBDBD, 0x008B8B8B, 0x008A8A8A,
    0x00707070, 0x003E3E3E, 0x00B5B5B5, 0x00666666, 0x00484848, 0x00030303, 0x00F6F6F6, 0x000E0E0E,
    0x00616161, 0x00353535, 0x00575757, 0x00B9B9B9, 0x00868686, 0x00C1C1C1, 0x001D1D1D, 0x009E9E9E,
    0x00E1E1E1, 0x00F8F8F8, 0x00989898, 0x00111111, 0x00696969, 0x00D9D9D9, 0x008E8E8E, 0x00949494,
    0x009B9B9B, 0x001E1E1E, 0x00878787, 0x00E9E9E9, 0x00CECECE, 0x00555555, 0x00282828, 0x00DFDFDF,
    0x008C8C8C, 0x00A1A1A1, 0x00898989, 0x000D0D0D, 0x00BFBFBF, 0x00E6E6E6, 0x00424242, 0x00686868,
    0x00414141, 0x00999999, 0x002D2D2D, 0x000F0F0F, 0x00B0B0B0, 0x00545454, 0x00BBBBBB, 0x00161616,
];

/// `static const uint32_t S2[256]` — `aria.c:136-201`. `S2[j]` is `sb2[j]` in lanes 3, 1 and 0, with
/// lane 2 zero.
static S2: [u32; 256] = [
    0xE200E2E2, 0x4E004E4E, 0x54005454, 0xFC00FCFC, 0x94009494, 0xC200C2C2, 0x4A004A4A, 0xCC00CCCC,
    0x62006262, 0x0D000D0D, 0x6A006A6A, 0x46004646, 0x3C003C3C, 0x4D004D4D, 0x8B008B8B, 0xD100D1D1,
    0x5E005E5E, 0xFA00FAFA, 0x64006464, 0xCB00CBCB, 0xB400B4B4, 0x97009797, 0xBE00BEBE, 0x2B002B2B,
    0xBC00BCBC, 0x77007777, 0x2E002E2E, 0x03000303, 0xD300D3D3, 0x19001919, 0x59005959, 0xC100C1C1,
    0x1D001D1D, 0x06000606, 0x41004141, 0x6B006B6B, 0x55005555, 0xF000F0F0, 0x99009999, 0x69006969,
    0xEA00EAEA, 0x9C009C9C, 0x18001818, 0xAE00AEAE, 0x63006363, 0xDF00DFDF, 0xE700E7E7, 0xBB00BBBB,
    0x00000000, 0x73007373, 0x66006666, 0xFB00FBFB, 0x96009696, 0x4C004C4C, 0x85008585, 0xE400E4E4,
    0x3A003A3A, 0x09000909, 0x45004545, 0xAA00AAAA, 0x0F000F0F, 0xEE00EEEE, 0x10001010, 0xEB00EBEB,
    0x2D002D2D, 0x7F007F7F, 0xF400F4F4, 0x29002929, 0xAC00ACAC, 0xCF00CFCF, 0xAD00ADAD, 0x91009191,
    0x8D008D8D, 0x78007878, 0xC800C8C8, 0x95009595, 0xF900F9F9, 0x2F002F2F, 0xCE00CECE, 0xCD00CDCD,
    0x08000808, 0x7A007A7A, 0x88008888, 0x38003838, 0x5C005C5C, 0x83008383, 0x2A002A2A, 0x28002828,
    0x47004747, 0xDB00DBDB, 0xB800B8B8, 0xC700C7C7, 0x93009393, 0xA400A4A4, 0x12001212, 0x53005353,
    0xFF00FFFF, 0x87008787, 0x0E000E0E, 0x31003131, 0x36003636, 0x21002121, 0x58005858, 0x48004848,
    0x01000101, 0x8E008E8E, 0x37003737, 0x74007474, 0x32003232, 0xCA00CACA, 0xE900E9E9, 0xB100B1B1,
    0xB700B7B7, 0xAB00ABAB, 0x0C000C0C, 0xD700D7D7, 0xC400C4C4, 0x56005656, 0x42004242, 0x26002626,
    0x07000707, 0x98009898, 0x60006060, 0xD900D9D9, 0xB600B6B6, 0xB900B9B9, 0x11001111, 0x40004040,
    0xEC00ECEC, 0x20002020, 0x8C008C8C, 0xBD00BDBD, 0xA000A0A0, 0xC900C9C9, 0x84008484, 0x04000404,
    0x49004949, 0x23002323, 0xF100F1F1, 0x4F004F4F, 0x50005050, 0x1F001F1F, 0x13001313, 0xDC00DCDC,
    0xD800D8D8, 0xC000C0C0, 0x9E009E9E, 0x57005757, 0xE300E3E3, 0xC300C3C3, 0x7B007B7B, 0x65006565,
    0x3B003B3B, 0x02000202, 0x8F008F8F, 0x3E003E3E, 0xE800E8E8, 0x25002525, 0x92009292, 0xE500E5E5,
    0x15001515, 0xDD00DDDD, 0xFD00FDFD, 0x17001717, 0xA900A9A9, 0xBF00BFBF, 0xD400D4D4, 0x9A009A9A,
    0x7E007E7E, 0xC500C5C5, 0x39003939, 0x67006767, 0xFE00FEFE, 0x76007676, 0x9D009D9D, 0x43004343,
    0xA700A7A7, 0xE100E1E1, 0xD000D0D0, 0xF500F5F5, 0x68006868, 0xF200F2F2, 0x1B001B1B, 0x34003434,
    0x70007070, 0x05000505, 0xA300A3A3, 0x8A008A8A, 0xD500D5D5, 0x79007979, 0x86008686, 0xA800A8A8,
    0x30003030, 0xC600C6C6, 0x51005151, 0x4B004B4B, 0x1E001E1E, 0xA600A6A6, 0x27002727, 0xF600F6F6,
    0x35003535, 0xD200D2D2, 0x6E006E6E, 0x24002424, 0x16001616, 0x82008282, 0x5F005F5F, 0xDA00DADA,
    0xE600E6E6, 0x75007575, 0xA200A2A2, 0xEF00EFEF, 0x2C002C2C, 0xB200B2B2, 0x1C001C1C, 0x9F009F9F,
    0x5D005D5D, 0x6F006F6F, 0x80008080, 0x0A000A0A, 0x72007272, 0x44004444, 0x9B009B9B, 0x6C006C6C,
    0x90009090, 0x0B000B0B, 0x5B005B5B, 0x33003333, 0x7D007D7D, 0x5A005A5A, 0x52005252, 0xF300F3F3,
    0x61006161, 0xA100A1A1, 0xF700F7F7, 0xB000B0B0, 0xD600D6D6, 0x3F003F3F, 0x7C007C7C, 0x6D006D6D,
    0xED00EDED, 0x14001414, 0xE000E0E0, 0xA500A5A5, 0x3D003D3D, 0x22002222, 0xB300B3B3, 0xF800F8F8,
    0x89008989, 0xDE00DEDE, 0x71007171, 0x1A001A1A, 0xAF00AFAF, 0xBA00BABA, 0xB500B5B5, 0x81008181,
];

/// `static const uint32_t X1[256]` — `aria.c:203-268`. `X1[j]` is `sb3[j]` in lanes 3, 2 and 0, with
/// lane 1 zero.
static X1: [u32; 256] = [
    0x52520052, 0x09090009, 0x6A6A006A, 0xD5D500D5, 0x30300030, 0x36360036, 0xA5A500A5, 0x38380038,
    0xBFBF00BF, 0x40400040, 0xA3A300A3, 0x9E9E009E, 0x81810081, 0xF3F300F3, 0xD7D700D7, 0xFBFB00FB,
    0x7C7C007C, 0xE3E300E3, 0x39390039, 0x82820082, 0x9B9B009B, 0x2F2F002F, 0xFFFF00FF, 0x87870087,
    0x34340034, 0x8E8E008E, 0x43430043, 0x44440044, 0xC4C400C4, 0xDEDE00DE, 0xE9E900E9, 0xCBCB00CB,
    0x54540054, 0x7B7B007B, 0x94940094, 0x32320032, 0xA6A600A6, 0xC2C200C2, 0x23230023, 0x3D3D003D,
    0xEEEE00EE, 0x4C4C004C, 0x95950095, 0x0B0B000B, 0x42420042, 0xFAFA00FA, 0xC3C300C3, 0x4E4E004E,
    0x08080008, 0x2E2E002E, 0xA1A100A1, 0x66660066, 0x28280028, 0xD9D900D9, 0x24240024, 0xB2B200B2,
    0x76760076, 0x5B5B005B, 0xA2A200A2, 0x49490049, 0x6D6D006D, 0x8B8B008B, 0xD1D100D1, 0x25250025,
    0x72720072, 0xF8F800F8, 0xF6F600F6, 0x64640064, 0x86860086, 0x68680068, 0x98980098, 0x16160016,
    0xD4D400D4, 0xA4A400A4, 0x5C5C005C, 0xCCCC00CC, 0x5D5D005D, 0x65650065, 0xB6B600B6, 0x92920092,
    0x6C6C006C, 0x70700070, 0x48480048, 0x50500050, 0xFDFD00FD, 0xEDED00ED, 0xB9B900B9, 0xDADA00DA,
    0x5E5E005E, 0x15150015, 0x46460046, 0x57570057, 0xA7A700A7, 0x8D8D008D, 0x9D9D009D, 0x84840084,
    0x90900090, 0xD8D800D8, 0xABAB00AB, 0x00000000, 0x8C8C008C, 0xBCBC00BC, 0xD3D300D3, 0x0A0A000A,
    0xF7F700F7, 0xE4E400E4, 0x58580058, 0x05050005, 0xB8B800B8, 0xB3B300B3, 0x45450045, 0x06060006,
    0xD0D000D0, 0x2C2C002C, 0x1E1E001E, 0x8F8F008F, 0xCACA00CA, 0x3F3F003F, 0x0F0F000F, 0x02020002,
    0xC1C100C1, 0xAFAF00AF, 0xBDBD00BD, 0x03030003, 0x01010001, 0x13130013, 0x8A8A008A, 0x6B6B006B,
    0x3A3A003A, 0x91910091, 0x11110011, 0x41410041, 0x4F4F004F, 0x67670067, 0xDCDC00DC, 0xEAEA00EA,
    0x97970097, 0xF2F200F2, 0xCFCF00CF, 0xCECE00CE, 0xF0F000F0, 0xB4B400B4, 0xE6E600E6, 0x73730073,
    0x96960096, 0xACAC00AC, 0x74740074, 0x22220022, 0xE7E700E7, 0xADAD00AD, 0x35350035, 0x85850085,
    0xE2E200E2, 0xF9F900F9, 0x37370037, 0xE8E800E8, 0x1C1C001C, 0x75750075, 0xDFDF00DF, 0x6E6E006E,
    0x47470047, 0xF1F100F1, 0x1A1A001A, 0x71710071, 0x1D1D001D, 0x29290029, 0xC5C500C5, 0x89890089,
    0x6F6F006F, 0xB7B700B7, 0x62620062, 0x0E0E000E, 0xAAAA00AA, 0x18180018, 0xBEBE00BE, 0x1B1B001B,
    0xFCFC00FC, 0x56560056, 0x3E3E003E, 0x4B4B004B, 0xC6C600C6, 0xD2D200D2, 0x79790079, 0x20200020,
    0x9A9A009A, 0xDBDB00DB, 0xC0C000C0, 0xFEFE00FE, 0x78780078, 0xCDCD00CD, 0x5A5A005A, 0xF4F400F4,
    0x1F1F001F, 0xDDDD00DD, 0xA8A800A8, 0x33330033, 0x88880088, 0x07070007, 0xC7C700C7, 0x31310031,
    0xB1B100B1, 0x12120012, 0x10100010, 0x59590059, 0x27270027, 0x80800080, 0xECEC00EC, 0x5F5F005F,
    0x60600060, 0x51510051, 0x7F7F007F, 0xA9A900A9, 0x19190019, 0xB5B500B5, 0x4A4A004A, 0x0D0D000D,
    0x2D2D002D, 0xE5E500E5, 0x7A7A007A, 0x9F9F009F, 0x93930093, 0xC9C900C9, 0x9C9C009C, 0xEFEF00EF,
    0xA0A000A0, 0xE0E000E0, 0x3B3B003B, 0x4D4D004D, 0xAEAE00AE, 0x2A2A002A, 0xF5F500F5, 0xB0B000B0,
    0xC8C800C8, 0xEBEB00EB, 0xBBBB00BB, 0x3C3C003C, 0x83830083, 0x53530053, 0x99990099, 0x61610061,
    0x17170017, 0x2B2B002B, 0x04040004, 0x7E7E007E, 0xBABA00BA, 0x77770077, 0xD6D600D6, 0x26260026,
    0xE1E100E1, 0x69690069, 0x14140014, 0x63630063, 0x55550055, 0x21210021, 0x0C0C000C, 0x7D7D007D,
];

/// `static const uint32_t X2[256]` — `aria.c:270-335`. `X2[j]` is `sb4[j]` in lanes 3, 2 and 1, with
/// lane 0 zero.
static X2: [u32; 256] = [
    0x30303000, 0x68686800, 0x99999900, 0x1B1B1B00, 0x87878700, 0xB9B9B900, 0x21212100, 0x78787800,
    0x50505000, 0x39393900, 0xDBDBDB00, 0xE1E1E100, 0x72727200, 0x09090900, 0x62626200, 0x3C3C3C00,
    0x3E3E3E00, 0x7E7E7E00, 0x5E5E5E00, 0x8E8E8E00, 0xF1F1F100, 0xA0A0A000, 0xCCCCCC00, 0xA3A3A300,
    0x2A2A2A00, 0x1D1D1D00, 0xFBFBFB00, 0xB6B6B600, 0xD6D6D600, 0x20202000, 0xC4C4C400, 0x8D8D8D00,
    0x81818100, 0x65656500, 0xF5F5F500, 0x89898900, 0xCBCBCB00, 0x9D9D9D00, 0x77777700, 0xC6C6C600,
    0x57575700, 0x43434300, 0x56565600, 0x17171700, 0xD4D4D400, 0x40404000, 0x1A1A1A00, 0x4D4D4D00,
    0xC0C0C000, 0x63636300, 0x6C6C6C00, 0xE3E3E300, 0xB7B7B700, 0xC8C8C800, 0x64646400, 0x6A6A6A00,
    0x53535300, 0xAAAAAA00, 0x38383800, 0x98989800, 0x0C0C0C00, 0xF4F4F400, 0x9B9B9B00, 0xEDEDED00,
    0x7F7F7F00, 0x22222200, 0x76767600, 0xAFAFAF00, 0xDDDDDD00, 0x3A3A3A00, 0x0B0B0B00, 0x58585800,
    0x67676700, 0x88888800, 0x06060600, 0xC3C3C300, 0x35353500, 0x0D0D0D00, 0x01010100, 0x8B8B8B00,
    0x8C8C8C00, 0xC2C2C200, 0xE6E6E600, 0x5F5F5F00, 0x02020200, 0x24242400, 0x75757500, 0x93939300,
    0x66666600, 0x1E1E1E00, 0xE5E5E500, 0xE2E2E200, 0x54545400, 0xD8D8D800, 0x10101000, 0xCECECE00,
    0x7A7A7A00, 0xE8E8E800, 0x08080800, 0x2C2C2C00, 0x12121200, 0x97979700, 0x32323200, 0xABABAB00,
    0xB4B4B400, 0x27272700, 0x0A0A0A00, 0x23232300, 0xDFDFDF00, 0xEFEFEF00, 0xCACACA00, 0xD9D9D900,
    0xB8B8B800, 0xFAFAFA00, 0xDCDCDC00, 0x31313100, 0x6B6B6B00, 0xD1D1D100, 0xADADAD00, 0x19191900,
    0x49494900, 0xBDBDBD00, 0x51515100, 0x96969600, 0xEEEEEE00, 0xE4E4E400, 0xA8A8A800, 0x41414100,
    0xDADADA00, 0xFFFFFF00, 0xCDCDCD00, 0x55555500, 0x86868600, 0x36363600, 0xBEBEBE00, 0x61616100,
    0x52525200, 0xF8F8F800, 0xBBBBBB00, 0x0E0E0E00, 0x82828200, 0x48484800, 0x69696900, 0x9A9A9A00,
    0xE0E0E000, 0x47474700, 0x9E9E9E00, 0x5C5C5C00, 0x04040400, 0x4B4B4B00, 0x34343400, 0x15151500,
    0x79797900, 0x26262600, 0xA7A7A700, 0xDEDEDE00, 0x29292900, 0xAEAEAE00, 0x92929200, 0xD7D7D700,
    0x84848400, 0xE9E9E900, 0xD2D2D200, 0xBABABA00, 0x5D5D5D00, 0xF3F3F300, 0xC5C5C500, 0xB0B0B000,
    0xBFBFBF00, 0xA4A4A400, 0x3B3B3B00, 0x71717100, 0x44444400, 0x46464600, 0x2B2B2B00, 0xFCFCFC00,
    0xEBEBEB00, 0x6F6F6F00, 0xD5D5D500, 0xF6F6F600, 0x14141400, 0xFEFEFE00, 0x7C7C7C00, 0x70707000,
    0x5A5A5A00, 0x7D7D7D00, 0xFDFDFD00, 0x2F2F2F00, 0x18181800, 0x83838300, 0x16161600, 0xA5A5A500,
    0x91919100, 0x1F1F1F00, 0x05050500, 0x95959500, 0x74747400, 0xA9A9A900, 0xC1C1C100, 0x5B5B5B00,
    0x4A4A4A00, 0x85858500, 0x6D6D6D00, 0x13131300, 0x07070700, 0x4F4F4F00, 0x4E4E4E00, 0x45454500,
    0xB2B2B200, 0x0F0F0F00, 0xC9C9C900, 0x1C1C1C00, 0xA6A6A600, 0xBCBCBC00, 0xECECEC00, 0x73737300,
    0x90909000, 0x7B7B7B00, 0xCFCFCF00, 0x59595900, 0x8F8F8F00, 0xA1A1A100, 0xF9F9F900, 0x2D2D2D00,
    0xF2F2F200, 0xB1B1B100, 0x00000000, 0x94949400, 0x37373700, 0x9F9F9F00, 0xD0D0D000, 0x2E2E2E00,
    0x9C9C9C00, 0x6E6E6E00, 0x28282800, 0x3F3F3F00, 0x80808000, 0xF0F0F000, 0x3D3D3D00, 0xD3D3D300,
    0x25252500, 0x8A8A8A00, 0xB5B5B500, 0xE7E7E700, 0x42424200, 0xB3B3B300, 0xC7C7C700, 0xEAEAEA00,
    0xF7F7F700, 0x4C4C4C00, 0x11111100, 0x33333300, 0x03030300, 0xA2A2A200, 0xACACAC00, 0x60606000,
];

/// `typedef union { unsigned char c[ARIA_BLOCK_SIZE]; unsigned int u[ARIA_BLOCK_SIZE /
/// sizeof(unsigned int)]; } ARIA_u128` — `include/crypto/aria.h:29-32`. The compiled branch reads
/// and writes the `u` member and copies the whole 16-byte object (the authority's
/// `memcpy(..., ARIA_BLOCK_SIZE)`), so both members are live here.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union AriaU128 {
    /// `unsigned char c[ARIA_BLOCK_SIZE]`.
    pub c: [c_uchar; ARIA_BLOCK_SIZE],
    /// `unsigned int u[ARIA_BLOCK_SIZE / sizeof(unsigned int)]` — four 32-bit round-key words.
    pub u: [u32; ARIA_BLOCK_SIZE / 4],
}

/// `struct aria_key_st { ARIA_u128 rd_key[ARIA_MAX_KEYS]; unsigned int rounds; }` —
/// `include/crypto/aria.h:36-40`.
#[repr(C)]
pub(crate) struct AriaKey {
    /// `ARIA_u128 rd_key[ARIA_MAX_KEYS]` — up to seventeen round keys.
    pub rd_key: [AriaU128; ARIA_MAX_KEYS],
    /// `unsigned int rounds` — 12, 14 or 16.
    pub rounds: c_uint,
}

/// `#define GET_U8_BE(X, Y) ((uint8_t)((X) >> ((3 - Y) * 8)))` — `aria.c:38`: byte `Y` of `x`,
/// counting from the most significant.
#[inline]
fn GET_U8_BE(x: u32, y: usize) -> u8 {
    (x >> ((3 - y) * 8)) as u8
}

/// `#define MAKE_U32(V0, V1, V2, V3)` — `aria.c:50-51`, the big-endian word from four bytes.
#[inline]
fn MAKE_U32(v0: u8, v1: u8, v2: u8, v3: u8) -> u32 {
    ((v0 as u32) << 24) | ((v1 as u32) << 16) | ((v2 as u32) << 8) | (v3 as u32)
}

/// `#define GET_U32_BE(X, Y)` — `aria.c:39-40`: big-endian word `Y` of a byte buffer.
///
/// # Safety
/// `x` is readable for `4 * y + 4` bytes.
#[inline]
unsafe fn GET_U32_BE(x: *const c_uchar, y: usize) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        ((*x.add(y * 4) as u32) << 24)
            | ((*x.add(y * 4 + 1) as u32) << 16)
            | ((*x.add(y * 4 + 2) as u32) << 8)
            | (*x.add(y * 4 + 3) as u32)
    }
}

/// `#define PUT_U32_BE(DEST, IDX, VAL)` — `aria.c:42-48`: store a word big-endian.
///
/// # Safety
/// `dest` is writable for `4 * idx + 4` bytes.
#[inline]
unsafe fn PUT_U32_BE(dest: *mut c_uchar, idx: usize, val: u32) {
    // SAFETY: the caller's contract.
    unsafe {
        *dest.add(idx * 4) = (val >> 24) as c_uchar;
        *dest.add(idx * 4 + 1) = (val >> 16) as c_uchar;
        *dest.add(idx * 4 + 2) = (val >> 8) as c_uchar;
        *dest.add(idx * 4 + 3) = val as c_uchar;
    }
}

/// The four-word view of an `ARIA_u128`, used wherever the authority writes `->u[i]`.
///
/// # Safety
/// `p` is a live `ARIA_u128`.
#[inline]
unsafe fn aria_words(p: *const AriaU128) -> [u32; 4] {
    // SAFETY: the caller's contract; the union's `u` member is the four-word view.
    unsafe { (*p).u }
}

/// `#define ARIA_ADD_ROUND_KEY(RK, T0, T1, T2, T3)` — `aria.c:338-344`: xor the round key's four
/// words into the four state words.
///
/// # Safety
/// `rk` is a live `ARIA_u128`.
#[inline]
unsafe fn ARIA_ADD_ROUND_KEY(rk: *const AriaU128, t: &mut [u32; 4]) {
    // SAFETY: the caller's contract; the union's `u` member is the word view.
    unsafe {
        t[0] ^= (*rk).u[0];
        t[1] ^= (*rk).u[1];
        t[2] ^= (*rk).u[2];
        t[3] ^= (*rk).u[3];
    }
}

/// `#define ARIA_SBOX_LAYER1_WITH_PRE_DIFF(T0, T1, T2, T3)` — `aria.c:347-353`. Each state word is
/// replaced independently, so the four assignments are a map over the state.
#[inline]
fn ARIA_SBOX_LAYER1_WITH_PRE_DIFF(t: &mut [u32; 4]) {
    for w in t.iter_mut() {
        *w = S1[GET_U8_BE(*w, 0) as usize]
            ^ S2[GET_U8_BE(*w, 1) as usize]
            ^ X1[GET_U8_BE(*w, 2) as usize]
            ^ X2[GET_U8_BE(*w, 3) as usize];
    }
}

/// `#define ARIA_SBOX_LAYER2_WITH_PRE_DIFF(T0, T1, T2, T3)` — `aria.c:356-362`: the even round's
/// table order, `X1`, `X2`, `S1`, `S2`.
#[inline]
fn ARIA_SBOX_LAYER2_WITH_PRE_DIFF(t: &mut [u32; 4]) {
    for w in t.iter_mut() {
        *w = X1[GET_U8_BE(*w, 0) as usize]
            ^ X2[GET_U8_BE(*w, 1) as usize]
            ^ S1[GET_U8_BE(*w, 2) as usize]
            ^ S2[GET_U8_BE(*w, 3) as usize];
    }
}

/// `#define ARIA_DIFF_WORD(T0, T1, T2, T3)` — `aria.c:365-374`. The six `^=` statements are
/// order-dependent; they are transcribed in the authority's order.
#[inline]
fn ARIA_DIFF_WORD(t: &mut [u32; 4]) {
    t[1] ^= t[2];
    t[2] ^= t[3];
    t[0] ^= t[1];
    t[3] ^= t[1];
    t[2] ^= t[0];
    t[1] ^= t[2];
}

/// `#define ARIA_DIFF_BYTE(T0, T1, T2, T3)` — `aria.c:377-382`: a masked byte swap on the second
/// word, a 16-bit rotation on the third and a full byte swap on the fourth. `rotl32`/`rotr32` are
/// the authority's own macros (`aria.c:32-33`) and `bswap32` is `aria.c:35-36`.
#[inline]
fn ARIA_DIFF_BYTE(t: &mut [u32; 4]) {
    t[1] = ((t[1] << 8) & 0xff00_ff00) ^ ((t[1] >> 8) & 0x00ff_00ff);
    t[2] = t[2].rotate_right(16);
    t[3] = t[3].swap_bytes();
}

/// `#define ARIA_SUBST_DIFF_ODD(T0, T1, T2, T3)` — `aria.c:385-391`.
#[inline]
fn ARIA_SUBST_DIFF_ODD(t: &mut [u32; 4]) {
    ARIA_SBOX_LAYER1_WITH_PRE_DIFF(t);
    ARIA_DIFF_WORD(t);
    ARIA_DIFF_BYTE(t);
    ARIA_DIFF_WORD(t);
}

/// `#define ARIA_SUBST_DIFF_EVEN(T0, T1, T2, T3)` — `aria.c:394-400`. The byte diffusion is applied
/// with its arguments **rotated** there — `ARIA_DIFF_BYTE(T2, T3, T0, T1)` — so `T2`, `T3`, `T0`
/// and `T1` take the roles of the macro's first through fourth parameters for that one step. The
/// rotation is reproduced rather than flattened, because flattening it into a differently-shaped
/// helper is exactly the class of transcription error the standard vector exists to catch.
#[inline]
fn ARIA_SUBST_DIFF_EVEN(t: &mut [u32; 4]) {
    ARIA_SBOX_LAYER2_WITH_PRE_DIFF(t);
    ARIA_DIFF_WORD(t);
    let mut r = [t[2], t[3], t[0], t[1]];
    ARIA_DIFF_BYTE(&mut r);
    t[2] = r[0];
    t[3] = r[1];
    t[0] = r[2];
    t[1] = r[3];
    ARIA_DIFF_WORD(t);
}

/// `#define ARIA_GSRK(RK, X, Y, N)` over `_ARIA_GSRK(RK, X, Y, Q, R)` — `aria.c:403-411`. The macro
/// derives `Q = 4 - N / 32` and `R = N % 32`; every `N` the schedule uses (19, 31, 67, 97, 109) has
/// `R` in `1..=31`, so the `<< (32 - R)` shifts are in range.
///
/// # Safety
/// `rk` is a live `ARIA_u128`.
#[inline]
unsafe fn ARIA_GSRK(rk: *mut AriaU128, x: &[u32; 4], y: &[u32; 4], n: u32) {
    let q = 4 - (n / 32);
    let r = n % 32;
    // SAFETY: the caller's contract; the union's `u` member is the word view.
    unsafe {
        (*rk).u[0] = x[0] ^ (y[(q % 4) as usize] >> r) ^ (y[((q + 3) % 4) as usize] << (32 - r));
        (*rk).u[1] = x[1] ^ (y[((q + 1) % 4) as usize] >> r) ^ (y[(q % 4) as usize] << (32 - r));
        (*rk).u[2] =
            x[2] ^ (y[((q + 2) % 4) as usize] >> r) ^ (y[((q + 1) % 4) as usize] << (32 - r));
        (*rk).u[3] =
            x[3] ^ (y[((q + 3) % 4) as usize] >> r) ^ (y[((q + 2) % 4) as usize] << (32 - r));
    }
}

/// `#define ARIA_DEC_DIFF_BYTE(X, Y, TMP, TMP2)` — `aria.c:413-418`: answer the `Y` the macro
/// stores for input `X`. `TMP` and `TMP2` are only the macro's temporaries.
#[inline]
fn ARIA_DEC_DIFF_BYTE(x: u32) -> u32 {
    let tmp = x;
    let tmp2 = tmp.rotate_right(8);
    tmp2 ^ (tmp ^ tmp2).rotate_right(16)
}

/// `void ossl_aria_encrypt(const unsigned char *in, unsigned char *out, const ARIA_KEY *key)` —
/// `aria.c:420-469`, the compiled branch.
///
/// **Decryption is this function.** The header declares no decrypt entry point; a caller builds
/// `ossl_aria_set_decrypt_key`'s schedule and runs this same loop over it. The round count is
/// re-checked here (the authority returns silently for anything but 12, 14 and 16) and the final
/// round substitutes through the *byte* values of the four tables rather than the word xor, which is
/// why `X2`'s entry is shifted down by 8 before its low byte is taken.
///
/// # Safety
/// `in_` is readable for sixteen bytes; `out` is writable for sixteen; `key` is live.
pub(crate) unsafe fn ossl_aria_encrypt(
    in_: *const c_uchar,
    out: *mut c_uchar,
    key: *const AriaKey,
) {
    if in_.is_null() || out.is_null() || key.is_null() {
        return;
    }
    // SAFETY: `key` was checked non-null.
    let nr = unsafe { (*key).rounds };
    if !matches!(nr, 12 | 14 | 16) {
        return;
    }
    // SAFETY: `key` is live; `rd_key` holds `nr + 1` live entries for a schedule of `nr` rounds.
    let rk = unsafe { (*key).rd_key.as_ptr() };
    // SAFETY: `in_` is readable for sixteen bytes.
    let mut t = unsafe {
        [
            GET_U32_BE(in_, 0),
            GET_U32_BE(in_, 1),
            GET_U32_BE(in_, 2),
            GET_U32_BE(in_, 3),
        ]
    };

    // SAFETY: `rk` is live for `nr + 1` entries and `t` is a live local.
    unsafe { ARIA_ADD_ROUND_KEY(rk, &mut t) };
    ARIA_SUBST_DIFF_ODD(&mut t);
    // SAFETY: index 1 is in range for every valid `nr`.
    unsafe { ARIA_ADD_ROUND_KEY(rk.add(1), &mut t) };

    let mut idx = 2usize;
    let mut left = nr - 2;
    while left > 0 {
        ARIA_SUBST_DIFF_EVEN(&mut t);
        // SAFETY: `idx` advances two per iteration and stays below `nr`.
        unsafe { ARIA_ADD_ROUND_KEY(rk.add(idx), &mut t) };
        idx += 1;
        ARIA_SUBST_DIFF_ODD(&mut t);
        // SAFETY: as above.
        unsafe { ARIA_ADD_ROUND_KEY(rk.add(idx), &mut t) };
        idx += 1;
        left -= 2;
    }

    // SAFETY: `rk` has `nr + 1` entries, so `rd_key[nr]` is the final round key.
    let last = unsafe { aria_words(rk.add(nr as usize)) };
    t[0] = last[0]
        ^ MAKE_U32(
            X1[GET_U8_BE(t[0], 0) as usize] as u8,
            (X2[GET_U8_BE(t[0], 1) as usize] >> 8) as u8,
            S1[GET_U8_BE(t[0], 2) as usize] as u8,
            S2[GET_U8_BE(t[0], 3) as usize] as u8,
        );
    t[1] = last[1]
        ^ MAKE_U32(
            X1[GET_U8_BE(t[1], 0) as usize] as u8,
            (X2[GET_U8_BE(t[1], 1) as usize] >> 8) as u8,
            S1[GET_U8_BE(t[1], 2) as usize] as u8,
            S2[GET_U8_BE(t[1], 3) as usize] as u8,
        );
    t[2] = last[2]
        ^ MAKE_U32(
            X1[GET_U8_BE(t[2], 0) as usize] as u8,
            (X2[GET_U8_BE(t[2], 1) as usize] >> 8) as u8,
            S1[GET_U8_BE(t[2], 2) as usize] as u8,
            S2[GET_U8_BE(t[2], 3) as usize] as u8,
        );
    t[3] = last[3]
        ^ MAKE_U32(
            X1[GET_U8_BE(t[3], 0) as usize] as u8,
            (X2[GET_U8_BE(t[3], 1) as usize] >> 8) as u8,
            S1[GET_U8_BE(t[3], 2) as usize] as u8,
            S2[GET_U8_BE(t[3], 3) as usize] as u8,
        );

    // SAFETY: `out` is writable for sixteen bytes.
    unsafe {
        PUT_U32_BE(out, 0, t[0]);
        PUT_U32_BE(out, 1, t[1]);
        PUT_U32_BE(out, 2, t[2]);
        PUT_U32_BE(out, 3, t[3]);
    }
}

/// `int ossl_aria_set_encrypt_key(const unsigned char *userKey, const int bits, ARIA_KEY *key)` —
/// `aria.c:471-599`, the compiled branch.
///
/// The round count is `(bits + 256) / 32`, and the `Key_RC` pointer starts at row
/// `(bits - 128) / 64` but is read as one flattened run, so `ck[4]` is the next row's first word.
/// The standard defines the fourth and fifth schedule groups only for the longer keys, and the
/// authority short-circuits the unused `ARIA_GSRK` calls with `bits > 128` and `bits > 192`; those
/// tests are kept.
///
/// The `bits` validity check is hoisted above the `(bits + 256) / 32` computation. C computes the
/// count first but only uses it on the valid path, and with `overflow-checks = true` the unchecked
/// `bits + 256` would otherwise be a reachable panic for a caller that passes an absurd size.
///
/// # Safety
/// `user_key` is readable for `bits / 8` bytes; `key` is writable.
pub(crate) unsafe fn ossl_aria_set_encrypt_key(
    user_key: *const c_uchar,
    bits: c_int,
    key: *mut AriaKey,
) -> c_int {
    if user_key.is_null() || key.is_null() {
        return -1;
    }
    if !matches!(bits, 128 | 192 | 256) {
        return -2;
    }

    let nr = (bits + 256) / 32;
    // SAFETY: `key` was checked non-null.
    unsafe { (*key).rounds = nr as c_uint };
    // SAFETY: `key` is live; `rd_key` is a live `[ARIA_u128; ARIA_MAX_KEYS]`.
    let rk = unsafe { core::ptr::addr_of_mut!((*key).rd_key).cast::<AriaU128>() };

    // `ck` is `&Key_RC[(bits - 128) / 64][0]` read as a flat run of twelve words.
    let base = ((bits - 128) / 64) as usize * 4;
    let ck = |i: usize| KEY_RC[(base + i) / 4][(base + i) % 4];

    // SAFETY: `user_key` is readable for at least sixteen bytes.
    let w0 = unsafe {
        [
            GET_U32_BE(user_key, 0),
            GET_U32_BE(user_key, 1),
            GET_U32_BE(user_key, 2),
            GET_U32_BE(user_key, 3),
        ]
    };

    let mut reg = [w0[0] ^ ck(0), w0[1] ^ ck(1), w0[2] ^ ck(2), w0[3] ^ ck(3)];
    ARIA_SUBST_DIFF_ODD(&mut reg);

    let mut w1 = [0u32; 4];
    if bits > 128 {
        // SAFETY: `bits > 128`, so `user_key` is readable for at least twenty-four bytes.
        unsafe {
            w1[0] = GET_U32_BE(user_key, 4);
            w1[1] = GET_U32_BE(user_key, 5);
        }
        if bits > 192 {
            // SAFETY: `bits > 192`, so `user_key` is readable for at least thirty-two bytes.
            unsafe {
                w1[2] = GET_U32_BE(user_key, 6);
                w1[3] = GET_U32_BE(user_key, 7);
            }
        }
    }
    for (a, b) in w1.iter_mut().zip(reg.iter()) {
        *a ^= *b;
    }

    reg = w1;
    reg[0] ^= ck(4);
    reg[1] ^= ck(5);
    reg[2] ^= ck(6);
    reg[3] ^= ck(7);
    ARIA_SUBST_DIFF_EVEN(&mut reg);
    for (a, b) in reg.iter_mut().zip(w0.iter()) {
        *a ^= *b;
    }
    let w2 = reg;

    reg[0] ^= ck(8);
    reg[1] ^= ck(9);
    reg[2] ^= ck(10);
    reg[3] ^= ck(11);
    ARIA_SUBST_DIFF_ODD(&mut reg);
    let w3 = [
        reg[0] ^ w1[0],
        reg[1] ^ w1[1],
        reg[2] ^ w1[2],
        reg[3] ^ w1[3],
    ];

    // SAFETY: `rk` is the start of `key->rd_key`, a live array of `ARIA_MAX_KEYS` entries, and the
    // schedule below writes indices 0..=16.
    unsafe {
        ARIA_GSRK(rk.add(0), &w0, &w1, 19);
        ARIA_GSRK(rk.add(1), &w1, &w2, 19);
        ARIA_GSRK(rk.add(2), &w2, &w3, 19);
        ARIA_GSRK(rk.add(3), &w3, &w0, 19);
        ARIA_GSRK(rk.add(4), &w0, &w1, 31);
        ARIA_GSRK(rk.add(5), &w1, &w2, 31);
        ARIA_GSRK(rk.add(6), &w2, &w3, 31);
        ARIA_GSRK(rk.add(7), &w3, &w0, 31);
        ARIA_GSRK(rk.add(8), &w0, &w1, 67);
        ARIA_GSRK(rk.add(9), &w1, &w2, 67);
        ARIA_GSRK(rk.add(10), &w2, &w3, 67);
        ARIA_GSRK(rk.add(11), &w3, &w0, 67);
        ARIA_GSRK(rk.add(12), &w0, &w1, 97);
        if bits > 128 {
            ARIA_GSRK(rk.add(13), &w1, &w2, 97);
            ARIA_GSRK(rk.add(14), &w2, &w3, 97);
        }
        if bits > 192 {
            ARIA_GSRK(rk.add(15), &w3, &w0, 97);
            ARIA_GSRK(rk.add(16), &w0, &w1, 109);
        }
    }

    0
}

/// `int ossl_aria_set_decrypt_key(const unsigned char *userKey, const int bits, ARIA_KEY *key)` —
/// `aria.c:601-683`, the compiled branch.
///
/// The encryption schedule is built first and then unwound in place: the first and last round keys
/// are swapped (the authority's `memcpy(rk_head, rk_tail, ARIA_BLOCK_SIZE)` plus the register
/// stores), and every remaining pair is passed through `ARIA_DEC_DIFF_BYTE` and the same diffusion
/// the round uses, so that running `ossl_aria_encrypt` over the result decrypts. The middle loop
/// walks inward from both ends; the key left at the centre when they meet is finished by the tail
/// block after the loop.
///
/// # Safety
/// As `ossl_aria_set_encrypt_key`.
pub(crate) unsafe fn ossl_aria_set_decrypt_key(
    user_key: *const c_uchar,
    bits: c_int,
    key: *mut AriaKey,
) -> c_int {
    // SAFETY: the caller's contract.
    let r = unsafe { ossl_aria_set_encrypt_key(user_key, bits, key) };
    if r != 0 {
        return r;
    }

    // SAFETY: `key` is live and holds a completed encryption schedule.
    let rounds = unsafe { (*key).rounds as usize };
    // SAFETY: `key` is live; `rd_key` is a live `[ARIA_u128; ARIA_MAX_KEYS]` and `rounds <= 16`.
    let rk = unsafe { core::ptr::addr_of_mut!((*key).rd_key).cast::<AriaU128>() };

    // SAFETY: `rk` is live for `rounds + 1` entries; the union's `u` member is the word view.
    let first = unsafe { aria_words(rk) };
    // SAFETY: the byte copy is the authority's `memcpy(rk_head, rk_tail, ARIA_BLOCK_SIZE)`; `rk` is
    // live for `rounds + 1` entries and the union's `c` and `u` members are its two views.
    unsafe {
        (*rk).c = (*rk.add(rounds)).c;
        (*rk.add(rounds)).u = first;
    }

    let mut head = 1usize;
    let mut tail = rounds - 1;
    while head < tail {
        // SAFETY: `head` is in `0..rounds` and `rk` is live.
        let hw = unsafe { aria_words(rk.add(head)) };
        let mut reg = [
            ARIA_DEC_DIFF_BYTE(hw[0]),
            ARIA_DEC_DIFF_BYTE(hw[1]),
            ARIA_DEC_DIFF_BYTE(hw[2]),
            ARIA_DEC_DIFF_BYTE(hw[3]),
        ];
        ARIA_DIFF_WORD(&mut reg);
        ARIA_DIFF_BYTE(&mut reg);
        ARIA_DIFF_WORD(&mut reg);
        let s = reg;

        // SAFETY: `tail` is in `0..rounds` and `rk` is live.
        let tw = unsafe { aria_words(rk.add(tail)) };
        let mut reg = [
            ARIA_DEC_DIFF_BYTE(tw[0]),
            ARIA_DEC_DIFF_BYTE(tw[1]),
            ARIA_DEC_DIFF_BYTE(tw[2]),
            ARIA_DEC_DIFF_BYTE(tw[3]),
        ];
        ARIA_DIFF_WORD(&mut reg);
        ARIA_DIFF_BYTE(&mut reg);
        ARIA_DIFF_WORD(&mut reg);

        // SAFETY: `head != tail`, both are in `0..rounds`, and `rk` is live.
        unsafe {
            (*rk.add(head)).u = reg;
            (*rk.add(tail)).u = s;
        }
        head += 1;
        tail -= 1;
    }

    // SAFETY: `tail == head` after the loop, and both are in `0..rounds`.
    let cw = unsafe { aria_words(rk.add(tail)) };
    let mut reg = [
        ARIA_DEC_DIFF_BYTE(cw[0]),
        ARIA_DEC_DIFF_BYTE(cw[1]),
        ARIA_DEC_DIFF_BYTE(cw[2]),
        ARIA_DEC_DIFF_BYTE(cw[3]),
    ];
    ARIA_DIFF_WORD(&mut reg);
    ARIA_DIFF_BYTE(&mut reg);
    ARIA_DIFF_WORD(&mut reg);
    // SAFETY: `tail` is in `0..rounds` and `rk` is live.
    unsafe { (*rk.add(tail)).u = reg };

    0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// `static const unsigned char sb1[256]` — `aria.c:687-720`; `sb2` is `aria.c:722-755`,
    /// `sb3` `aria.c:757-790` and `sb4` `aria.c:792-825`. These are the `#else` branch's byte
    /// S-boxes. The compiled branch never references them; they are read out of the authority and
    /// emitted here only so the expansion into `S1`..`X2` can be checked rather than assumed.
    const SB1: [u8; 256] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
        0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
        0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
        0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
        0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
        0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
        0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
        0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
        0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
        0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
        0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1,
        0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16,
    ];
    /// As [`SB1`] — `aria.c:722-755`.
    const SB2: [u8; 256] = [
        0xE2, 0x4E, 0x54, 0xFC, 0x94, 0xC2, 0x4A, 0xCC, 0x62, 0x0D, 0x6A, 0x46, 0x3C, 0x4D, 0x8B,
        0xD1, 0x5E, 0xFA, 0x64, 0xCB, 0xB4, 0x97, 0xBE, 0x2B, 0xBC, 0x77, 0x2E, 0x03, 0xD3, 0x19,
        0x59, 0xC1, 0x1D, 0x06, 0x41, 0x6B, 0x55, 0xF0, 0x99, 0x69, 0xEA, 0x9C, 0x18, 0xAE, 0x63,
        0xDF, 0xE7, 0xBB, 0x00, 0x73, 0x66, 0xFB, 0x96, 0x4C, 0x85, 0xE4, 0x3A, 0x09, 0x45, 0xAA,
        0x0F, 0xEE, 0x10, 0xEB, 0x2D, 0x7F, 0xF4, 0x29, 0xAC, 0xCF, 0xAD, 0x91, 0x8D, 0x78, 0xC8,
        0x95, 0xF9, 0x2F, 0xCE, 0xCD, 0x08, 0x7A, 0x88, 0x38, 0x5C, 0x83, 0x2A, 0x28, 0x47, 0xDB,
        0xB8, 0xC7, 0x93, 0xA4, 0x12, 0x53, 0xFF, 0x87, 0x0E, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01,
        0x8E, 0x37, 0x74, 0x32, 0xCA, 0xE9, 0xB1, 0xB7, 0xAB, 0x0C, 0xD7, 0xC4, 0x56, 0x42, 0x26,
        0x07, 0x98, 0x60, 0xD9, 0xB6, 0xB9, 0x11, 0x40, 0xEC, 0x20, 0x8C, 0xBD, 0xA0, 0xC9, 0x84,
        0x04, 0x49, 0x23, 0xF1, 0x4F, 0x50, 0x1F, 0x13, 0xDC, 0xD8, 0xC0, 0x9E, 0x57, 0xE3, 0xC3,
        0x7B, 0x65, 0x3B, 0x02, 0x8F, 0x3E, 0xE8, 0x25, 0x92, 0xE5, 0x15, 0xDD, 0xFD, 0x17, 0xA9,
        0xBF, 0xD4, 0x9A, 0x7E, 0xC5, 0x39, 0x67, 0xFE, 0x76, 0x9D, 0x43, 0xA7, 0xE1, 0xD0, 0xF5,
        0x68, 0xF2, 0x1B, 0x34, 0x70, 0x05, 0xA3, 0x8A, 0xD5, 0x79, 0x86, 0xA8, 0x30, 0xC6, 0x51,
        0x4B, 0x1E, 0xA6, 0x27, 0xF6, 0x35, 0xD2, 0x6E, 0x24, 0x16, 0x82, 0x5F, 0xDA, 0xE6, 0x75,
        0xA2, 0xEF, 0x2C, 0xB2, 0x1C, 0x9F, 0x5D, 0x6F, 0x80, 0x0A, 0x72, 0x44, 0x9B, 0x6C, 0x90,
        0x0B, 0x5B, 0x33, 0x7D, 0x5A, 0x52, 0xF3, 0x61, 0xA1, 0xF7, 0xB0, 0xD6, 0x3F, 0x7C, 0x6D,
        0xED, 0x14, 0xE0, 0xA5, 0x3D, 0x22, 0xB3, 0xF8, 0x89, 0xDE, 0x71, 0x1A, 0xAF, 0xBA, 0xB5,
        0x81,
    ];
    /// As [`SB1`] — `aria.c:757-790`.
    const SB3: [u8; 256] = [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7,
        0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE,
        0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42,
        0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
        0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C,
        0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15,
        0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7,
        0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
        0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC,
        0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
        0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D,
        0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
        0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD, 0xA8,
        0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51,
        0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0,
        0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C,
        0x7D,
    ];
    /// As [`SB1`] — `aria.c:792-825`.
    const SB4: [u8; 256] = [
        0x30, 0x68, 0x99, 0x1B, 0x87, 0xB9, 0x21, 0x78, 0x50, 0x39, 0xDB, 0xE1, 0x72, 0x09, 0x62,
        0x3C, 0x3E, 0x7E, 0x5E, 0x8E, 0xF1, 0xA0, 0xCC, 0xA3, 0x2A, 0x1D, 0xFB, 0xB6, 0xD6, 0x20,
        0xC4, 0x8D, 0x81, 0x65, 0xF5, 0x89, 0xCB, 0x9D, 0x77, 0xC6, 0x57, 0x43, 0x56, 0x17, 0xD4,
        0x40, 0x1A, 0x4D, 0xC0, 0x63, 0x6C, 0xE3, 0xB7, 0xC8, 0x64, 0x6A, 0x53, 0xAA, 0x38, 0x98,
        0x0C, 0xF4, 0x9B, 0xED, 0x7F, 0x22, 0x76, 0xAF, 0xDD, 0x3A, 0x0B, 0x58, 0x67, 0x88, 0x06,
        0xC3, 0x35, 0x0D, 0x01, 0x8B, 0x8C, 0xC2, 0xE6, 0x5F, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1E,
        0xE5, 0xE2, 0x54, 0xD8, 0x10, 0xCE, 0x7A, 0xE8, 0x08, 0x2C, 0x12, 0x97, 0x32, 0xAB, 0xB4,
        0x27, 0x0A, 0x23, 0xDF, 0xEF, 0xCA, 0xD9, 0xB8, 0xFA, 0xDC, 0x31, 0x6B, 0xD1, 0xAD, 0x19,
        0x49, 0xBD, 0x51, 0x96, 0xEE, 0xE4, 0xA8, 0x41, 0xDA, 0xFF, 0xCD, 0x55, 0x86, 0x36, 0xBE,
        0x61, 0x52, 0xF8, 0xBB, 0x0E, 0x82, 0x48, 0x69, 0x9A, 0xE0, 0x47, 0x9E, 0x5C, 0x04, 0x4B,
        0x34, 0x15, 0x79, 0x26, 0xA7, 0xDE, 0x29, 0xAE, 0x92, 0xD7, 0x84, 0xE9, 0xD2, 0xBA, 0x5D,
        0xF3, 0xC5, 0xB0, 0xBF, 0xA4, 0x3B, 0x71, 0x44, 0x46, 0x2B, 0xFC, 0xEB, 0x6F, 0xD5, 0xF6,
        0x14, 0xFE, 0x7C, 0x70, 0x5A, 0x7D, 0xFD, 0x2F, 0x18, 0x83, 0x16, 0xA5, 0x91, 0x1F, 0x05,
        0x95, 0x74, 0xA9, 0xC1, 0x5B, 0x4A, 0x85, 0x6D, 0x13, 0x07, 0x4F, 0x4E, 0x45, 0xB2, 0x0F,
        0xC9, 0x1C, 0xA6, 0xBC, 0xEC, 0x73, 0x90, 0x7B, 0xCF, 0x59, 0x8F, 0xA1, 0xF9, 0x2D, 0xF2,
        0xB1, 0x00, 0x94, 0x37, 0x9F, 0xD0, 0x2E, 0x9C, 0x6E, 0x28, 0x3F, 0x80, 0xF0, 0x3D, 0xD3,
        0x25, 0x8A, 0xB5, 0xE7, 0x42, 0xB3, 0xC7, 0xEA, 0xF7, 0x4C, 0x11, 0x33, 0x03, 0xA2, 0xAC,
        0x60,
    ];

    /// The four-word view of a whole schedule, so two schedules can be compared without
    /// `PartialEq` on the union.
    fn schedule_words(k: &AriaKey) -> [[u32; 4]; ARIA_MAX_KEYS] {
        let mut out = [[0u32; 4]; ARIA_MAX_KEYS];
        for (i, rk) in k.rd_key.iter().enumerate() {
            // SAFETY: `rk` is a live `ARIA_u128`; the union's `u` member is the word view.
            out[i] = unsafe { aria_words(core::ptr::addr_of!(*rk)) };
        }
        out
    }

    /// **The tables are the authority's literals, including its repetition.** The head and tail
    /// entries are compared against values read out of `aria.c` by `court/gen-aria.py`; the only
    /// relation the table itself carries is that rows 3 and 4 of `Key_RC` repeat rows 0 and 1, and
    /// the authority writes them out rather than leaving them implicit.
    #[test]
    fn the_tables_are_the_authoritys_literals() {
        assert_eq!(
            [S1[0], S1[1], S1[255]],
            [0x00636363, 0x007C7C7C, 0x00161616]
        );
        assert_eq!(
            [S2[0], S2[1], S2[255]],
            [0xE200E2E2, 0x4E004E4E, 0x81008181]
        );
        assert_eq!(
            [X1[0], X1[1], X1[255]],
            [0x52520052, 0x09090009, 0x7D7D007D]
        );
        assert_eq!(
            [X2[0], X2[1], X2[255]],
            [0x30303000, 0x68686800, 0x60606000]
        );
        assert_eq!(KEY_RC[0], [0x517CC1B7, 0x27220A94, 0xFE13ABE8, 0xFA9A6EE0]);
        assert_eq!(KEY_RC[2], [0xDB92371D, 0x2126E970, 0x03249775, 0x04E8C90E]);
        assert_eq!(KEY_RC[3], KEY_RC[0]);
        assert_eq!(KEY_RC[4], KEY_RC[1]);
    }

    /// **The 32-bit tables are the byte S-boxes in complementary lanes.** Each word table is one of
    /// `sb1`..`sb4` replicated across the three lanes the round's xor leaves to it, with the fourth
    /// lane zero: `S1` is lanes 0,1,2; `S2` lanes 0,1,3; `X1` lanes 0,2,3; `X2` lanes 1,2,3. The
    /// check runs over all 256 entries, so a single mistyped row of any table fails it.
    #[test]
    fn the_byte_sboxes_expand_to_the_word_tables() {
        for (v, &b1) in SB1.iter().enumerate() {
            assert_eq!(S1[v], u32::from(b1) * 0x0001_0101);
            assert_eq!(S2[v], u32::from(SB2[v]) * 0x0100_0101);
            assert_eq!(X1[v], u32::from(SB3[v]) * 0x0101_0001);
            assert_eq!(X2[v], u32::from(SB4[v]) * 0x0101_0100);
        }
    }

    /// RFC 5794 Appendix A's first vector, read from the pinned corpus at
    /// `test/recipes/30-test_evp_data/evpciph_aria.txt:16-19`: key `000102030405060708090a0b0c0d0e0f`,
    /// plaintext `00112233445566778899aabbccddeeff`, ciphertext
    /// `d718fbd6ab644c739da95f3be6451778`. A **published** vector, not this transcription's output,
    /// so it is the evidence that the table lane assignment, both byte orders and the round-key order
    /// are right. The same test then decrypts, through the separate decrypt schedule.
    #[test]
    fn the_standard_vector_round_trips() {
        let key = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let mut ek = AriaKey {
            rd_key: [AriaU128 { u: [0; 4] }; ARIA_MAX_KEYS],
            rounds: 0,
        };
        let mut ct = [0u8; ARIA_BLOCK_SIZE];
        // SAFETY: every buffer is a live local of the required length.
        unsafe {
            assert_eq!(ossl_aria_set_encrypt_key(key.as_ptr(), 128, &mut ek), 0);
            ossl_aria_encrypt(pt.as_ptr(), ct.as_mut_ptr(), &ek);
        }
        assert_eq!(
            ct,
            [
                0xd7, 0x18, 0xfb, 0xd6, 0xab, 0x64, 0x4c, 0x73, 0x9d, 0xa9, 0x5f, 0x3b, 0xe6, 0x45,
                0x17, 0x78
            ]
        );

        let mut dk = AriaKey {
            rd_key: [AriaU128 { u: [0; 4] }; ARIA_MAX_KEYS],
            rounds: 0,
        };
        let mut back = [0u8; ARIA_BLOCK_SIZE];
        // SAFETY: as above.
        unsafe {
            assert_eq!(ossl_aria_set_decrypt_key(key.as_ptr(), 128, &mut dk), 0);
            ossl_aria_encrypt(ct.as_ptr(), back.as_mut_ptr(), &dk);
        }
        assert_eq!(back, pt);
    }

    /// RFC 5794 Appendix A's 192- and 256-bit vectors, read from the same pinned file at
    /// `evpciph_aria.txt:21-24` and `:26-29`: the 192-bit key
    /// `000102030405060708090a0b0c0d0e0f1011121314151617` gives
    /// `26449c1805dbe7aa25a468ce263a9e79`, and the 256-bit key
    /// `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` gives
    /// `f92bd7c79fb72e2f2b8f80c1972d24fc`. The 128-bit test above never reaches round keys 13..16,
    /// so these are the only evidence that the `bits > 128` and `bits > 192` branches of
    /// `ossl_aria_set_encrypt_key` — and the matching unwind in the decrypt schedule — are right.
    #[test]
    fn the_longer_key_schedules_match_the_standard_vectors() {
        let pt = [
            0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let cases: [(&[u8], c_int, [u8; 16]); 2] = [
            (
                &[
                    0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                ],
                192,
                [
                    0x26, 0x44, 0x9c, 0x18, 0x05, 0xdb, 0xe7, 0xaa, 0x25, 0xa4, 0x68, 0xce, 0x26,
                    0x3a, 0x9e, 0x79,
                ],
            ),
            (
                &[
                    0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                256,
                [
                    0xf9, 0x2b, 0xd7, 0xc7, 0x9f, 0xb7, 0x2e, 0x2f, 0x2b, 0x8f, 0x80, 0xc1, 0x97,
                    0x2d, 0x24, 0xfc,
                ],
            ),
        ];

        for (key, bits, expect) in cases {
            let mut ek = AriaKey {
                rd_key: [AriaU128 { u: [0; 4] }; ARIA_MAX_KEYS],
                rounds: 0,
            };
            let mut ct = [0u8; ARIA_BLOCK_SIZE];
            // SAFETY: every buffer is a live local of the required length.
            unsafe {
                assert_eq!(ossl_aria_set_encrypt_key(key.as_ptr(), bits, &mut ek), 0);
                ossl_aria_encrypt(pt.as_ptr(), ct.as_mut_ptr(), &ek);
            }
            assert_eq!(ct, expect);

            let mut dk = AriaKey {
                rd_key: [AriaU128 { u: [0; 4] }; ARIA_MAX_KEYS],
                rounds: 0,
            };
            let mut back = [0u8; ARIA_BLOCK_SIZE];
            // SAFETY: as above.
            unsafe {
                assert_eq!(ossl_aria_set_decrypt_key(key.as_ptr(), bits, &mut dk), 0);
                ossl_aria_encrypt(ct.as_ptr(), back.as_mut_ptr(), &dk);
            }
            assert_eq!(back, pt);
        }
    }

    /// A schedule is a function of the key alone, so two from one key are equal and one from a
    /// changed key is not. The first round key is not the key words: the `Key_RC` constants and the
    /// substitution/diffusion layers have already been applied.
    #[test]
    fn the_key_schedule_is_deterministic_and_key_dependent() {
        let key = [0x11u8; 16];
        let mut other = [0x11u8; 16];
        other[15] = 0x12;

        let mut a = AriaKey {
            rd_key: [AriaU128 { u: [0; 4] }; ARIA_MAX_KEYS],
            rounds: 0,
        };
        let mut b = AriaKey {
            rd_key: [AriaU128 { u: [0; 4] }; ARIA_MAX_KEYS],
            rounds: 0,
        };
        let mut c = AriaKey {
            rd_key: [AriaU128 { u: [0; 4] }; ARIA_MAX_KEYS],
            rounds: 0,
        };
        // SAFETY: every buffer is a live local.
        unsafe {
            assert_eq!(ossl_aria_set_encrypt_key(key.as_ptr(), 128, &mut a), 0);
            assert_eq!(ossl_aria_set_encrypt_key(key.as_ptr(), 128, &mut b), 0);
            assert_eq!(ossl_aria_set_encrypt_key(other.as_ptr(), 128, &mut c), 0);
        }
        assert_eq!(a.rounds, 12);
        assert_eq!(schedule_words(&a), schedule_words(&b));
        assert_ne!(schedule_words(&a), schedule_words(&c));
        assert_ne!(schedule_words(&a)[0], [0x1111_1111; 4]);
    }
}
