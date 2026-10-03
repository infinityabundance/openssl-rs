//! Phase 12.8 — `crypto/bn/bn_srp.c`: the SRP (RFC 5054) group constants.
//!
//! Ten `const BIGNUM` objects: the seven moduli `ossl_bn_group_{1024,1536,2048,3072,4096,
//! 6144,8192}` and the three generators `ossl_bn_generator_{2,5,19}`. They are
//! `crypto/bn/bn_srp.c`'s whole content — the file defines nothing else — and they are
//! read by one consumer, [`crate::srp::srp_lib`]'s `knowngN[]` table. The module is
//! registered `pub(crate)` and every name here is **internal**: none carries `#[no_mangle]`
//! and no export is published, which is why the unit moves no ledger row.
//!
//! ## This is [`crate::bn::dh`]'s idiom, and the reason it is needed
//!
//! `bn_srp.c` declares each object as `const BIGNUM` initialised from a `static const
//! BN_ULONG` limb array in `.rodata`, so in C its address is a link-time constant. This
//! crate's [`BigNum`] owns a heap `Vec` and cannot be placed in static storage at all, so
//! each object is built **once**, lazily, and cached in an [`AtomicPtr`] — exactly the
//! static-`BIGNUM` idiom [`crate::bn::dh`] and [`crate::bn::primes`] already use. Two reads
//! of one accessor answer the same pointer, which is what a `static` object means in C.
//!
//! Entry for entry, the arrays below are `bn_srp.c`'s own limbs, in its own order: the
//! magnitude is little-endian limb order (the first initialiser is the least significant
//! limb) with each limb the `bn_pack4(a1,a2,a3,a4)` expansion `0xa1a2a3a4` on this profile's
//! 64-bit `BN_ULONG`. So the transcription is a spelling of the authority's numbers rather
//! than a re-derivation of them.
//!
//! ## `BN_FLG_STATIC_DATA`, which is not decoration here
//!
//! Every object is built by [`new_static_data`], which carries `BN_FLG_STATIC_DATA` **without**
//! `BN_FLG_MALLOCED` — the pair `bn_srp.c`'s initialisers give each object. `knowngN[]`
//! hands the numbers straight into `SRP_get_default_gN`/`SRP_check_known_gN_param`, and
//! `SRP_{Calc,Verify}_*` treat them as borrowed parameters; [`crate::bn::bignum`]'s `BN_free`
//! and `BN_clear_free` test the flag first and release nothing, so a caller that frees a
//! borrowed group constant is a no-op rather than a free of shared storage. Each object is
//! process-lifetime constant storage and is never released; the cache leaks exactly one
//! `BIGNUM` per constant, which is what `.rodata` costs in C.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::bn::bignum::{new_static_data, BigNum};
use crate::bn::limbs::Limb;

// `bn_srp.c:32-49`, `:59-84`, `:94-127`, `:137-186`, `:196-261`, `:271-368`, `:378-507`
// — the seven moduli, in the file's own definition order.
//
// `OSS_NELEM(bn_group_*_value)` is the array length in each case, which is the authority's
// `top` and `dmax`; the values are all full width, so no trailing limb is zero.

/// `static const BN_ULONG bn_group_1024_value[]` — `crypto/bn/bn_srp.c:32-49`.
pub(crate) const BN_GROUP_1024: [u64; 16] = [
    0x9FC61D2FC0EB06E3,
    0xFD5138FE8376435B,
    0x2FD4CBF4976EAA9A,
    0x68EDBC3C05726CC0,
    0xC529F566660E57EC,
    0x82559B297BCF1885,
    0xCE8EF4AD69B15D49,
    0x5DC7D7B46154D6B6,
    0x8E495C1D6089DAD1,
    0xE0D5D8E250B98BE4,
    0x383B4813D692C6E0,
    0xD674DF7496EA81D3,
    0x9EA2314C9C256576,
    0x6072618775FF3C0B,
    0x9C33F80AFA8FC5E8,
    0xEEAF0AB9ADB38DD6,
];

/// `static const BN_ULONG bn_group_1536_value[]` — `crypto/bn/bn_srp.c:59-84`.
pub(crate) const BN_GROUP_1536: [u64; 24] = [
    0xCF76E3FED135F9BB,
    0x15180F93499A234D,
    0x8CE7A28C2442C6F3,
    0x5A021FFF5E91479E,
    0x7F8A2FE9B8B5292E,
    0x837C264AE3A9BEB8,
    0xE442734AF7CCB7AE,
    0x65772E437D6C7F8C,
    0xDB2FD53D24B7C486,
    0x6EDF019539349627,
    0x158BFD3E2B9C8CF5,
    0x764E3F4B53DD9DA1,
    0x47548381DBC5B1FC,
    0x9B609E0BE3BAB63D,
    0x8134B1C8B9798914,
    0xDF028A7CEC67F0D0,
    0x80B655BB9A22E8DC,
    0x1558903BA0D0F843,
    0x51C6A94BE4607A29,
    0x5F4F5F556E27CBDE,
    0xBEEEA9614B19CC4D,
    0xDBA51DF499AC4C80,
    0xB1F12A8617A47BBB,
    0x9DEF3CAFB939277A,
];

/// `static const BN_ULONG bn_group_2048_value[]` — `crypto/bn/bn_srp.c:94-127`.
pub(crate) const BN_GROUP_2048: [u64; 32] = [
    0x0FA7111F9E4AFF73,
    0x9B65E372FCD68EF2,
    0x35DE236D525F5475,
    0x94B5C803D89F7AE4,
    0x71AE35F8E9DBFBB6,
    0x2A5698F3A8D0C382,
    0x9CCC041C7BC308D8,
    0xAF874E7303CE5329,
    0x6160279004E57AE6,
    0x032CFBDBF52FB378,
    0x5EA77A2775D2ECFA,
    0x544523B524B0D57D,
    0x5B9D32E688F87748,
    0xF1D2B9078717461A,
    0x76BD207A436C6481,
    0xCA97B43A23FB8016,
    0x1D281E446B14773B,
    0x7359D041D5C33EA7,
    0xA80D740ADBF4FF74,
    0x55F97993EC975EEA,
    0x2918A9962F0B93B8,
    0x661A05FBD5FAAAE8,
    0xCF6095179A163AB3,
    0xE8083969EDB767B0,
    0xCD7F48A9DA04FD50,
    0xD52312AB4B03310D,
    0x8193E0757767A13D,
    0xA37329CBB4A099ED,
    0xFC3192943DB56050,
    0xAF72B6651987EE07,
    0xF166DE5E1389582F,
    0xAC6BDB41324A9A9B,
];

/// `static const BN_ULONG bn_group_3072_value[]` — `crypto/bn/bn_srp.c:137-186`.
pub(crate) const BN_GROUP_3072: [u64; 48] = [
    0xFFFFFFFFFFFFFFFF,
    0x4B82D120A93AD2CA,
    0x43DB5BFCE0FD108E,
    0x08E24FA074E5AB31,
    0x770988C0BAD946E2,
    0xBBE117577A615D6C,
    0x521F2B18177B200C,
    0xD87602733EC86A64,
    0xF12FFA06D98A0864,
    0xCEE3D2261AD2EE6B,
    0x1E8C94E04A25619D,
    0xABF5AE8CDB0933D7,
    0xB3970F85A6E1E4C7,
    0x8AEA71575D060C7D,
    0xECFB850458DBEF0A,
    0xA85521ABDF1CBA64,
    0xAD33170D04507A33,
    0x15728E5A8AAAC42D,
    0x15D2261898FA0510,
    0x3995497CEA956AE5,
    0xDE2BCBF695581718,
    0xB5C55DF06F4C52C9,
    0x9B2783A2EC07A28F,
    0xE39E772C180E8603,
    0x32905E462E36CE3B,
    0xF1746C08CA18217C,
    0x670C354E4ABC9804,
    0x9ED529077096966D,
    0x1C62F356208552BB,
    0x83655D23DCA3AD96,
    0x69163FA8FD24CF5F,
    0x98DA48361C55D39A,
    0xC2007CB8A163BF05,
    0x49286651ECE45B3D,
    0xAE9F24117C4B1FE6,
    0xEE386BFB5A899FA5,
    0x0BFF5CB6F406B7ED,
    0xF44C42E9A637ED6B,
    0xE485B576625E7EC6,
    0x4FE1356D6D51C245,
    0x302B0A6DF25F1437,
    0xEF9519B3CD3A431B,
    0x514A08798E3404DD,
    0x020BBEA63B139B22,
    0x29024E088A67CC74,
    0xC4C6628B80DC1CD1,
    0xC90FDAA22168C234,
    0xFFFFFFFFFFFFFFFF,
];

/// `static const BN_ULONG bn_group_4096_value[]` — `crypto/bn/bn_srp.c:196-261`.
pub(crate) const BN_GROUP_4096: [u64; 64] = [
    0xFFFFFFFFFFFFFFFF,
    0x4DF435C934063199,
    0x86FFB7DC90A6C08F,
    0x93B4EA988D8FDDC1,
    0xD0069127D5B05AA9,
    0xB81BDD762170481C,
    0x1F612970CEE2D7AF,
    0x233BA186515BE7ED,
    0x99B2964FA090C3A2,
    0x287C59474E6BC05D,
    0x2E8EFC141FBECAA6,
    0xDBBBC2DB04DE8EF9,
    0x2583E9CA2AD44CE8,
    0x1A946834B6150BDA,
    0x99C327186AF4E23C,
    0x88719A10BDBA5B26,
    0x1A723C12A787E6D7,
    0x4B82D120A9210801,
    0x43DB5BFCE0FD108E,
    0x08E24FA074E5AB31,
    0x770988C0BAD946E2,
    0xBBE117577A615D6C,
    0x521F2B18177B200C,
    0xD87602733EC86A64,
    0xF12FFA06D98A0864,
    0xCEE3D2261AD2EE6B,
    0x1E8C94E04A25619D,
    0xABF5AE8CDB0933D7,
    0xB3970F85A6E1E4C7,
    0x8AEA71575D060C7D,
    0xECFB850458DBEF0A,
    0xA85521ABDF1CBA64,
    0xAD33170D04507A33,
    0x15728E5A8AAAC42D,
    0x15D2261898FA0510,
    0x3995497CEA956AE5,
    0xDE2BCBF695581718,
    0xB5C55DF06F4C52C9,
    0x9B2783A2EC07A28F,
    0xE39E772C180E8603,
    0x32905E462E36CE3B,
    0xF1746C08CA18217C,
    0x670C354E4ABC9804,
    0x9ED529077096966D,
    0x1C62F356208552BB,
    0x83655D23DCA3AD96,
    0x69163FA8FD24CF5F,
    0x98DA48361C55D39A,
    0xC2007CB8A163BF05,
    0x49286651ECE45B3D,
    0xAE9F24117C4B1FE6,
    0xEE386BFB5A899FA5,
    0x0BFF5CB6F406B7ED,
    0xF44C42E9A637ED6B,
    0xE485B576625E7EC6,
    0x4FE1356D6D51C245,
    0x302B0A6DF25F1437,
    0xEF9519B3CD3A431B,
    0x514A08798E3404DD,
    0x020BBEA63B139B22,
    0x29024E088A67CC74,
    0xC4C6628B80DC1CD1,
    0xC90FDAA22168C234,
    0xFFFFFFFFFFFFFFFF,
];

/// `static const BN_ULONG bn_group_6144_value[]` — `crypto/bn/bn_srp.c:271-368`.
pub(crate) const BN_GROUP_6144: [u64; 96] = [
    0xFFFFFFFFFFFFFFFF,
    0xE694F91E6DCC4024,
    0x12BF2D5B0B7474D6,
    0x043E8F663F4860EE,
    0x387FE8D76E3C0468,
    0xDA56C9EC2EF29632,
    0xEB19CCB1A313D55C,
    0xF550AA3D8A1FBFF0,
    0x06A1D58BB7C5DA76,
    0xA79715EEF29BE328,
    0x14CC5ED20F8037E0,
    0xCC8F6D7EBF48E1D8,
    0x4BD407B22B4154AA,
    0x0F1D45B7FF585AC5,
    0x23A97A7E36CC88BE,
    0x59E7C97FBEC7E8F3,
    0xB5A84031900B1C9E,
    0xD55E702F46980C82,
    0xF482D7CE6E74FEF6,
    0xF032EA15D1721D03,
    0x5983CA01C64B92EC,
    0x6FB8F401378CD2BF,
    0x332051512BD7AF42,
    0xDB7F1447E6CC254B,
    0x44CE6CBACED4BB1B,
    0xDA3EDBEBCF9B14ED,
    0x179727B0865A8918,
    0xB06A53ED9027D831,
    0xE5DB382F413001AE,
    0xF8FF9406AD9E530E,
    0xC9751E763DBA37BD,
    0xC1D4DCB2602646DE,
    0x36C3FAB4D27C7026,
    0x4DF435C934028492,
    0x86FFB7DC90A6C08F,
    0x93B4EA988D8FDDC1,
    0xD0069127D5B05AA9,
    0xB81BDD762170481C,
    0x1F612970CEE2D7AF,
    0x233BA186515BE7ED,
    0x99B2964FA090C3A2,
    0x287C59474E6BC05D,
    0x2E8EFC141FBECAA6,
    0xDBBBC2DB04DE8EF9,
    0x2583E9CA2AD44CE8,
    0x1A946834B6150BDA,
    0x99C327186AF4E23C,
    0x88719A10BDBA5B26,
    0x1A723C12A787E6D7,
    0x4B82D120A9210801,
    0x43DB5BFCE0FD108E,
    0x08E24FA074E5AB31,
    0x770988C0BAD946E2,
    0xBBE117577A615D6C,
    0x521F2B18177B200C,
    0xD87602733EC86A64,
    0xF12FFA06D98A0864,
    0xCEE3D2261AD2EE6B,
    0x1E8C94E04A25619D,
    0xABF5AE8CDB0933D7,
    0xB3970F85A6E1E4C7,
    0x8AEA71575D060C7D,
    0xECFB850458DBEF0A,
    0xA85521ABDF1CBA64,
    0xAD33170D04507A33,
    0x15728E5A8AAAC42D,
    0x15D2261898FA0510,
    0x3995497CEA956AE5,
    0xDE2BCBF695581718,
    0xB5C55DF06F4C52C9,
    0x9B2783A2EC07A28F,
    0xE39E772C180E8603,
    0x32905E462E36CE3B,
    0xF1746C08CA18217C,
    0x670C354E4ABC9804,
    0x9ED529077096966D,
    0x1C62F356208552BB,
    0x83655D23DCA3AD96,
    0x69163FA8FD24CF5F,
    0x98DA48361C55D39A,
    0xC2007CB8A163BF05,
    0x49286651ECE45B3D,
    0xAE9F24117C4B1FE6,
    0xEE386BFB5A899FA5,
    0x0BFF5CB6F406B7ED,
    0xF44C42E9A637ED6B,
    0xE485B576625E7EC6,
    0x4FE1356D6D51C245,
    0x302B0A6DF25F1437,
    0xEF9519B3CD3A431B,
    0x514A08798E3404DD,
    0x020BBEA63B139B22,
    0x29024E088A67CC74,
    0xC4C6628B80DC1CD1,
    0xC90FDAA22168C234,
    0xFFFFFFFFFFFFFFFF,
];

/// `static const BN_ULONG bn_group_8192_value[]` — `crypto/bn/bn_srp.c:378-507`.
pub(crate) const BN_GROUP_8192: [u64; 128] = [
    0xFFFFFFFFFFFFFFFF,
    0x60C980DD98EDD3DF,
    0xC81F56E880B96E71,
    0x9E3050E2765694DF,
    0x9558E4475677E9AA,
    0xC9190DA6FC026E47,
    0x889A002ED5EE382B,
    0x4009438B481C6CD7,
    0x359046F4EB879F92,
    0xFAF36BC31ECFA268,
    0xB1D510BD7EE74D73,
    0xF9AB48195DED7EA1,
    0x64F31CC50846851D,
    0x4597E899A0255DC1,
    0xDF310EE074AB6A36,
    0x6D2A13F83F44F82D,
    0x062B3CF5B3A278A6,
    0x79683303ED5BDD3A,
    0xFA9D4B7FA2C087E8,
    0x4BCBC8862F8385DD,
    0x3473FC646CEA306B,
    0x13EB57A81A23F0C7,
    0x22222E04A4037C07,
    0xE3FDB8BEFC848AD9,
    0x238F16CBE39D652D,
    0x3423B4742BF1C978,
    0x3AAB639C5AE4F568,
    0x2576F6936BA42466,
    0x741FA7BF8AFC47ED,
    0x3BC832B68D9DD300,
    0xD8BEC4D073B931BA,
    0x38777CB6A932DF8C,
    0x74A3926F12FEE5E4,
    0xE694F91E6DBE1159,
    0x12BF2D5B0B7474D6,
    0x043E8F663F4860EE,
    0x387FE8D76E3C0468,
    0xDA56C9EC2EF29632,
    0xEB19CCB1A313D55C,
    0xF550AA3D8A1FBFF0,
    0x06A1D58BB7C5DA76,
    0xA79715EEF29BE328,
    0x14CC5ED20F8037E0,
    0xCC8F6D7EBF48E1D8,
    0x4BD407B22B4154AA,
    0x0F1D45B7FF585AC5,
    0x23A97A7E36CC88BE,
    0x59E7C97FBEC7E8F3,
    0xB5A84031900B1C9E,
    0xD55E702F46980C82,
    0xF482D7CE6E74FEF6,
    0xF032EA15D1721D03,
    0x5983CA01C64B92EC,
    0x6FB8F401378CD2BF,
    0x332051512BD7AF42,
    0xDB7F1447E6CC254B,
    0x44CE6CBACED4BB1B,
    0xDA3EDBEBCF9B14ED,
    0x179727B0865A8918,
    0xB06A53ED9027D831,
    0xE5DB382F413001AE,
    0xF8FF9406AD9E530E,
    0xC9751E763DBA37BD,
    0xC1D4DCB2602646DE,
    0x36C3FAB4D27C7026,
    0x4DF435C934028492,
    0x86FFB7DC90A6C08F,
    0x93B4EA988D8FDDC1,
    0xD0069127D5B05AA9,
    0xB81BDD762170481C,
    0x1F612970CEE2D7AF,
    0x233BA186515BE7ED,
    0x99B2964FA090C3A2,
    0x287C59474E6BC05D,
    0x2E8EFC141FBECAA6,
    0xDBBBC2DB04DE8EF9,
    0x2583E9CA2AD44CE8,
    0x1A946834B6150BDA,
    0x99C327186AF4E23C,
    0x88719A10BDBA5B26,
    0x1A723C12A787E6D7,
    0x4B82D120A9210801,
    0x43DB5BFCE0FD108E,
    0x08E24FA074E5AB31,
    0x770988C0BAD946E2,
    0xBBE117577A615D6C,
    0x521F2B18177B200C,
    0xD87602733EC86A64,
    0xF12FFA06D98A0864,
    0xCEE3D2261AD2EE6B,
    0x1E8C94E04A25619D,
    0xABF5AE8CDB0933D7,
    0xB3970F85A6E1E4C7,
    0x8AEA71575D060C7D,
    0xECFB850458DBEF0A,
    0xA85521ABDF1CBA64,
    0xAD33170D04507A33,
    0x15728E5A8AAAC42D,
    0x15D2261898FA0510,
    0x3995497CEA956AE5,
    0xDE2BCBF695581718,
    0xB5C55DF06F4C52C9,
    0x9B2783A2EC07A28F,
    0xE39E772C180E8603,
    0x32905E462E36CE3B,
    0xF1746C08CA18217C,
    0x670C354E4ABC9804,
    0x9ED529077096966D,
    0x1C62F356208552BB,
    0x83655D23DCA3AD96,
    0x69163FA8FD24CF5F,
    0x98DA48361C55D39A,
    0xC2007CB8A163BF05,
    0x49286651ECE45B3D,
    0xAE9F24117C4B1FE6,
    0xEE386BFB5A899FA5,
    0x0BFF5CB6F406B7ED,
    0xF44C42E9A637ED6B,
    0xE485B576625E7EC6,
    0x4FE1356D6D51C245,
    0x302B0A6DF25F1437,
    0xEF9519B3CD3A431B,
    0x514A08798E3404DD,
    0x020BBEA63B139B22,
    0x29024E088A67CC74,
    0xC4C6628B80DC1CD1,
    0xC90FDAA22168C234,
    0xFFFFFFFFFFFFFFFF,
];

// `bn_srp.c:517-543` — the three one-limb generators.

/// `static const BN_ULONG bn_generator_19_value[]` — `crypto/bn/bn_srp.c:517`.
pub(crate) const BN_GENERATOR_19: [u64; 1] = [19];
/// `static const BN_ULONG bn_generator_5_value[]` — `crypto/bn/bn_srp.c:526`.
pub(crate) const BN_GENERATOR_5: [u64; 1] = [5];
/// `static const BN_ULONG bn_generator_2_value[]` — `crypto/bn/bn_srp.c:535`.
pub(crate) const BN_GENERATOR_2: [u64; 1] = [2];

/// The shared object behind one `ossl_bn_*` constant, built once and cached in `cache`.
///
/// This is [`crate::bn::bignum::static_data_bignum`]'s idiom applied to a limb array rather
/// than a big-endian byte string: `bn_srp.c`'s own arrays are limbs, so the transcription
/// spells them as limbs and skips the byte-order round trip. Two calls answer the same
/// pointer; a caller that leaks the pointer (it must not free it) leaks exactly one.
///
/// # Safety
///
/// `cache` must be a unique, process-lifetime cache slot for one constant, and `limbs` must
/// be the whole magnitude in little-endian limb order.
unsafe fn cached(cache: &AtomicPtr<BigNum>, limbs: &[Limb]) -> *const BigNum {
    let existing = cache.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }
    let fresh = new_static_data(limbs.to_vec());
    match cache.compare_exchange(
        core::ptr::null_mut(),
        fresh,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => fresh,
        Err(winner) => {
            // SAFETY: `fresh` is the object this call built and has not published, and
            // nothing else has seen it, so releasing it here leaves the cached one
            // alone. `new_static_data` produced it as a live `Box`, so this is the whole
            // release.
            drop(unsafe { Box::from_raw(fresh) });
            winner
        }
    }
}

/// `const BIGNUM ossl_bn_group_1024` — `crypto/bn/bn_srp.c:51-57`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_group_1024() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: `CACHE` is this symbol's own process-lifetime cache slot and the constant is
    // the whole magnitude in little-endian limb order.
    unsafe { cached(&CACHE, &BN_GROUP_1024) }
}

/// `const BIGNUM ossl_bn_group_1536` — `crypto/bn/bn_srp.c:86-92`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_group_1536() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GROUP_1536) }
}

/// `const BIGNUM ossl_bn_group_2048` — `crypto/bn/bn_srp.c:129-135`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_group_2048() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GROUP_2048) }
}

/// `const BIGNUM ossl_bn_group_3072` — `crypto/bn/bn_srp.c:188-194`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_group_3072() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GROUP_3072) }
}

/// `const BIGNUM ossl_bn_group_4096` — `crypto/bn/bn_srp.c:263-269`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_group_4096() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GROUP_4096) }
}

/// `const BIGNUM ossl_bn_group_6144` — `crypto/bn/bn_srp.c:370-376`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_group_6144() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GROUP_6144) }
}

/// `const BIGNUM ossl_bn_group_8192` — `crypto/bn/bn_srp.c:509-515`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_group_8192() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GROUP_8192) }
}

/// `const BIGNUM ossl_bn_generator_19` — `crypto/bn/bn_srp.c:519-525`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_generator_19() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GENERATOR_19) }
}

/// `const BIGNUM ossl_bn_generator_5` — `crypto/bn/bn_srp.c:528-534`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_generator_5() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GENERATOR_5) }
}

/// `const BIGNUM ossl_bn_generator_2` — `crypto/bn/bn_srp.c:537-543`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bn_generator_2() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    // SAFETY: as `ossl_bn_group_1024`.
    unsafe { cached(&CACHE, &BN_GENERATOR_2) }
}
