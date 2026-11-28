//! The one place the process environment decides which CPU code path runs.
//!
//! `OPENSSL_ia32cap` is a documented OpenSSL interface: a consumer sets it before the
//! library initialises to disable processor features, and every backend must honour it.
//! Before PFP-67 this crate modelled only three ad-hoc fragments of it (`aes.rs`,
//! `digest/sha2.rs`, `modes/gcm.rs`), each parsing the variable itself, each supporting
//! only the `~` clear form, and two of them testing the wrong bit of the first logical
//! vector. Several more dispatchers (`provider/cipher.rs`, `ec/p256.rs`,
//! `ec/curve25519.rs`) read `CPUID` directly and ignored the variable entirely. This
//! module replaces all of them: [`has_aes`], [`has_pclmul`], [`has_sha`], [`has_avx`],
//! [`has_avx2`], [`has_vaes`], [`has_vpclmul`], [`has_bmi2`] and [`has_adx`] are the
//! only capability predicates the crate consults.
//!
//! ## The grammar
//!
//! The authority (`crypto/cpuid.c:94-171`, `OPENSSL_cpuid_setup`) treats the value as a
//! colon-separated list of five 64-bit *logical vectors* (`doc/man3/OPENSSL_ia32cap.pod`):
//!
//! * LV0 — `CPUID.(EAX=1).EDX` in bits 0..31 and `.ECX` in bits 32..63;
//! * LV1 — `CPUID.(EAX=7,ECX=0).EBX` in bits 0..31 and `.ECX` in bits 32..63;
//! * LV2..LV4 — the remaining pairs (`crypto/cpuid.c:132-155`).
//!
//! A field beginning with `~` is a *clear mask*: those bits are removed from the CPU's
//! own value. Any other field is a *value-set*: it replaces the whole 64-bit vector.
//! An empty field (`::`) leaves that vector unchanged. When the value has no colon, or
//! fewer fields than vectors, every remaining vector is **zeroed** — upstream's
//! compatibility rule, so `OPENSSL_ia32cap=~0x0` disables all of LV1 and beyond.
//! Numbers are parsed by `ossl_strtouint64` (`crypto/cpuid.c:61-76`): `0x`/`0X` is
//! hexadecimal, a leading `0` is octal, anything else is decimal, and parsing stops at
//! the first character that is not a digit in that base.
//!
//! Clearing FXSR (LV0 bit 24) in the clear form additionally clears PCLMULQDQ (LV0
//! bit 33), AMD XOP (LV0 bit 43), AES-NI (LV0 bit 57) and AVX (LV0 bit 60), which is
//! `crypto/cpuid.c:114-124`. The value-set form deliberately does **not** do this,
//! matching the authority.
//!
//! Malformed input is total: the authority has no error path, so `~zz` is a zero mask
//! (clears nothing), `zz` is a zero value (disables that vector), and `~0x1fZZ` clears
//! `0x1f`. Nothing panics.
//!
//! ## Reading and caching
//!
//! The environment is read lazily, once, and cached in a `OnceLock`; [`init`] forces
//! that read from `OPENSSL_init_crypto`'s base step, which is where the authority's
//! `.init` constructor/`OPENSSL_cpuid_setup` would. A consumer that sets the variable
//! before initialising the library is therefore honoured.
//!
//! ## Deliberate divergence
//!
//! The authority's value-set form can also *enable* a bit the CPU does not report
//! (which then executes an unsupported instruction and faults). This module intersects
//! every query with Rust's `is_x86_feature_detected!`, so the override may only
//! restrict, never fabricate, a capability. That is a safety improvement, not a
//! compatibility mechanism: no consumer can rely on `OPENSSL_ia32cap` to make a CPU
//! support AES-NI, and reproducing the fault would be undefined behaviour.

// The parser and predicates are x86-only; on other targets every query is a constant
// `false` and the parser has no caller, so the dead-code lint would otherwise fire in a
// cross-target build.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

/// The number of logical capability vectors the authority models.
const LV_COUNT: usize = 5;

/// What the environment decided for one logical vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    /// No override: the CPU's own capability decides.
    Cpu,
    /// `~mask`: the named bits are cleared.
    Clear(u64),
    /// A literal: only the named bits survive.
    Set(u64),
    /// A missing trailing field: the authority zeroes the whole vector.
    Zero,
}

impl Decision {
    /// Whether `bit` of this logical vector is permitted.
    fn permits(self, bit: u32) -> bool {
        match self {
            Decision::Cpu => true,
            Decision::Clear(mask) => mask & (1u64 << bit) == 0,
            Decision::Set(value) => value & (1u64 << bit) != 0,
            Decision::Zero => false,
        }
    }
}

/// `ossl_strtouint64` — `crypto/cpuid.c:61-76`.
///
/// The prefix decides the base: `0x`/`0X` hexadecimal, a leading `0` octal, otherwise
/// decimal. Accumulation wraps at 64 bits, exactly as the C unsigned multiply does, and
/// stops at the first non-digit of that base.
fn parse_u64(bytes: &[u8]) -> u64 {
    let mut i = 0usize;
    let mut base = 10u64;
    if bytes.first() == Some(&b'0') {
        base = 8;
        i = 1;
        if bytes.get(i).is_some_and(|c| c.eq_ignore_ascii_case(&b'x')) {
            base = 16;
            i += 1;
        }
    }
    let mut value = 0u64;
    while let Some(&c) = bytes.get(i) {
        let digit = match c {
            b'0'..=b'9' => u64::from(c - b'0'),
            b'a'..=b'f' => u64::from(c - b'a') + 10,
            b'A'..=b'F' => u64::from(c - b'A') + 10,
            _ => break,
        };
        if digit >= base {
            break;
        }
        value = value.wrapping_mul(base).wrapping_add(digit);
        i += 1;
    }
    value
}

/// Parse `OPENSSL_ia32cap` into one [`Decision`] per logical vector.
///
/// This is a transcription of `OPENSSL_cpuid_setup` (`crypto/cpuid.c:106-155`), not a
/// simplification of the man page: the value-set form, the empty-field skip, the
/// trailing-zero rule and the FXSR knock-on are all observable to a consumer.
fn parse_override(spec: Option<&str>) -> [Decision; LV_COUNT] {
    let mut out = [Decision::Cpu; LV_COUNT];
    let Some(spec) = spec else {
        return out;
    };
    let bytes = spec.as_bytes();

    // LV0: `~` masks the CPU value, `:` defers to the CPU, anything else replaces it.
    if bytes.first() == Some(&b'~') {
        let mask = parse_u64(&bytes[1..]);
        let mut cleared = mask;
        if mask & (1 << 24) != 0 {
            // FXSR disabled: PCLMULQDQ (1), AMD XOP (11), AES-NI (25) and AVX (28)
            // live in the ECX half, i.e. 32 bits higher in the logical vector.
            cleared |= (1u64 << 1 | 1 << 11 | 1 << 25 | 1 << 28) << 32;
        }
        out[0] = Decision::Clear(cleared);
    } else if bytes.first() == Some(&b':') {
        out[0] = Decision::Cpu;
    } else {
        out[0] = Decision::Set(parse_u64(bytes));
    }

    // `ossl_strchr(env, ':')`, then the extended-vector walk. A missing colon zeroes
    // every remaining vector rather than leaving it at the CPU's value.
    let mut pos = match bytes.iter().position(|&c| c == b':') {
        Some(at) => at + 1,
        None => {
            out[1..].fill(Decision::Zero);
            return out;
        }
    };

    for lv in 1..LV_COUNT {
        if pos >= bytes.len() {
            out[lv..].fill(Decision::Zero);
            return out;
        }
        if bytes[pos] == b':' {
            // Empty field: leave this vector unchanged and consume the delimiter.
            pos += 1;
            continue;
        }
        let end = bytes[pos..]
            .iter()
            .position(|&c| c == b':')
            .map(|at| pos + at);
        let field = &bytes[pos..end.unwrap_or(bytes.len())];
        out[lv] = if field.first() == Some(&b'~') {
            Decision::Clear(parse_u64(&field[1..]))
        } else {
            Decision::Set(parse_u64(field))
        };
        match end {
            Some(at) => pos = at + 1,
            None => {
                out[lv + 1..].fill(Decision::Zero);
                return out;
            }
        }
    }
    out
}

/// The parsed override, read once from the process environment.
#[cfg(target_arch = "x86_64")]
fn decisions() -> &'static [Decision; LV_COUNT] {
    use std::sync::OnceLock;

    static DECISIONS: OnceLock<[Decision; LV_COUNT]> = OnceLock::new();
    DECISIONS.get_or_init(|| {
        // Non-UTF-8 is treated as absent; upstream would parse its ASCII prefix. That is
        // a recorded, unreachable-in-practice divergence (see the module docs and the
        // PFP-67 receipt).
        let spec = std::env::var("OPENSSL_ia32cap").ok();
        parse_override(spec.as_deref())
    })
}

/// Force the environment read at the authority's initialisation point.
///
/// `OPENSSL_cpuid_setup` runs from `ossl_init_base` (`crypto/init.c:70`); calling this
/// from the same step means a consumer that sets `OPENSSL_ia32cap` before
/// `OPENSSL_init_crypto` is honoured even if some earlier safe call touched a
/// dispatcher. Idempotent because [`decisions`] is a `OnceLock`.
pub(crate) fn init() {
    #[cfg(target_arch = "x86_64")]
    let _ = decisions();
}

/// Whether the environment permits `bit` of logical vector `lv`.
#[cfg(target_arch = "x86_64")]
fn permitted(lv: usize, bit: u32) -> bool {
    decisions()[lv].permits(bit)
}

/// `OPENSSL_ia32cap`'s AES-NI bit: LV0 bit 57 (`CPUID.(EAX=1).ECX` bit 25).
pub(crate) fn has_aes() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("aes") && permitted(0, 57)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `OPENSSL_ia32cap`'s PCLMULQDQ bit: LV0 bit 33 (`CPUID.(EAX=1).ECX` bit 1).
pub(crate) fn has_pclmul() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("pclmulqdq") && permitted(0, 33)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `OPENSSL_ia32cap`'s SHA bit: LV1 bit 29 (`CPUID.(EAX=7,ECX=0).EBX` bit 29).
///
/// The SHA-NI compression function also executes SSE4.1 `blend`/SSSE3 `alignr`, so the
/// query is only true when both extensions are present — the caller's
/// `#[target_feature(enable = "sha,sse4.1")]` precondition.
pub(crate) fn has_sha() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("sha")
            && std::is_x86_feature_detected!("sse4.1")
            && permitted(1, 29)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `OPENSSL_ia32cap`'s AVX bit: LV0 bit 60 (`CPUID.(EAX=1).ECX` bit 28).
///
/// Exposed because the authority's GCM and AES arms select AVX paths; this crate's
/// dispatchers do not yet have an AVX arm, so nothing consumes it today.
#[allow(dead_code)]
pub(crate) fn has_avx() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx") && permitted(0, 60)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `OPENSSL_ia32cap`'s AVX2 bit: LV1 bit 5 (`CPUID.(EAX=7,ECX=0).EBX` bit 5).
pub(crate) fn has_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx2") && permitted(1, 5)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `OPENSSL_ia32cap`'s VAES bit: LV1 bit 41 (`CPUID.(EAX=7,ECX=0).ECX` bit 9).
///
/// Exposed for the same reason as [`has_avx`]: the authority has VAES paths, this crate
/// does not, so no dispatcher consumes it yet.
#[allow(dead_code)]
pub(crate) fn has_vaes() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("vaes") && permitted(1, 41)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `OPENSSL_ia32cap`'s VPCLMULQDQ bit: LV1 bit 42 (`CPUID.(EAX=7,ECX=0).ECX` bit 10).
///
/// Exposed for the same reason as [`has_avx`].
#[allow(dead_code)]
pub(crate) fn has_vpclmul() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("vpclmulqdq") && permitted(1, 42)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `OPENSSL_ia32cap`'s BMI2 bit: LV1 bit 8 (`CPUID.(EAX=7,ECX=0).EBX` bit 8).
pub(crate) fn has_bmi2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("bmi2") && permitted(1, 8)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `OPENSSL_ia32cap`'s ADX bit: LV1 bit 19 (`CPUID.(EAX=7,ECX=0).EBX` bit 19).
pub(crate) fn has_adx() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("adx") && permitted(1, 19)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Test-only observation of the arm each dispatcher actually executed.
///
/// The counters are incremented *inside* the accelerated and portable kernels, so a test
/// observes execution rather than re-reading the predicate that chose it. They are
/// compiled only under `cfg(test)`, so no release artefact carries them.
#[cfg(test)]
pub(crate) mod path_probe {
    use core::sync::atomic::{AtomicU64, Ordering};

    pub(crate) static AES_NI: AtomicU64 = AtomicU64::new(0);
    pub(crate) static AES_PORTABLE: AtomicU64 = AtomicU64::new(0);
    pub(crate) static PCLMUL: AtomicU64 = AtomicU64::new(0);
    pub(crate) static PCLMUL_PORTABLE: AtomicU64 = AtomicU64::new(0);
    pub(crate) static SHA_NI: AtomicU64 = AtomicU64::new(0);
    pub(crate) static SHA_PORTABLE: AtomicU64 = AtomicU64::new(0);

    /// A point-in-time view of every counter.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Snapshot {
        pub aes_ni: u64,
        pub aes_portable: u64,
        pub pclmul: u64,
        pub pclmul_portable: u64,
        pub sha_ni: u64,
        pub sha_portable: u64,
    }

    pub(crate) fn reset() {
        for counter in [
            &AES_NI,
            &AES_PORTABLE,
            &PCLMUL,
            &PCLMUL_PORTABLE,
            &SHA_NI,
            &SHA_PORTABLE,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot() -> Snapshot {
        Snapshot {
            aes_ni: AES_NI.load(Ordering::Relaxed),
            aes_portable: AES_PORTABLE.load(Ordering::Relaxed),
            pclmul: PCLMUL.load(Ordering::Relaxed),
            pclmul_portable: PCLMUL_PORTABLE.load(Ordering::Relaxed),
            sha_ni: SHA_NI.load(Ordering::Relaxed),
            sha_portable: SHA_PORTABLE.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn aes_ni() {
        AES_NI.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn aes_portable() {
        AES_PORTABLE.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn pclmul() {
        PCLMUL.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn pclmul_portable() {
        PCLMUL_PORTABLE.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn sha_ni() {
        SHA_NI.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn sha_portable() {
        SHA_PORTABLE.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full grammar, including the parts the old ad-hoc helpers got wrong: the first
    /// vector's feature bits live in its *high* half, value-set replaces rather than
    /// masks, empty fields skip, missing fields zero, and octal/decimal are accepted.
    #[test]
    fn the_authority_grammar_is_transcribed_exactly() {
        // AES-NI (LV0 bit 57) and PCLMULQDQ (LV0 bit 33) are in the ECX half.
        let aes_clear = parse_override(Some("~0x200000000000000:::::"));
        assert_eq!(aes_clear[0], Decision::Clear(1 << 57));
        assert!(!aes_clear[0].permits(57));
        assert!(aes_clear[0].permits(33));
        assert_eq!(aes_clear[1..], [Decision::Cpu; 4]);

        let pclmul_clear = parse_override(Some("~0x200000000::::"));
        assert_eq!(pclmul_clear[0], Decision::Clear(1 << 33));
        assert!(pclmul_clear[0].permits(57));
        assert!(!pclmul_clear[0].permits(33));

        // `~` with no further field zeroes LV1..LV4.
        let no_fields = parse_override(Some("~0x200000000000000"));
        assert_eq!(no_fields[0], Decision::Clear(1 << 57));
        assert_eq!(no_fields[1..], [Decision::Zero; 4]);

        // `~0x0` is a zero clear mask, but the missing fields still zero LV1..LV4.
        assert_eq!(parse_override(Some("~0x0"))[0], Decision::Clear(0));
        assert_eq!(parse_override(Some("~0x0"))[1..], [Decision::Zero; 4]);

        // The man page's examples.
        assert_eq!(parse_override(Some(":0"))[0], Decision::Cpu);
        assert_eq!(parse_override(Some(":0"))[1], Decision::Set(0));
        assert_eq!(parse_override(Some(":0"))[2..], [Decision::Zero; 3]);
        assert_eq!(parse_override(Some("::0"))[1], Decision::Cpu);
        assert_eq!(parse_override(Some("::0"))[2], Decision::Set(0));
        assert_eq!(parse_override(Some("::0"))[3..], [Decision::Zero; 2]);
        let only_lv1 = parse_override(Some(":0::::"));
        assert_eq!(only_lv1[0], Decision::Cpu);
        assert_eq!(only_lv1[1], Decision::Set(0));
        assert_eq!(only_lv1[2..], [Decision::Cpu; 3]);

        // A value-set replaces the vector; it is not ANDed with the CPU's value.
        let reference = parse_override(Some("0x0200000100000000"));
        assert_eq!(reference[0], Decision::Set(0x0200_0001_0000_0000));
        assert_eq!(reference[1..], [Decision::Zero; 4]);

        // Empty value: LV0 becomes zero and the rest are zeroed.
        assert_eq!(
            parse_override(Some("")),
            [
                Decision::Set(0),
                Decision::Zero,
                Decision::Zero,
                Decision::Zero,
                Decision::Zero
            ]
        );

        // Decimal and octal, per `ossl_strtouint64`.
        assert_eq!(parse_override(Some("~8192"))[0], Decision::Clear(8192));
        assert_eq!(parse_override(Some("~0755"))[0], Decision::Clear(0o755));
        assert_eq!(parse_override(Some("~0X1F"))[0], Decision::Clear(0x1f));

        // Malformed input is total and follows prefix parsing: no panic, no silent enable.
        assert_eq!(parse_override(Some("~zz"))[0], Decision::Clear(0));
        assert!(parse_override(Some("~zz"))[0].permits(57));
        assert_eq!(parse_override(Some("zz"))[0], Decision::Set(0));
        assert!(!parse_override(Some("zz"))[0].permits(57));
        assert_eq!(parse_override(Some("~0x1fZZ"))[0], Decision::Clear(0x1f));
        assert_eq!(parse_override(Some(":~not-hex"))[1], Decision::Clear(0));
        // Binary-looking input is octal and stops at `b`; `09` is octal and stops at `9`.
        assert_eq!(parse_override(Some("0b101"))[0], Decision::Set(0));
        assert_eq!(parse_override(Some("09"))[0], Decision::Set(0));
        // Arbitrary junk never panics.
        for junk in [
            "~::::::::~~~~~xxxx",
            "::::",
            ":",
            "~",
            "0x",
            "0x_",
            "\u{3400}",
        ] {
            let _ = parse_override(Some(junk));
        }
    }

    /// Clearing FXSR masks the XMM-only extensions; the value-set form does not.
    #[test]
    fn fxsr_clear_masks_the_xmm_only_extensions() {
        let fxsr = parse_override(Some("~0x1000000:::::"));
        for bit in [24, 33, 43, 57, 60] {
            assert!(!fxsr[0].permits(bit), "FXSR clear must clear bit {bit}");
        }
        assert!(fxsr[0].permits(32));

        let value_set = parse_override(Some("0x200000000000000:::::"));
        assert_eq!(value_set[0], Decision::Set(1 << 57));
        assert!(value_set[0].permits(57));
        assert!(!value_set[0].permits(24));
    }

    /// The extended vectors map to their CPUID halves: AVX2/BMI2/ADX/SHA in EBX,
    /// VAES/VPCLMULQDQ in ECX.
    #[test]
    fn extended_vector_bits_are_the_cpuid_bits() {
        let mask = (1u64 << 8) | (1u64 << 19) | (1u64 << 29) | (1u64 << 41) | (1u64 << 42);
        let spec = format!("0x0:~{mask:#x}");
        let lv1 = parse_override(Some(&spec));
        for bit in [8, 19, 29, 41, 42] {
            assert!(!lv1[1].permits(bit), "bit {bit}");
        }
        assert!(lv1[1].permits(5));
        let clear_all_lv1 = parse_override(Some(":~0xffffffffffffffff"));
        for bit in [0, 5, 8, 19, 29, 41, 42, 63] {
            assert!(!clear_all_lv1[1].permits(bit), "bit {bit}");
        }
    }

    // The cross-caller end-to-end matrix lives in `pfp67_override_matrix` below. Each
    // child process fixes `OPENSSL_ia32cap` before the library reads it, performs the
    // real operation, and reports the kernel counters.
    mod child {
        use super::super::path_probe::{self, Snapshot};
        use crate::aes::{AES_cbc_encrypt, AES_encrypt, AES_set_encrypt_key, AesKey};
        use crate::digest::sha2::{SHA256_Final, SHA256_Init, SHA256_Update, Sha256Ctx};
        use crate::modes::gcm::{
            CRYPTO_gcm128_encrypt, CRYPTO_gcm128_finish, CRYPTO_gcm128_new, CRYPTO_gcm128_setiv,
            CRYPTO_gcm128_tag,
        };
        use crate::modes::CRYPTO_ctr128_encrypt;
        use core::ffi::{c_uint, c_void};

        const KEY: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        const IV: [u8; 16] = [
            0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x01, 0x00,
        ];
        const PLAINTEXT: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb,
            0xdc, 0xed, 0xfe, 0x0f,
        ];

        fn schedule() -> AesKey {
            let mut k = AesKey {
                rd_key: [0; 60],
                rounds: 0,
            };
            // SAFETY: live locals with the contracted extents.
            unsafe {
                assert_eq!(AES_set_encrypt_key(KEY.as_ptr(), 128, &mut k), 0);
            }
            k
        }

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        fn report(name: &str, out: &[u8], s: Snapshot) {
            println!(
                "caller={name} aes_ni={} aes_portable={} pclmul={} pclmul_portable={} sha_ni={} sha_portable={} out={}",
                s.aes_ni, s.aes_portable, s.pclmul, s.pclmul_portable, s.sha_ni, s.sha_portable, hex(out)
            );
        }

        unsafe extern "C" fn aes_block(input: *const u8, out: *mut u8, key: *const c_void) {
            // SAFETY: forwards the GCM context's contracted block call.
            unsafe { AES_encrypt(input, out, key.cast::<AesKey>()) }
        }

        pub(super) fn run() {
            println!(
                "cpu_aes={} cpu_pclmul={} cpu_sha={} cpu_avx2={} cpu_vaes={} cpu_vpclmul={}",
                std::is_x86_feature_detected!("aes"),
                std::is_x86_feature_detected!("pclmulqdq"),
                std::is_x86_feature_detected!("sha") && std::is_x86_feature_detected!("sse4.1"),
                std::is_x86_feature_detected!("avx2"),
                std::is_x86_feature_detected!("vaes"),
                std::is_x86_feature_detected!("vpclmulqdq"),
            );
            println!(
                "caps aes={} pclmul={} sha={} avx={} avx2={} vaes={} vpclmul={} bmi2={} adx={}",
                super::super::has_aes(),
                super::super::has_pclmul(),
                super::super::has_sha(),
                super::super::has_avx(),
                super::super::has_avx2(),
                super::super::has_vaes(),
                super::super::has_vpclmul(),
                super::super::has_bmi2(),
                super::super::has_adx(),
            );
            let k = schedule();

            path_probe::reset();
            let mut one = [0u8; 16];
            // SAFETY: live locals.
            unsafe { AES_encrypt(PLAINTEXT.as_ptr(), one.as_mut_ptr(), &k) };
            report("AES_encrypt", &one, path_probe::snapshot());

            path_probe::reset();
            let mut cbc = [0u8; 32];
            let mut cbc_iv = IV;
            // SAFETY: live locals and a live schedule.
            unsafe {
                AES_cbc_encrypt(
                    PLAINTEXT.as_ptr(),
                    cbc.as_mut_ptr(),
                    PLAINTEXT.len(),
                    &k,
                    cbc_iv.as_mut_ptr(),
                    1,
                )
            };
            report("AES_cbc_encrypt", &cbc, path_probe::snapshot());

            path_probe::reset();
            let mut ctr = [0u8; 32];
            let mut ctr_iv = IV;
            let mut num: c_uint = 0;
            let mut ecount = [0u8; 16];
            // SAFETY: live locals and a live schedule.
            unsafe {
                CRYPTO_ctr128_encrypt(
                    PLAINTEXT.as_ptr(),
                    ctr.as_mut_ptr(),
                    PLAINTEXT.len(),
                    (&k as *const AesKey).cast(),
                    ctr_iv.as_mut_ptr(),
                    ecount.as_mut_ptr(),
                    &mut num,
                    aes_block,
                )
            };
            report("CRYPTO_ctr128_encrypt", &ctr, path_probe::snapshot());

            path_probe::reset();
            let mut gcm = [0u8; 32];
            let mut tag = [0u8; 16];
            // SAFETY: live locals, a live schedule, and the context is released below.
            unsafe {
                let ctx = CRYPTO_gcm128_new((&k as *const AesKey).cast_mut().cast(), aes_block);
                assert!(!ctx.is_null());
                CRYPTO_gcm128_setiv(ctx, IV.as_ptr(), IV.len());
                CRYPTO_gcm128_encrypt(ctx, PLAINTEXT.as_ptr(), gcm.as_mut_ptr(), PLAINTEXT.len());
                // A NULL tag makes the authority answer -1; `CRYPTO_gcm128_tag` below is the
                // compute path, and its return is likewise irrelevant.
                let _ = CRYPTO_gcm128_finish(ctx, core::ptr::null(), 0);
                CRYPTO_gcm128_tag(ctx, tag.as_mut_ptr(), tag.len());
                crate::modes::gcm::CRYPTO_gcm128_release(ctx);
            }
            let mut gcm_out = [0u8; 48];
            gcm_out[..32].copy_from_slice(&gcm);
            gcm_out[32..].copy_from_slice(&tag);
            report("CRYPTO_gcm128_encrypt", &gcm_out, path_probe::snapshot());

            path_probe::reset();
            let mut md = [0u8; 32];
            // SAFETY: live locals.
            unsafe {
                let mut ctx = Sha256Ctx {
                    h: [0; 8],
                    nl: 0,
                    nh: 0,
                    data: [0; 16],
                    num: 0,
                    md_len: 0,
                };
                assert_eq!(SHA256_Init(&mut ctx), 1);
                assert_eq!(
                    SHA256_Update(&mut ctx, PLAINTEXT.as_ptr().cast(), PLAINTEXT.len()),
                    1
                );
                assert_eq!(SHA256_Final(md.as_mut_ptr(), &mut ctx), 1);
            }
            report("SHA256", &md, path_probe::snapshot());

            // The stitched CBC-HMAC constructors are the authority's own observable for
            // `AESNI_CAPABLE`: NULL when the bit is clear. They consume the same predicate.
            println!(
                "sel cbc_hmac_sha1_128_null={} cbc_hmac_sha256_128_null={}",
                usize::from(crate::evp::e_aes_cbc_hmac_sha1::EVP_aes_128_cbc_hmac_sha1().is_null()),
                usize::from(
                    crate::evp::e_aes_cbc_hmac_sha256::EVP_aes_128_cbc_hmac_sha256().is_null()
                ),
            );
        }
    }

    const CHILD_ENV: &str = "OPENSSL_RS_PFP67_CHILD";

    /// The child half: run only when the parent set [`CHILD_ENV`].
    #[test]
    fn pfp67_child_performs_the_calls() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        child::run();
    }

    #[derive(Debug)]
    struct Row {
        name: String,
        aes_ni: u64,
        aes_portable: u64,
        pclmul: u64,
        pclmul_portable: u64,
        sha_ni: u64,
        sha_portable: u64,
        out: String,
    }

    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn run_child(spec: Option<&str>) -> (bool, bool, bool, Vec<Row>, bool, bool) {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "--exact",
            "runtime::cpu::tests::pfp67_child_performs_the_calls",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1");
        match spec {
            Some(value) => {
                cmd.env("OPENSSL_ia32cap", value);
            }
            None => {
                cmd.env_remove("OPENSSL_ia32cap");
            }
        }
        let out = cmd.output().expect("the test binary can be re-executed");
        assert!(
            out.status.success(),
            "child {spec:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        let mut cpu = (false, false, false);
        let mut sel = (false, false);
        let mut rows = Vec::new();
        for line in text.lines() {
            if line.starts_with("cpu_aes=") {
                let mut map = std::collections::HashMap::new();
                for field in line.split_whitespace() {
                    if let Some((k, v)) = field.split_once('=') {
                        map.insert(k, v);
                    }
                }
                let flag = |name: &str| map.get(name).is_some_and(|v| *v == "true");
                cpu = (flag("cpu_aes"), flag("cpu_pclmul"), flag("cpu_sha"));
            }
            if let Some(rest) = line.strip_prefix("sel ") {
                let mut map = std::collections::HashMap::new();
                for field in rest.split_whitespace() {
                    if let Some((k, v)) = field.split_once('=') {
                        map.insert(k, v);
                    }
                }
                let flag = |name: &str| map.get(name).is_some_and(|v| *v == "1");
                sel = (
                    flag("cbc_hmac_sha1_128_null"),
                    flag("cbc_hmac_sha256_128_null"),
                );
            }
            if let Some(rest) = line.strip_prefix("caller=") {
                let mut parts = rest.split_whitespace();
                let mut row = Row {
                    name: parts.next().unwrap_or_default().to_string(),
                    aes_ni: 0,
                    aes_portable: 0,
                    pclmul: 0,
                    pclmul_portable: 0,
                    sha_ni: 0,
                    sha_portable: 0,
                    out: String::new(),
                };
                for field in parts {
                    if let Some((k, v)) = field.split_once('=') {
                        match k {
                            "aes_ni" => row.aes_ni = v.parse().unwrap(),
                            "aes_portable" => row.aes_portable = v.parse().unwrap(),
                            "pclmul" => row.pclmul = v.parse().unwrap(),
                            "pclmul_portable" => row.pclmul_portable = v.parse().unwrap(),
                            "sha_ni" => row.sha_ni = v.parse().unwrap(),
                            "sha_portable" => row.sha_portable = v.parse().unwrap(),
                            "out" => row.out = v.to_string(),
                            _ => {}
                        }
                    }
                }
                rows.push(row);
            }
        }
        assert_eq!(rows.len(), 5, "child {spec:?} transcript: {text}");
        (cpu.0, cpu.1, cpu.2, rows, sel.0, sel.1)
    }

    #[allow(clippy::expect_used)]
    fn row<'a>(rows: &'a [Row], name: &str) -> &'a Row {
        rows.iter().find(|r| r.name == name).expect(name)
    }

    /// The Step-4 matrix: one environment per feature, every real caller, and the
    /// execution counters prove which kernel ran. Outputs must be identical no matter
    /// which arm the override selects.
    #[test]
    fn pfp67_override_forces_the_portable_arm_on_every_caller() {
        let (cpu_aes, cpu_pclmul, cpu_sha, base, base_sha1_null, base_sha256_null) =
            run_child(None);

        // Positive control: with no override the accelerated kernels execute.
        if cpu_aes {
            // The stitched CBC-HMAC constructors are the authority's AESNI_CAPABLE observable.
            assert!(
                !base_sha1_null && !base_sha256_null,
                "the CBC-HMAC selectors are NULL without an override"
            );
            for name in [
                "AES_encrypt",
                "AES_cbc_encrypt",
                "CRYPTO_ctr128_encrypt",
                "CRYPTO_gcm128_encrypt",
            ] {
                let r = row(&base, name);
                assert!(
                    r.aes_ni > 0,
                    "{name} did not take AES-NI without an override"
                );
                assert_eq!(r.aes_portable, 0, "{name} used the portable arm");
            }
        }
        if cpu_pclmul {
            let r = row(&base, "CRYPTO_gcm128_encrypt");
            assert!(
                r.pclmul > 0,
                "GCM did not take PCLMULQDQ without an override"
            );
            assert_eq!(r.pclmul_portable, 0);
        }
        if cpu_sha {
            let r = row(&base, "SHA256");
            assert!(
                r.sha_ni > 0,
                "SHA-256 did not take SHA-NI without an override"
            );
            assert_eq!(r.sha_portable, 0);
        }

        // AES cleared through the documented first-vector `~` form. `::::` keeps the
        // extended vectors at the CPU's value, so only AES moves.
        let (_, _, _, aes_off, aes_sha1_null, aes_sha256_null) =
            run_child(Some("~0x200000000000000:::::"));
        for name in [
            "AES_encrypt",
            "AES_cbc_encrypt",
            "CRYPTO_ctr128_encrypt",
            "CRYPTO_gcm128_encrypt",
        ] {
            let r = row(&aes_off, name);
            assert_eq!(r.aes_ni, 0, "{name} still executed AES-NI with AES cleared");
            assert!(
                r.aes_portable > 0,
                "{name} did not execute the portable arm"
            );
            assert_eq!(r.out, row(&base, name).out, "{name} output changed");
        }
        if cpu_aes {
            assert!(
                aes_sha1_null && aes_sha256_null,
                "the CBC-HMAC selectors ignored a cleared AES bit"
            );
        }

        // PCLMULQDQ cleared through LV0 bit 33.
        let (_, _, _, pclmul_off, _, _) = run_child(Some("~0x200000000:::::"));
        let gcm_base = row(&base, "CRYPTO_gcm128_encrypt");
        let gcm_off = row(&pclmul_off, "CRYPTO_gcm128_encrypt");
        assert_eq!(gcm_off.pclmul, 0, "GCM still executed PCLMULQDQ");
        assert!(
            gcm_off.pclmul_portable > 0,
            "GCM did not run the portable field multiply"
        );
        assert_eq!(gcm_off.out, gcm_base.out, "GCM output changed");

        // SHA cleared through the documented second-vector `~` form.
        let (_, _, _, sha_off, _, _) = run_child(Some(":~0x20000000"));
        let sha_off_row = row(&sha_off, "SHA256");
        assert_eq!(sha_off_row.sha_ni, 0, "SHA-256 still executed SHA-NI");
        assert!(
            sha_off_row.sha_portable > 0,
            "SHA-256 did not execute the portable arm"
        );
        assert_eq!(
            sha_off_row.out,
            row(&base, "SHA256").out,
            "SHA-256 output changed"
        );

        // The value-set form the authority's own Phase-19 court drives. The old
        // fragment ignored it entirely; it must now disable both AES and SHA.
        let (_, _, _, value_set, value_set_sha1_null, value_set_sha256_null) =
            run_child(Some("0x0:0x0"));
        for name in [
            "AES_encrypt",
            "AES_cbc_encrypt",
            "CRYPTO_ctr128_encrypt",
            "CRYPTO_gcm128_encrypt",
        ] {
            let r = row(&value_set, name);
            assert_eq!(r.aes_ni, 0, "{name} ignored the value-set form");
            assert!(r.aes_portable > 0);
            assert_eq!(r.out, row(&base, name).out);
        }
        assert_eq!(row(&value_set, "CRYPTO_gcm128_encrypt").pclmul, 0);
        assert_eq!(row(&value_set, "SHA256").sha_ni, 0);
        assert_eq!(row(&value_set, "SHA256").out, row(&base, "SHA256").out);
        if cpu_aes {
            assert!(
                value_set_sha1_null && value_set_sha256_null,
                "the CBC-HMAC selectors ignored the value-set form"
            );
        }

        // Clearing FXSR (bit 24) masks AES-NI through the authority's knock-on rule.
        let (_, _, _, fxsr_off, _, _) = run_child(Some("~0x1000000:::::"));
        assert_eq!(
            row(&fxsr_off, "AES_encrypt").aes_ni,
            0,
            "FXSR knock-on not applied"
        );
        assert_eq!(
            row(&fxsr_off, "AES_encrypt").out,
            row(&base, "AES_encrypt").out
        );
    }
}
