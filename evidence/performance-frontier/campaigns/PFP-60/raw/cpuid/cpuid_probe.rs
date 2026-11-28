// PFP-60 step 0 — CPUID / OS-enablement truth probe.
//
// Uses the same `std::is_x86_feature_detected!` machinery the implementation will
// dispatch on, so the answer includes the kernel's XCR0/OS-enablement gate rather
// than raw CPUID bits alone. `vaes`/`vpclmulqdq` are additionally reported in their
// 256-bit VEX form (available when `avx` is present; the ZMM form would need AVX-512,
// which is a separate feature).
fn main() {
    macro_rules! f {
        ($($name:literal),* $(,)?) => {
            $(println!("{:<14} = {}", $name, std::is_x86_feature_detected!($name));)*
        };
    }
    f!(
        "aes",
        "pclmulqdq",
        "sse2",
        "ssse3",
        "avx",
        "avx2",
        "vaes",
        "vpclmulqdq",
        "avx512f",
        "avx512vl",
    );
    println!(
        "vaes-256-vex       = {}",
        std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("vaes")
    );
    println!(
        "vpclmulqdq-256-vex = {}",
        std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("vpclmulqdq")
    );
}
