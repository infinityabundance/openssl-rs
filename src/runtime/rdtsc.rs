//! Phase 7.1 — `crypto/x86_64cpuid.pl`'s `OPENSSL_rdtsc`, and the profile fact it corrects.
//!
//! One function, and it lands here because 7.1 is its first caller in this crate:
//! `ossl_method_cache_flush_some` seeds its xorshift from it, and when the answer is zero it falls
//! back to a process-global counter instead. Attribution is by first caller, the same rule that
//! decides which stratum owns a shared store.
//!
//! ## The plan said `no-asm`, and the authority's own build record says otherwise
//!
//! `docs/PHASE-7-SUBPHASES.md` §3.5 recorded "**`no-asm` is set**, so no `crypto/evp/*.s` or
//! per-architecture `.pl` output is a dependency". That is **wrong**, and the authority contradicts
//! it in three places a reader can check:
//!
//! * `%disabled` in `configdata.pm` — the admitted profile's actual disable list — contains
//!   `acvp-tests`, `asan`, `brotli`, `crypto-mdebug`, `ec_nistp_64_gcc_128`, `fips`, `ktls`, `md2`,
//!   `msan`, `pie`, `rc5`, `sctp`, `ssl3`, `tests`, `trace`, `ubsan`, `zlib` and twenty-one more,
//!   and **`asm` is not among them**;
//! * `"asm_arch" => "x86_64"` and `"perlasm_scheme" => "elf"` are both recorded;
//! * the build tree holds `crypto/x86_64cpuid.s` **and** `libcrypto-shlib-x86_64cpuid.o`, and the
//!   `.s` is perlasm output — a file that does not exist in a `no-asm` build.
//!
//! The record is corrected in D143 rather than quietly worked around, because the *consequence* is
//! not local to this file: whatever `crypto/*.pl` and `crypto/*/*.pl` produce is part of the
//! authority this crate reconstructs. Most of it is hidden from the DSO by the version script, so
//! none of it is *exported* surface — but a Phase 8 or 9 transcription that reaches `aesni_encrypt`
//! or `sha256_block_data_order` is reaching a perlasm implementation, and a plan that says there
//! are none would have sent that work looking in the wrong place.
//!
//! What it does **not** change is any observable: `OPENSSL_rdtsc`'s value is a timestamp, and the
//! only thing that reads it is a *stochastic* cache flush whose outcome is seed-dependent on the
//! authority as well. No court can assert it and none does; see `RT-FETCH`'s header.
//!
//! ## The value is the low half of the counter
//!
//! The perlasm body is `rdtsc; shl $32,%rdx; or %rdx,%rax; ret` — it assembles the full 64-bit
//! value in `rax` — but the declared return type is `uint32_t`, so every caller reads the low 32
//! bits. This transcription takes the same half rather than the whole, because "the function
//! returns a `uint32_t`" is the contract and the wider register is an artefact of how the counter
//! is read.
//!
//! SPDX-License-Identifier: Apache-2.0

/// `uint32_t OPENSSL_rdtsc(void)`.
///
/// On `x86_64` this is the CPU's timestamp counter, which is what the perlasm body reads. The
/// intrinsic is `unsafe` in Rust for the same reason the instruction is unavailable on some
/// targets rather than because it can corrupt anything: it is a read of a special register with no
/// memory effects.
///
/// **The no-`x86_64` arm is a recorded divergence and not a fallback implementation.** The admitted
/// profile is `linux-x86_64` and this crate's claims are scoped to it, so a build for another
/// architecture is already outside the contract; answering `0` there takes the *documented*
/// second branch of the one caller (the global seed) instead of inventing a timestamp source the
/// authority does not have on that target either. `docs/SECURITY_DIVERGENCE_POLICY.md` carries the
/// class.
#[cfg(target_arch = "x86_64")]
#[allow(non_snake_case)] // the authority's name is the contract, and it is a C identifier
pub(crate) fn OPENSSL_rdtsc() -> u32 {
    // SAFETY: `_rdtsc` has no memory effects and no preconditions on this target; it is the same
    // instruction the perlasm body emits.
    unsafe { core::arch::x86_64::_rdtsc() as u32 }
}

/// The non-`x86_64` arm: see the note above. `0` selects the caller's global-seed branch.
#[cfg(not(target_arch = "x86_64"))]
#[allow(non_snake_case)] // as above
pub(crate) fn OPENSSL_rdtsc() -> u32 {
    0
}
