/*
 * RT-CPU-CAPABILITY — the Phase 19.1 CPU-capability dispatch audit.
 *
 * What it measures
 * ----------------
 * Phase 19 measures the finished implementation's *dispatch behaviour*. 19.1's subject is the
 * candidate's CPU-capability surface: `OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup` and
 * `OPENSSL_ia32_cpuid`. This probe reports that surface deterministically. It prints the array
 * words `[0..3]`, whether `OPENSSL_cpuid_setup` was reachable and callable, whether
 * `OPENSSL_ia32_cpuid` was reachable and callable, and the capability-derived selection
 * observable through the public API (`OpenSSL_version(OPENSSL_CPU_INFO)`,
 * `OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)` and the four `EVP_aes_*_cbc_hmac_sha*` constructors,
 * which answer NULL when `AESNI_CAPABLE` (`OPENSSL_ia32cap_P[1] & (1 << 25)`) is clear).
 *
 * The probe deliberately does **not** print the raw vector `OPENSSL_ia32_cpuid` returns. That
 * return is built from the runner's own CPUID leaves and is independent of the `OPENSSL_ia32cap`
 * facade, so it is a property of the machine the probe runs on (D213's class) and cannot be part
 * of a capability-set differential whose record must reproduce byte for byte on any runner. The
 * probe still *calls* `OPENSSL_ia32_cpuid`, so `probe.cpuid.called` is an honest observation that
 * the symbol is reachable and executable.
 *
 * The same source compiles twice, once against the admitted authority and once against the
 * candidate distribution shell. Every `key=value` line is a function of the library under test
 * and the process environment alone: no address, no clock and no measured duration is printed,
 * so `forensics/tools/probe_hygiene.py` sees the same transcript at `-O0`, `-O1` and `-O2`.
 *
 * Reaching the capability surface, and the honest answer when it is not there
 * --------------------------------------------------------------------------
 * `OPENSSL_ia32cap_P` is `.hidden` and `OPENSSL_cpuid_setup` / `OPENSSL_ia32_cpuid` live in the
 * static archive, so the three names are declared `weak`: on a side that does not provide them
 * the linker resolves their addresses to NULL and this probe records `probe.reachable.*=0`
 * rather than failing to link. The authority's static archive provides all three; the candidate
 * does not provide any of them (docs/PHASE-19-SUBPHASES.md section 4.2's census), so on the
 * candidate side the probe answers `probe.reachable.*=0` and the public-API observations alone.
 * That is the honest result, not a defect to hide: the plan records the candidate's disposition
 * (the CPU-dispatch string is `CPUINFO: N/A` and `OPENSSL_info(1008)` is NULL) as
 * `OBL-INIT-VERSION-CPU-INFO` / `OBL-INIT-INFO-CPU-SETTINGS`.
 *
 * The fixed CPUID facade
 * ----------------------
 * `OPENSSL_cpuid_setup` reads the `OPENSSL_ia32cap` environment variable and sets the capability
 * vector from it (`crypto/cpuid.c:106-159`), so the *court* fixes the capability set by running
 * this probe under a chosen `OPENSSL_ia32cap` value. The authority reads that value in its ELF
 * `.init` constructor, before `main`; the candidate never reads it. The court drives every set
 * under an explicit fixed literal (no leading `~` and no `:`) -- a synthetic *reference* vector,
 * that vector with the AES-NI bit cleared, and zero -- so `OPENSSL_cpuid_setup` overrides
 * `OPENSSL_ia32cap_P[0..1]` with the literal and zeroizes `[2..9]` rather than masking the
 * runner's own CPUID. The vector the authority reports is therefore identical on any runner and
 * never the capture host's; the masking still moves the authority's selection while the
 * candidate, which reads CPUID directly and does not model the facade, does not. The court
 * records that divergence rather than inventing agreement.
 *
 * Not a claim
 * -----------
 * This is a bounded audit of the capability surface under the sets the court drives. It is not a
 * benchmark, not a parity claim, and not an assembly-versus-Rust equivalence claim; a surface the
 * facade does not reach is recorded as `probe.reachable.*=0` rather than assumed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
# define RT_X86 1
#else
# define RT_X86 0
#endif

/*
 * The capability surface. `OPENSSL_IA32CAP_P_MAX_INDEXES` is 10 (include/internal/cryptlib.h);
 * the plan names `[0..3]`, and the court reports exactly those four words. The declarations are
 * weak so the probe links on a side that lacks them, which is how `probe.reachable.*` is
 * answered.
 */
#if RT_X86
extern unsigned int OPENSSL_ia32cap_P[] __attribute__((weak));
extern void OPENSSL_cpuid_setup(void) __attribute__((weak));
extern unsigned long long OPENSSL_ia32_cpuid(unsigned int *) __attribute__((weak));
#endif

#define RT_WORDS 4
#define RT_CPUID_INDEXES 10

static void kv(const char *key, const char *value)
{
    printf("%s=%s\n", key, value != NULL ? value : "");
}

static void khex32(const char *key, unsigned int value)
{
    printf("%s=0x%08x\n", key, value);
}

static void klong(const char *key, long long value)
{
    printf("%s=%lld\n", key, value);
}

static void word_key(char *out, size_t cap, const char *prefix, int i)
{
    snprintf(out, cap, "%s.%d", prefix, i);
}

int main(void)
{
    printf("probe.kind=cpu-capability\n");
    printf("probe.arch=%s\n",
#if RT_X86
           "x86"
#else
           "non-x86"
#endif
    );

#if !RT_X86
    /* The capability surface is x86-only; on any other architecture every numeric observation
     * is `n/a` and the public-API observations below are still reported. */
    printf("probe.reachable.ia32cap_p=0\n");
    printf("probe.reachable.cpuid_setup=0\n");
    printf("probe.reachable.ia32_cpuid=0\n");
    printf("probe.setup.called=0\n");
    printf("probe.setup.stable=-1\n");
    printf("probe.cpuid.called=0\n");
    for (int i = 0; i < RT_WORDS; i++) {
        char k[64];
        word_key(k, sizeof k, "cap.word", i);
        printf("%s=n/a\n", k);
        word_key(k, sizeof k, "cap.after_setup", i);
        printf("%s=n/a\n", k);
    }
#else
    /*
     * `OPENSSL_ia32cap_P` is `.hidden`, so a dynamic link never resolves it; the court links the
     * authority and candidate probes against their *static* archives so this address is real on a
     * side that provides the symbol. The address is carried through a volatile so the null test
     * is not folded away for a weak definition.
     */
    volatile uintptr_t cap_addr = (uintptr_t)(const void *)OPENSSL_ia32cap_P;
    volatile uintptr_t setup_addr = (uintptr_t)OPENSSL_cpuid_setup;
    volatile uintptr_t cpuid_addr = (uintptr_t)OPENSSL_ia32_cpuid;
    int have_cap = (cap_addr != 0);
    int have_setup = (setup_addr != 0);
    int have_cpuid = (cpuid_addr != 0);
    const unsigned int *p = (const unsigned int *)(uintptr_t)cap_addr;

    klong("probe.reachable.ia32cap_p", have_cap);
    klong("probe.reachable.cpuid_setup", have_setup);
    klong("probe.reachable.ia32_cpuid", have_cpuid);

    unsigned int before[RT_WORDS];
    for (int i = 0; i < RT_WORDS; i++)
        before[i] = have_cap ? p[i] : 0;

    /* The effect of `OPENSSL_cpuid_setup`: it is a `trigger`-guarded once, so a second call after
     * the ELF `.init` constructor is a no-op and the array is unchanged. */
    if (have_setup) {
        ((void (*)(void))(uintptr_t)setup_addr)();
        klong("probe.setup.called", 1);
        int stable = 1;
        for (int i = 0; i < RT_WORDS; i++)
            if (have_cap && p[i] != before[i])
                stable = 0;
        klong("probe.setup.stable", have_cap ? stable : -1);
    } else {
        klong("probe.setup.called", 0);
        klong("probe.setup.stable", -1);
    }

    for (int i = 0; i < RT_WORDS; i++) {
        char k[64];
        word_key(k, sizeof k, "cap.word", i);
        if (have_cap)
            khex32(k, before[i]);
        else
            printf("%s=n/a\n", k);
        word_key(k, sizeof k, "cap.after_setup", i);
        if (have_cap)
            khex32(k, have_setup ? p[i] : before[i]);
        else
            printf("%s=n/a\n", k);
    }

    /* Exercise `OPENSSL_ia32_cpuid` so `probe.cpuid.called` is an honest observation that the
     * symbol is reachable and executable. Its return is not recorded: it is the runner's raw
     * CPUID, independent of the `OPENSSL_ia32cap` facade (see the header). */
    if (have_cpuid) {
        unsigned int buf[RT_CPUID_INDEXES];
        memset(buf, 0, sizeof buf);
        (void)((unsigned long long (*)(unsigned int *))(uintptr_t)cpuid_addr)(buf);
        klong("probe.cpuid.called", 1);
    } else {
        klong("probe.cpuid.called", 0);
    }
#endif

    /* The capability report and the capability-derived selection, both through the public API.
     * These are observable on either side whether or not the internal surface is reachable. */
    kv("api.cpuinfo", OpenSSL_version(OPENSSL_CPU_INFO));
    {
        const char *settings = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS);
        klong("api.cpu_settings_null", settings == NULL);
        kv("api.cpu_settings", settings);
    }
    klong("sel.aes128cbcsha1.null", EVP_aes_128_cbc_hmac_sha1() == NULL);
    klong("sel.aes256cbcsha1.null", EVP_aes_256_cbc_hmac_sha1() == NULL);
    klong("sel.aes128cbcsha256.null", EVP_aes_128_cbc_hmac_sha256() == NULL);
    klong("sel.aes256cbcsha256.null", EVP_aes_256_cbc_hmac_sha256() == NULL);

    printf("probe.done=1\n");
    return 0;
}
