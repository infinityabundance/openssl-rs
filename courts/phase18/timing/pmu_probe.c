/*
 * pmu_probe.c — T17 evidence: does this CPU expose an architectural PMU?
 *
 * The absence of /sys/bus/event_source/devices/cpu is a kernel observation.
 * This probe records the CPU-side reason, so the conclusion does not rest on a
 * single interface:
 *
 *   - CPUID.0AH (Intel architectural performance monitoring) version/counters;
 *   - CPUID.1.ECX[31] (hypervisor present);
 *   - CPUID.80000001H.EDX[22] (AMD PerfCtrExtCore) and CPUID.80000022H;
 *   - the vendor string, so an Intel leaf is not read as if it applied to AMD.
 *
 * It prints raw fields only; the interpretation belongs in the report.
 *
 * Build/run through run_pmu_substitutes.sh. Part of the T17 substitute suite,
 * not a PMU itself.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void leaf(const char *name, unsigned int a, unsigned int b,
                 unsigned int c, unsigned int d)
{
    printf("%s eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x\n", name, a, b, c,
           d);
}

int main(void)
{
    unsigned int max_leaf, max_ext;
    unsigned int a, b, c, d;
    char vendor[13];

    __cpuid(0, max_leaf, b, c, d);
    memcpy(vendor + 0, &b, 4);
    memcpy(vendor + 4, &d, 4);
    memcpy(vendor + 8, &c, 4);
    vendor[12] = '\0';
    printf("cpuid.0 max_leaf=%u vendor=%s\n", max_leaf, vendor);

    __cpuid(1, a, b, c, d);
    printf("cpuid.1 hypervisor_present=%u\n", (c >> 31) & 1u);
    leaf("cpuid.1", a, b, c, d);

    if (max_leaf >= 0x0a) {
        unsigned int sub;

        for (sub = 0; sub < 3; sub++) {
            char name[32];

            __cpuid_count(0x0a, sub, a, b, c, d);
            snprintf(name, sizeof(name), "cpuid.0A.%u", sub);
            leaf(name, a, b, c, d);
            if (sub == 0) {
                printf("cpuid.0A.version=%u num_general_counters=%u "
                       "counter_bit_width=%u\n",
                       a & 0xffu, (a >> 8) & 0xffu, (a >> 16) & 0xffu);
            }
        }
    } else {
        printf("cpuid.0A unavailable (max_leaf=%u < 10)\n", max_leaf);
    }

    __cpuid(0x80000000u, max_ext, b, c, d);
    printf("cpuid.80000000 max_ext_leaf=0x%08x\n", max_ext);
    if (max_ext >= 0x80000001u) {
        __cpuid(0x80000001u, a, b, c, d);
        printf("cpuid.80000001 PerfCtrExtCore_edx_bit22=%u\n",
               (d >> 22) & 1u);
        leaf("cpuid.80000001", a, b, c, d);
    }
    if (max_ext >= 0x80000022u) {
        __cpuid(0x80000022u, a, b, c, d);
        printf("cpuid.80000022 PerfMon_version=%u num_core_counters=%u "
               "counter_bit_width=%u\n",
               a & 0xffu, (a >> 8) & 0xffu, (a >> 12) & 0xfu);
        leaf("cpuid.80000022", a, b, c, d);
    } else {
        printf("cpuid.80000022 unavailable (max_ext=0x%08x)\n", max_ext);
    }

    return 0;
}
