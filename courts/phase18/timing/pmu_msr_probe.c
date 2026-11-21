// openssl-rs — is a PMU present, and are its counters real?
//
// `cpuid` can be masked by a hypervisor while the machine still has counters,
// so CPUID alone is not conclusive.  This probe goes to the hardware: it
// programs a general-purpose performance counter and checks whether the
// configuration is retained and whether the counter moves.
//
// Three outcomes, each distinguishable:
//
//   * open /dev/cpu/N/msr fails          -> no access (run privileged)
//   * PERFEVTSEL0 reads back what was
//     written and PMC0 advances          -> counters are real
//   * PERFEVTSEL0 reads back 0 and PMC0
//     stays 0 with ECONNREFUSED-free IO  -> the hypervisor traps and discards
//                                          PMU MSR writes; no PMU is exposed
//
// Build and run (needs /dev/cpu and privilege; outside the court):
//   cc -O2 -o pmu_msr_probe pmu_msr_probe.c
//   docker run --rm --privileged -v /dev/cpu:/dev/cpu
//     -v "$PWD/pmu_msr_probe:/pmu_msr_probe:ro" debian:bookworm-slim /pmu_msr_probe 1
// (the second line continues the same docker invocation)
//
// Exits 0 when counters are real, 2 when they are absent or stubbed, 1 on error.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IA32_PERFEVTSEL0 0x186
#define IA32_PMC0        0x0C1

/* instructions retired, user mode, counter enabled */
#define SEL_INSTRUCTIONS ((1ULL << 22) | (1ULL << 16) | 0xC0ULL)

static unsigned long long rd_msr(int fd, unsigned off)
{
    unsigned long long v = 0;
    if (pread(fd, &v, 8, off) != 8)
        return 0;
    return v;
}

static int wr_msr(int fd, unsigned off, unsigned long long v)
{
    if (pwrite(fd, &v, 8, off) != 8) {
        fprintf(stderr, "write 0x%x: %s\n", off, strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int cpu = argc > 1 ? atoi(argv[1]) : 0;
    cpu_set_t set;
    char path[64];
    int fd;
    unsigned long long readback, before, after;
    volatile unsigned long long acc = 0;
    unsigned long long i;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0) {
        fprintf(stderr, "setaffinity cpu %d: %s\n", cpu, strerror(errno));
        return 1;
    }

    snprintf(path, sizeof path, "/dev/cpu/%d/msr", cpu);
    fd = open(path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s (need /dev/cpu and privilege)\n", path,
                strerror(errno));
        return 1;
    }

    if (wr_msr(fd, IA32_PERFEVTSEL0, 0) != 0)
        return 1;
    if (wr_msr(fd, IA32_PMC0, 0) != 0)
        return 1;
    if (wr_msr(fd, IA32_PERFEVTSEL0, SEL_INSTRUCTIONS) != 0)
        return 1;

    readback = rd_msr(fd, IA32_PERFEVTSEL0);
    before = rd_msr(fd, IA32_PMC0);
    for (i = 0; i < 10000000ULL; i++)
        acc += i;
    after = rd_msr(fd, IA32_PMC0);
    wr_msr(fd, IA32_PERFEVTSEL0, 0);

    printf("cpu=%d wrote=0x%llx readback=0x%llx pmc_before=%llu pmc_after=%llu "
           "delta=%llu (work=%llu)\n",
           cpu, (unsigned long long)SEL_INSTRUCTIONS, readback, before, after,
           after - before, (unsigned long long)acc);

    if (readback != SEL_INSTRUCTIONS) {
        printf("verdict: PMU_ABSENT -- the hypervisor discarded the counter "
               "configuration; no PMU is exposed to this guest\n");
        return 2;
    }
    if (after == before) {
        printf("verdict: PMU_PRESENT_BUT_NOT_COUNTING -- configuration retained, "
               "counter did not advance\n");
        return 2;
    }
    printf("verdict: PMU_WORKING -- hardware instruction counter advanced by "
           "%llu\n", after - before);
    return 0;
}
