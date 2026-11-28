/* PFP-65: evaluate the two inputs of HWSM4_CAPABLE_X86_64
 *   ((OPENSSL_ia32cap_P[2] & (1 << 5)) && (OPENSSL_ia32cap_P[5] & (1 << 2)))
 * OPENSSL_ia32cap_P[2] is CPUID.(7,0).EBX; OPENSSL_ia32cap_P[5] is CPUID.(7,1).EAX.
 * No authority symbol is linked (OPENSSL_ia32cap_P is hidden); CPUID is direct. */
#include <cpuid.h>
#include <stdio.h>

int main(void) {
    unsigned int a0, b0, c0, d0, a1, b1, c1, d1;
    if (!__get_cpuid_count(7, 0, &a0, &b0, &c0, &d0)) {
        puts("cpuid leaf 7 subleaf 0: absent");
        return 1;
    }
    if (!__get_cpuid_count(7, 1, &a1, &b1, &c1, &d1)) {
        puts("cpuid leaf 7 subleaf 1: absent");
        return 1;
    }
    int avx2 = (int)((b0 >> 5) & 1u);
    int sm4 = (int)((a1 >> 2) & 1u);
    printf("cpuid.7.0.ebx=0x%08x bit5(AVX2)=%d\n", b0, avx2);
    printf("cpuid.7.1.eax=0x%08x bit2(SM4)=%d\n", a1, sm4);
    printf("HWSM4_CAPABLE_X86_64=%d\n", avx2 && sm4);
    return 0;
}
