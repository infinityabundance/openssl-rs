// Layout measurement for the `RSA` object and its method table.
//
// `RSA_new()` allocates `sizeof(RSA)` with `OPENSSL_zalloc`, so the size is what an application's
// `CRYPTO_set_mem_functions` allocator receives as `num`, and the member offsets are contract twice
// over: the accessors (`RSA_get0_key`, `RSA_get0_factors`, `RSA_get0_crt_params`, `RSA_get0_n` and
// the rest) hand out the addresses of the `BIGNUM *` fields themselves, so a caller that writes
// through one of those pointers writes into the object; and `RSA_set_method`/`RSA_get_method` move
// `meth`, which the encrypt/decrypt paths read.
//
// Three of these cannot be reasoned about from the declaration:
//
//   * `CRYPTO_REF_COUNT` is `_Atomic int` or `unsigned int` depending on the profile's atomics, and
//     the two are the same width here but not the same alignment guarantee;
//   * `RSA_PSS_PARAMS_30` is a struct of three pointers whose presence or absence is what makes a
//     PSS-restricted key distinguishable, so its size is part of the object's;
//   * the `#ifndef FIPS_MODULE` block means `pss`, `prime_infos` and `ex_data` are present in this
//     build and absent in a FIPS module build -- the object's layout is *profile-dependent*, and
//     only the compiler can say which this profile produces.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include "openssl/rsa.h"
#include "crypto/rsa.h"
#include "rsa_local.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(RSA);
    ALIGN(RSA);
    OFF(RSA, dummy_zero);
    OFF(RSA, libctx);
    OFF(RSA, version);
    OFF(RSA, meth);
    OFF(RSA, engine);
    OFF(RSA, n);
    OFF(RSA, e);
    OFF(RSA, d);
    OFF(RSA, p);
    OFF(RSA, q);
    OFF(RSA, dmp1);
    OFF(RSA, dmq1);
    OFF(RSA, iqmp);
    OFF(RSA, pss_params);
    OFF(RSA, pss);
    OFF(RSA, prime_infos);
    OFF(RSA, ex_data);
    OFF(RSA, references);
    OFF(RSA, flags);
    OFF(RSA, _method_mod_n);
    OFF(RSA, lock);
    OFF(RSA, dirty_cnt);
    printf("offsetof(%s, undef)                    = %zu\n", "RSA", sizeof(RSA) - sizeof(int));

    SHOW(RSA_PSS_PARAMS_30);
    SHOW(RSA_METHOD);
    OFF(RSA_METHOD, name);
    OFF(RSA_METHOD, rsa_pub_enc);
    OFF(RSA_METHOD, rsa_pub_dec);
    OFF(RSA_METHOD, rsa_priv_enc);
    OFF(RSA_METHOD, rsa_priv_dec);
    OFF(RSA_METHOD, rsa_mod_exp);
    OFF(RSA_METHOD, bn_mod_exp);
    OFF(RSA_METHOD, init);
    OFF(RSA_METHOD, finish);
    OFF(RSA_METHOD, flags);
    OFF(RSA_METHOD, app_data);
    OFF(RSA_METHOD, rsa_sign);
    OFF(RSA_METHOD, rsa_verify);
    OFF(RSA_METHOD, rsa_keygen);
    OFF(RSA_METHOD, rsa_multi_prime_keygen);

    printf("sizeof(CRYPTO_REF_COUNT) = %zu\n", sizeof(CRYPTO_REF_COUNT));
    printf("sizeof(CRYPTO_EX_DATA) = %zu\n", sizeof(CRYPTO_EX_DATA));
    return 0;
}
