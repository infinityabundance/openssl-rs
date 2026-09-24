// Layout measurement for the EC objects and the two method tables.
//
// 8.7's shapes are `crypto/ec/ec_local.h`, and four of them are the allocation an application's
// `CRYPTO_set_mem_functions` allocator receives as `num`: `ossl_ec_group_new_ex` allocates a
// `struct ec_group_st`, `EC_POINT_new` a `struct ec_point_st`, `ossl_ec_key_new_method_int` a
// `struct ec_key_st` (with `OPENSSL_zalloc`, so a missed member is a heap overrun rather than a
// wrong value), and `EC_KEY_METHOD_new` a `struct ec_key_method_st`. `struct ec_method_st` is a
// `static const` in each of the five method-table units rather than an allocation, but its
// **offsets** are what a caller's `EC_METHOD` read reaches and what a transcription that dropped
// or reordered a member would move.
//
// Three offsets cannot be reasoned about from the declaration. In `struct ec_group_st` the three
// four-byte ints at 32/36/40 are followed by an enum, so 32..48 is five four-byte members and no
// padding; `poly[6]` is 24 bytes at 72 and `a`/`b` are pointers, so 96 is the first of them. In
// `struct ec_key_st` the four-byte `version` at 16 is followed by a pointer, and the four-byte
// `references` at 56 is followed by another int, so `ex_data` is eight-aligned at 64. In
// `struct ec_key_method_st` the `int32_t flags` at 8 is followed by a pointer at 16.
//
// The width of `int`, of `size_t` and of an enum is the profile's, so only the compiler can say.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include "ec_local.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))
#define VAL(x) printf("%-34s = %d\n", #x, (int)(x))

int main(void)
{
    SHOW(struct ec_method_st);
    ALIGN(struct ec_method_st);
    OFF(struct ec_method_st, flags);
    OFF(struct ec_method_st, field_type);
    OFF(struct ec_method_st, group_init);
    OFF(struct ec_method_st, group_check_discriminant);
    OFF(struct ec_method_st, point_init);
    OFF(struct ec_method_st, point_set_to_infinity);
    OFF(struct ec_method_st, point_set_compressed_coordinates);
    OFF(struct ec_method_st, point2oct);
    OFF(struct ec_method_st, oct2point);
    OFF(struct ec_method_st, add);
    OFF(struct ec_method_st, is_at_infinity);
    OFF(struct ec_method_st, make_affine);
    OFF(struct ec_method_st, points_make_affine);
    OFF(struct ec_method_st, mul);
    OFF(struct ec_method_st, have_precompute_mult);
    OFF(struct ec_method_st, field_mul);
    OFF(struct ec_method_st, field_inv);
    OFF(struct ec_method_st, field_encode);
    OFF(struct ec_method_st, field_set_to_one);
    OFF(struct ec_method_st, priv2oct);
    OFF(struct ec_method_st, oct2priv);
    OFF(struct ec_method_st, keygen);
    OFF(struct ec_method_st, keycheck);
    OFF(struct ec_method_st, keygenpub);
    OFF(struct ec_method_st, keycopy);
    OFF(struct ec_method_st, keyfinish);
    OFF(struct ec_method_st, ecdh_compute_key);
    OFF(struct ec_method_st, ecdsa_sign_setup);
    OFF(struct ec_method_st, ecdsa_sign_sig);
    OFF(struct ec_method_st, ecdsa_verify_sig);
    OFF(struct ec_method_st, field_inverse_mod_ord);
    OFF(struct ec_method_st, blind_coordinates);
    OFF(struct ec_method_st, ladder_pre);
    OFF(struct ec_method_st, ladder_step);
    OFF(struct ec_method_st, ladder_post);
    OFF(struct ec_method_st, group_full_init);

    SHOW(struct ec_group_st);
    ALIGN(struct ec_group_st);
    OFF(struct ec_group_st, meth);
    OFF(struct ec_group_st, generator);
    OFF(struct ec_group_st, order);
    OFF(struct ec_group_st, cofactor);
    OFF(struct ec_group_st, curve_name);
    OFF(struct ec_group_st, asn1_flag);
    OFF(struct ec_group_st, decoded_from_explicit_params);
    OFF(struct ec_group_st, asn1_form);
    OFF(struct ec_group_st, seed);
    OFF(struct ec_group_st, seed_len);
    OFF(struct ec_group_st, field);
    OFF(struct ec_group_st, poly);
    OFF(struct ec_group_st, a);
    OFF(struct ec_group_st, b);
    OFF(struct ec_group_st, a_is_minus3);
    OFF(struct ec_group_st, field_data1);
    OFF(struct ec_group_st, field_data2);
    OFF(struct ec_group_st, field_mod_func);
    OFF(struct ec_group_st, mont_data);
    OFF(struct ec_group_st, pre_comp_type);
    OFF(struct ec_group_st, pre_comp);
    OFF(struct ec_group_st, libctx);
    OFF(struct ec_group_st, propq);

    SHOW(struct ec_point_st);
    ALIGN(struct ec_point_st);
    OFF(struct ec_point_st, meth);
    OFF(struct ec_point_st, curve_name);
    OFF(struct ec_point_st, X);
    OFF(struct ec_point_st, Y);
    OFF(struct ec_point_st, Z);
    OFF(struct ec_point_st, Z_is_one);

    SHOW(struct ec_key_st);
    ALIGN(struct ec_key_st);
    OFF(struct ec_key_st, meth);
    OFF(struct ec_key_st, engine);
    OFF(struct ec_key_st, version);
    OFF(struct ec_key_st, group);
    OFF(struct ec_key_st, pub_key);
    OFF(struct ec_key_st, priv_key);
    OFF(struct ec_key_st, enc_flag);
    OFF(struct ec_key_st, conv_form);
    OFF(struct ec_key_st, references);
    OFF(struct ec_key_st, flags);
    OFF(struct ec_key_st, ex_data);
    OFF(struct ec_key_st, libctx);
    OFF(struct ec_key_st, propq);
    OFF(struct ec_key_st, dirty_cnt);

    SHOW(struct ec_key_method_st);
    ALIGN(struct ec_key_method_st);
    OFF(struct ec_key_method_st, name);
    OFF(struct ec_key_method_st, flags);
    OFF(struct ec_key_method_st, init);
    OFF(struct ec_key_method_st, finish);
    OFF(struct ec_key_method_st, copy);
    OFF(struct ec_key_method_st, set_group);
    OFF(struct ec_key_method_st, set_private);
    OFF(struct ec_key_method_st, set_public);
    OFF(struct ec_key_method_st, keygen);
    OFF(struct ec_key_method_st, compute_key);
    OFF(struct ec_key_method_st, sign);
    OFF(struct ec_key_method_st, sign_setup);
    OFF(struct ec_key_method_st, sign_sig);
    OFF(struct ec_key_method_st, verify);
    OFF(struct ec_key_method_st, verify_sig);

    SHOW(struct ECDSA_SIG_st);
    ALIGN(struct ECDSA_SIG_st);
    OFF(struct ECDSA_SIG_st, r);
    OFF(struct ECDSA_SIG_st, s);

    SHOW(point_conversion_form_t);

    VAL(EC_FLAGS_DEFAULT_OCT);
    VAL(EC_FLAGS_CUSTOM_CURVE);
    VAL(EC_FLAGS_NO_SIGN);
    VAL(EC_KEY_METHOD_DYNAMIC);
    VAL(POINT_CONVERSION_COMPRESSED);
    VAL(POINT_CONVERSION_UNCOMPRESSED);
    VAL(POINT_CONVERSION_HYBRID);
    VAL(PCT_none);
    VAL(PCT_nistp224);
    VAL(PCT_nistp256);
    VAL(PCT_nistp384);
    VAL(PCT_nistp521);
    VAL(PCT_nistz256);
    VAL(PCT_ec);
    return 0;
}
