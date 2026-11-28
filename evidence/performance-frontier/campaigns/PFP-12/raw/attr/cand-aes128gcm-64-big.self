--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-aes128gcm-64-big.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 9197117
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op aes128gcm-64 --iters 1000 --runs 1 (PID 458, part 1)
Events recorded:  Ir
Events shown:     Ir
Event sort order: Ir
Thresholds:       99.9
Include dirs:     
User annotated:   
Auto-annotation:  off

--------------------------------------------------------------------------------
Ir                   
--------------------------------------------------------------------------------
136,240,392 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                   file:function
--------------------------------------------------------------------------------
52,665,000 (38.66%)  ???:AES_encrypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
37,285,000 (27.37%)  ???:openssl_rs::modes::gcm::crypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 8,707,500 ( 6.39%)  ???:CRYPTO_gcm128_finish [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 8,507,500 ( 6.24%)  ???:CRYPTO_gcm128_aad [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 4,190,840 ( 3.08%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 3,327,500 ( 2.44%)  ???:openssl_rs::provider::cipher_gcm::aes_gcm_freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 2,412,990 ( 1.77%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   963,551 ( 0.71%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   785,000 ( 0.58%)  ???:openssl_rs::aes::aes_expand [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   716,250 ( 0.53%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_get_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   709,941 ( 0.52%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   693,440 ( 0.51%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   683,498 ( 0.50%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   647,447 ( 0.48%)  ???:openssl_rs::evp::cipher_ctx::evp_cipher_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   605,689 ( 0.44%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   560,438 ( 0.41%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   550,000 ( 0.40%)  ???:openssl_rs::provider::cipher_gcm::aes_gcm_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   528,074 ( 0.39%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   525,342 ( 0.39%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   455,896 ( 0.33%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   433,653 ( 0.32%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
   378,750 ( 0.28%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_set_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   352,500 ( 0.26%)  ???:openssl_rs::provider::cipher_gcm::gcm_cipher_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   342,640 ( 0.25%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   331,812 ( 0.24%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   329,911 ( 0.24%)  ???:openssl_rs::property::store::ossl_method_store_cache_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   295,152 ( 0.22%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   294,010 ( 0.22%)  ./elf/./elf/do-rel.h:_dl_relocate_object
   278,355 ( 0.20%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   273,735 ( 0.20%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   244,296 ( 0.18%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   231,978 ( 0.17%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   226,640 ( 0.17%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   216,516 ( 0.16%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
   216,462 ( 0.16%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
   190,000 ( 0.14%)  ???:OSSL_PARAM_get_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   188,859 ( 0.14%)  ./string/../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:__memset_avx2_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
   187,986 ( 0.14%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   187,783 ( 0.14%)  ???:OPENSSL_LH_retrieve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   185,081 ( 0.14%)  ???:openssl_rs::evp::fetch::inner_evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   179,622 ( 0.13%)  ???:OSSL_LIB_CTX_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   178,750 ( 0.13%)  ???:EVP_CIPHER_CTX_ctrl [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   163,750 ( 0.12%)  ???:aead_round.constprop.0 [/work/court/tmp/pfp12/bench_pfp12]
   161,700 ( 0.12%)  ???:OSSL_PARAM_set_uint64 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   156,097 ( 0.11%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   146,418 ( 0.11%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
   145,000 ( 0.11%)  ???:EVP_CIPHER_CTX_get_iv_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   140,000 ( 0.10%)  ???:EVP_DecryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   122,961 ( 0.09%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   120,867 ( 0.09%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   120,000 ( 0.09%)  ???:EVP_EncryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   115,258 ( 0.08%)  ./string/../sysdeps/x86_64/multiarch/strlen-avx2.S:__strlen_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
   115,000 ( 0.08%)  ???:EVP_CIPHER_CTX_get_key_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   110,386 ( 0.08%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   102,366 ( 0.08%)  ./misc/../sysdeps/unix/sysv/linux/x86_64/syscall.S:syscall [/usr/lib/x86_64-linux-gnu/libc.so.6]
    99,387 ( 0.07%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    95,573 ( 0.07%)  ???:CRYPTO_zalloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    95,000 ( 0.07%)  ???:CRYPTO_gcm128_setiv [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    87,049 ( 0.06%)  ???:openssl_rs::context::namemap::ossl_namemap_stored [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    80,103 ( 0.06%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    80,000 ( 0.06%)  ???:openssl_rs::evp::fetch::evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    76,960 ( 0.06%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    76,250 ( 0.06%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_dinit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    76,250 ( 0.06%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_einit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    76,064 ( 0.06%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
    75,330 ( 0.06%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    70,000 ( 0.05%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_stream_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    68,484 ( 0.05%)  ./nptl/./nptl/pthread_getspecific.c:pthread_getspecific@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    64,661 ( 0.05%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    62,608 ( 0.05%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_realloc
    61,752 ( 0.05%)  ./string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S:__memcmp_avx2_movbe [/usr/lib/x86_64-linux-gnu/libc.so.6]
    61,250 ( 0.04%)  ???:openssl_rs::params::get_string_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    57,500 ( 0.04%)  ???:EVP_EncryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    57,500 ( 0.04%)  ???:openssl_rs::provider::cipher_gcm::aes128gcm_newctx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    55,380 ( 0.04%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    52,921 ( 0.04%)  ./string/../sysdeps/x86_64/multiarch/strcmp-avx2.S:__strcmp_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    52,500 ( 0.04%)  ???:EVP_DecryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    52,104 ( 0.04%)  ???:openssl_rs::context::lib_ctx_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    51,250 ( 0.04%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_cipher_final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    50,627 ( 0.04%)  ???:openssl_rs::evp::cipher::evp_cipher_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    50,532 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/alloc.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    50,424 ( 0.04%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    48,750 ( 0.04%)  ???:openssl_rs::provider::cipher_gcm::sm4_gcm_cipher_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    46,460 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/pal/unix/futex.rs:<std::sync::poison::condvar::Condvar>::notify_all
    42,500 ( 0.03%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_stream_final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    39,765 ( 0.03%)  ./malloc/./malloc/arena.c:free
    39,398 ( 0.03%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    37,160 ( 0.03%)  ./nptl/./nptl/pthread_self.c:pthread_self [/usr/lib/x86_64-linux-gnu/libc.so.6]
    36,834 ( 0.03%)  ???:EVP_CIPHER_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,776 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,500 ( 0.03%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,000 ( 0.03%)  ???:OSSL_PARAM_set_octet_string [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    34,986 ( 0.03%)  ???:openssl_rs::property::store::query_cmp [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    34,397 ( 0.03%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    33,240 ( 0.02%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,847 ( 0.02%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,616 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc_zeroed
    31,304 ( 0.02%)  ./malloc/./malloc/arena.c:realloc
    29,824 ( 0.02%)  ???:openssl_rs::runtime::stack::sk_reserve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    29,682 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/alloc/layout.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    29,682 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/cmp.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    29,682 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/result.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    27,897 ( 0.02%)  ???:openssl_rs::context::namemap::get_legacy_evp_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    27,500 ( 0.02%)  ???:openssl_rs::property::store::query_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    26,351 ( 0.02%)  ./nptl/./nptl/pthread_once.c:pthread_once@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    24,960 ( 0.02%)  ???:OSSL_PARAM_set_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,202 ( 0.02%)  ???:openssl_rs::property::store::ossl_method_store_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,167 ( 0.02%)  ???:openssl_rs::runtime::sparse_array::ossl_sa_set [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    22,500 ( 0.02%)  ???:OSSL_PARAM_get_octet_string [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    22,500 ( 0.02%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_aad_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,249 ( 0.02%)  ???:<hashbrown::raw::RawTable<(alloc::vec::Vec<u8>, i32)>>::reserve_rehash::<hashbrown::map::make_hasher<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>::{closure#0}> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,414 ( 0.01%)  ???:OBJ_NAME_cleanup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,000 ( 0.01%)  ???:EVP_DecryptInit_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,000 ( 0.01%)  ???:EVP_EncryptInit_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    19,396 ( 0.01%)  ???:openssl_rs::evp::cipher::evp_cipher_cache_constants [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    15,000 ( 0.01%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_setiv [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,635 ( 0.01%)  ???:CRYPTO_strndup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,592 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    12,500 ( 0.01%)  ???:openssl_rs::provider::cipher_gcm::aes_block_encrypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,940 ( 0.01%)  ???:__rustc::__rust_no_alloc_shim_is_unstable_v2 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,926 ( 0.01%)  ???:OPENSSL_LH_new [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,547 ( 0.01%)  ???:openssl_rs::context::namemap::ossl_namemap_doall_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,612 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,612 ( 0.01%)  ???:__rustc::__rust_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,336 ( 0.01%)  ./malloc/./malloc/malloc.c:alloc_perturb [/usr/lib/x86_64-linux-gnu/libc.so.6]
    10,276 ( 0.01%)  ./elf/./elf/dl-version.c:_dl_check_map_versions [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    10,105 ( 0.01%)  ./elf/./elf/dl-tunables.c:__GI___tunables_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     9,930 ( 0.01%)  ./elf/../sysdeps/generic/ldsodefs.h:do_lookup_x
     9,880 ( 0.01%)  ???:openssl_rs::evp::fetch::put_evp_method_in_store [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,508 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,508 ( 0.01%)  ???:__rustc::__rust_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,292 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/sync/atomic.rs:<std::sync::poison::condvar::Condvar>::notify_all
     9,292 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sync/poison/condvar.rs:<std::sync::poison::condvar::Condvar>::notify_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,202 ( 0.01%)  ./elf/../sysdeps/generic/ldsodefs.h:_dl_relocate_object
     7,944 ( 0.01%)  ./elf/../sysdeps/generic/dl-protected.h:do_lookup_x
     7,282 ( 0.01%)  ???:OPENSSL_sk_new_null [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,205 ( 0.01%)  ???:OPENSSL_sk_dup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,068 ( 0.00%)  ???:<alloc::vec::Vec<openssl_rs::runtime::obj::NameRec> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<openssl_rs::runtime::obj::NameRec, core::iter::adapters::copied::Copied<core::iter::adapters::filter::Filter<core::slice::iter::Iter<openssl_rs::runtime::obj::NameRec>, openssl_rs::runtime::obj::OBJ_NAME_do_all::{closure#0}::{closure#0}>>>>::from_iter [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,940 ( 0.00%)  ???:openssl_rs::evp::method_store::ossl_method_construct_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,939 ( 0.00%)  ???:openssl_rs::property::defn_cache::ossl_prop_defn_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,878 ( 0.00%)  ./malloc/./malloc/arena.c:calloc
     4,472 ( 0.00%)  ???:__rustc::__rust_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,095 ( 0.00%)  ???:openssl_rs::property::strings::property_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,030 ( 0.00%)  ???:OSSL_PARAM_set_uint32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,865 ( 0.00%)  ???:openssl_rs::runtime::mem::default_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]

