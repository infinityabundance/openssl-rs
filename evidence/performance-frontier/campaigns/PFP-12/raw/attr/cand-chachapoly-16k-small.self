--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-chachapoly-16k-small.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 2812048
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op chachapoly-16k --iters 16 --runs 1 (PID 485, part 1)
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
27,080,433 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                   file:function
--------------------------------------------------------------------------------
12,442,080 (45.94%)  ???:openssl_rs::chacha::ChaCha20_ctr32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 4,190,840 (15.48%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 2,343,000 ( 8.65%)  ???:openssl_rs::mac::poly1305::poly1305_blocks [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   683,498 ( 2.52%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   651,917 ( 2.41%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   528,386 ( 1.95%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   433,653 ( 1.60%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
   342,640 ( 1.27%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   333,734 ( 1.23%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   333,082 ( 1.23%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   294,010 ( 1.09%)  ./elf/./elf/do-rel.h:_dl_relocate_object
   268,458 ( 0.99%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   226,640 ( 0.84%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   216,516 ( 0.80%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
   214,816 ( 0.79%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   182,390 ( 0.67%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   175,035 ( 0.65%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   156,097 ( 0.58%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   135,432 ( 0.50%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   132,943 ( 0.49%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
   125,180 ( 0.46%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   122,961 ( 0.45%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   121,004 ( 0.45%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   117,318 ( 0.43%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   116,636 ( 0.43%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   110,386 ( 0.41%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    95,266 ( 0.35%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    80,103 ( 0.30%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    76,960 ( 0.28%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    75,330 ( 0.28%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    74,662 ( 0.28%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
    66,949 ( 0.25%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    64,661 ( 0.24%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    56,384 ( 0.21%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
    55,380 ( 0.20%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    50,627 ( 0.19%)  ???:openssl_rs::evp::cipher::evp_cipher_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    50,424 ( 0.19%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    47,811 ( 0.18%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    47,160 ( 0.17%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    39,398 ( 0.15%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,500 ( 0.13%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,233 ( 0.13%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    33,240 ( 0.12%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    32,967 ( 0.12%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,847 ( 0.12%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,616 ( 0.12%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc_zeroed
    30,195 ( 0.11%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    29,824 ( 0.11%)  ???:openssl_rs::runtime::stack::sk_reserve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    28,728 ( 0.11%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_realloc
    27,897 ( 0.10%)  ???:openssl_rs::context::namemap::get_legacy_evp_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    26,092 ( 0.10%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/alloc.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    25,005 ( 0.09%)  ./malloc/./malloc/arena.c:free
    24,960 ( 0.09%)  ???:OSSL_PARAM_set_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,202 ( 0.09%)  ???:openssl_rs::property::store::ossl_method_store_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,167 ( 0.09%)  ???:openssl_rs::runtime::sparse_array::ossl_sa_set [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,249 ( 0.08%)  ???:<hashbrown::raw::RawTable<(alloc::vec::Vec<u8>, i32)>>::reserve_rehash::<hashbrown::map::make_hasher<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>::{closure#0}> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,186 ( 0.08%)  ./misc/../sysdeps/unix/sysv/linux/x86_64/syscall.S:syscall [/usr/lib/x86_64-linux-gnu/libc.so.6]
    20,414 ( 0.08%)  ???:OBJ_NAME_cleanup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    19,396 ( 0.07%)  ???:openssl_rs::evp::cipher::evp_cipher_cache_constants [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    19,318 ( 0.07%)  ./string/../sysdeps/x86_64/multiarch/strlen-avx2.S:__strlen_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    19,313 ( 0.07%)  ???:CRYPTO_zalloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    17,430 ( 0.06%)  ./string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S:__memcmp_avx2_movbe [/usr/lib/x86_64-linux-gnu/libc.so.6]
    17,262 ( 0.06%)  ???:OSSL_LIB_CTX_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    16,416 ( 0.06%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    16,379 ( 0.06%)  ./string/../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:__memset_avx2_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
    15,042 ( 0.06%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/alloc/layout.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    15,042 ( 0.06%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/cmp.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    15,042 ( 0.06%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/result.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    15,040 ( 0.06%)  ???:openssl_rs::mac::poly1305::Poly1305_Final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,635 ( 0.05%)  ???:CRYPTO_strndup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,592 ( 0.05%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,364 ( 0.05%)  ./malloc/./malloc/arena.c:realloc
    14,100 ( 0.05%)  ???:OSSL_PARAM_set_uint64 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    13,249 ( 0.05%)  ???:openssl_rs::context::namemap::ossl_namemap_stored [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    13,123 ( 0.05%)  ???:OPENSSL_LH_retrieve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,926 ( 0.04%)  ???:OPENSSL_LH_new [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,547 ( 0.04%)  ???:openssl_rs::context::namemap::ossl_namemap_doall_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,720 ( 0.04%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_aead_cipher [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,360 ( 0.04%)  ./malloc/./malloc/malloc.c:alloc_perturb [/usr/lib/x86_64-linux-gnu/libc.so.6]
    10,307 ( 0.04%)  ???:openssl_rs::evp::cipher_ctx::evp_cipher_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,276 ( 0.04%)  ./elf/./elf/dl-version.c:_dl_check_map_versions [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    10,105 ( 0.04%)  ./elf/./elf/dl-tunables.c:__GI___tunables_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     9,930 ( 0.04%)  ./elf/../sysdeps/generic/ldsodefs.h:do_lookup_x
     9,880 ( 0.04%)  ???:openssl_rs::evp::fetch::put_evp_method_in_store [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,560 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/pal/unix/futex.rs:<std::sync::poison::condvar::Condvar>::notify_all
     9,480 ( 0.04%)  ???:__rustc::__rust_no_alloc_shim_is_unstable_v2 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,840 ( 0.03%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_get_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,202 ( 0.03%)  ./elf/../sysdeps/generic/ldsodefs.h:_dl_relocate_object
     8,152 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,152 ( 0.03%)  ???:__rustc::__rust_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,944 ( 0.03%)  ./elf/../sysdeps/generic/dl-protected.h:do_lookup_x
     7,824 ( 0.03%)  ???:openssl_rs::context::lib_ctx_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,640 ( 0.03%)  ./nptl/./nptl/pthread_self.c:pthread_self [/usr/lib/x86_64-linux-gnu/libc.so.6]
     7,282 ( 0.03%)  ???:OPENSSL_sk_new_null [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,205 ( 0.03%)  ???:OPENSSL_sk_dup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,048 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,048 ( 0.03%)  ???:__rustc::__rust_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,068 ( 0.02%)  ???:<alloc::vec::Vec<openssl_rs::runtime::obj::NameRec> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<openssl_rs::runtime::obj::NameRec, core::iter::adapters::copied::Copied<core::iter::adapters::filter::Filter<core::slice::iter::Iter<openssl_rs::runtime::obj::NameRec>, openssl_rs::runtime::obj::OBJ_NAME_do_all::{closure#0}::{closure#0}>>>>::from_iter [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,980 ( 0.02%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_set_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,191 ( 0.02%)  ???:openssl_rs::property::store::ossl_method_store_cache_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,940 ( 0.02%)  ???:openssl_rs::evp::method_store::ossl_method_construct_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,939 ( 0.02%)  ???:openssl_rs::property::defn_cache::ossl_prop_defn_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,878 ( 0.02%)  ./malloc/./malloc/arena.c:calloc
     4,524 ( 0.02%)  ./nptl/./nptl/pthread_getspecific.c:pthread_getspecific@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     4,095 ( 0.02%)  ???:openssl_rs::property::strings::property_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,030 ( 0.01%)  ???:OSSL_PARAM_set_uint32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,880 ( 0.01%)  ???:openssl_rs::provider::cipher::cipher_generic_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,821 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/strcmp-avx2.S:__strcmp_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     3,744 ( 0.01%)  ???:CRYPTO_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,717 ( 0.01%)  ./malloc/./malloc/arena.c:malloc
     3,640 ( 0.01%)  ???:openssl_rs::evp::fetch::construct_evp_method [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,555 ( 0.01%)  ???:openssl_rs::context::namemap::get_legacy_md_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,446 ( 0.01%)  ???:openssl_rs::evp::c_allc::openssl_add_all_ciphers_int [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,284 ( 0.01%)  ???:openssl_rs::evp::cipher::set_legacy_nid [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,120 ( 0.01%)  ???:<alloc::raw_vec::RawVec<usize>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,041 ( 0.01%)  ???:openssl_rs::evp::fetch::inner_evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,040 ( 0.01%)  ???:OSSL_PARAM_get_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,980 ( 0.01%)  ./elf/../sysdeps/x86/dl-cacheinfo.h:intel_check_word.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,872 ( 0.01%)  ./elf/./elf/dl-load.c:_dl_map_object_from_fd [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,860 ( 0.01%)  ???:EVP_CIPHER_CTX_ctrl [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,620 ( 0.01%)  ???:aead_round.constprop.0 [/work/court/tmp/pfp12/bench_pfp12]
     2,604 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/strchr-avx2.S:__strchr_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,598 ( 0.01%)  ./stdio-common/./stdio-common/printf_fp.c:__printf_fp_l [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,526 ( 0.01%)  ???:OBJ_NAME_do_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,520 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_cipher [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,474 ( 0.01%)  ???:<std::sync::once::Once>::call_once::<openssl_rs::provider::cipher::fill_exported_ciphers>::{closure#0} [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,432 ( 0.01%)  ???:__rustc::__rust_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,394 ( 0.01%)  ???:EVP_CIPHER_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,340 ( 0.01%)  ???:EVP_CIPHER_free [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,320 ( 0.01%)  ???:EVP_CIPHER_CTX_get_iv_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,292 ( 0.01%)  ./malloc/./malloc/malloc.c:malloc_consolidate [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,268 ( 0.01%)  ./elf/../bits/stdlib-bsearch.h:intel_check_word.constprop.0
     2,240 ( 0.01%)  ???:EVP_DecryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,210 ( 0.01%)  ???:openssl_rs::provider::ossl_provider_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,201 ( 0.01%)  ./elf/./elf/dl-deps.c:_dl_map_object_deps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,052 ( 0.01%)  ???:__rustc::__rust_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,960 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_initiv [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,920 ( 0.01%)  ???:EVP_EncryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,912 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/sync/atomic.rs:<std::sync::poison::condvar::Condvar>::notify_all
     1,912 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sync/poison/condvar.rs:<std::sync::poison::condvar::Condvar>::notify_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,840 ( 0.01%)  ???:EVP_CIPHER_CTX_get_key_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,821 ( 0.01%)  ./malloc/./malloc/malloc.c:unlink_chunk.constprop.0 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,751 ( 0.01%)  ./nptl/./nptl/pthread_once.c:pthread_once@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,660 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,440 ( 0.01%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_set_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,423 ( 0.01%)  ./elf/./elf/dl-load.c:_dl_map_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,405 ( 0.01%)  ???:openssl_rs::runtime::mem::default_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,382 ( 0.01%)  ???:EVP_add_digest [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,372 ( 0.01%)  ./elf/./elf/dl-misc.c:_dl_name_match_p [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,300 ( 0.00%)  ???:openssl_rs::provider::cipher::set_size_param [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,280 ( 0.00%)  ???:openssl_rs::evp::fetch::evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,249 ( 0.00%)  ./elf/./elf/rtld.c:dl_main [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,224 ( 0.00%)  ./elf/./elf/dl-runtime.c:_dl_fixup [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,219 ( 0.00%)  ./elf/./elf/dl-sym.c:do_sym [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,218 ( 0.00%)  ./stdio-common/./stdio-common/printf_fp.c:hack_digit [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,209 ( 0.00%)  ./elf/./elf/get-dynamic-info.h:_dl_map_object_from_fd
     1,200 ( 0.00%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,170 ( 0.00%)  ./nptl/./nptl/pthread_mutex_lock.c:pthread_mutex_lock@@GLIBC_2.2.5 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,169 ( 0.00%)  ./elf/./elf/dl-tunables.h:__GI___tunables_init
     1,131 ( 0.00%)  ???:openssl_rs::evp::algorithm::algorithm_do_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,085 ( 0.00%)  ???:OPENSSL_LH_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,082 ( 0.00%)  ./elf/./elf/dl-cache.c:_dl_cache_libcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,036 ( 0.00%)  ./elf/./elf/dl-error-skeleton.c:_dl_catch_exception [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,005 ( 0.00%)  ./stdlib/./stdlib/divrem.c:__mpn_divrem [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,005 ( 0.00%)  ???:openssl_rs::property::strings::ossl_property_string [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       990 ( 0.00%)  ./nptl/./nptl/pthread_mutex_unlock.c:__pthread_mutex_unlock_usercnt [/usr/lib/x86_64-linux-gnu/libc.so.6]
       963 ( 0.00%)  ./elf/./elf/dl-object.c:_dl_new_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       962 ( 0.00%)  ./stdio-common/./stdio-common/vfprintf-internal.c:__vfprintf_internal [/usr/lib/x86_64-linux-gnu/libc.so.6]
       960 ( 0.00%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_newctx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       920 ( 0.00%)  ???:EVP_EncryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       920 ( 0.00%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_dinit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       920 ( 0.00%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_einit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       897 ( 0.00%)  ./dlfcn/./dlfcn/dlerror.c:_dlerror_run [/usr/lib/x86_64-linux-gnu/libc.so.6]
       840 ( 0.00%)  ???:EVP_DecryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       840 ( 0.00%)  ???:openssl_rs::provider::cipher::chacha20_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       807 ( 0.00%)  ./elf/./elf/dl-load.c:open_path [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       776 ( 0.00%)  ./malloc/./malloc/malloc.c:ptmalloc_init.part.0
       744 ( 0.00%)  ???:<alloc::raw_vec::RawVec<alloc::vec::Vec<usize>>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       720 ( 0.00%)  ./elf/./elf/dl-hwcaps.c:_dl_important_hwcaps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       720 ( 0.00%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       704 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:mempcpy [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       696 ( 0.00%)  ./elf/./elf/dl-load.c:open_verify.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       696 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strchr-sse2.S:index [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       679 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/memset-vec-unaligned-erms.S:memset [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       672 ( 0.00%)  ./dlfcn/./dlfcn/dlsym.c:dlsym@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
       667 ( 0.00%)  ./elf/./elf/dl-error-skeleton.c:_dl_catch_error [/usr/lib/x86_64-linux-gnu/libc.so.6]
       640 ( 0.00%)  ./elf/./elf/dl-sort-maps.c:dfs_traversal.part.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       628 ( 0.00%)  ./elf/./elf/dl-tunables.c:__tunable_get_val [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       620 ( 0.00%)  ./elf/./elf/dl-minimal-malloc.c:__minimal_malloc [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       615 ( 0.00%)  ./setjmp/../sysdeps/x86_64/setjmp.S:__sigsetjmp [/usr/lib/x86_64-linux-gnu/libc.so.6]
       606 ( 0.00%)  ./elf/./elf/dl-close.c:_dl_close_worker [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       600 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strlen-sse2.S:strlen [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       592 ( 0.00%)  ./elf/./dl-map-segments.h:_dl_map_object_from_fd
       576 ( 0.00%)  ./stdlib/../sysdeps/x86_64/mul_1.S:__mpn_mul_1 [/usr/lib/x86_64-linux-gnu/libc.so.6]
       568 ( 0.00%)  ./elf/./elf/dl-sort-maps.c:_dl_sort_maps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       555 ( 0.00%)  ???:EVP_PKEY_asn1_get0 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       550 ( 0.00%)  ./libio/./libio/fileops.c:_IO_file_xsputn@@GLIBC_2.2.5 [/usr/lib/x86_64-linux-gnu/libc.so.6]
       546 ( 0.00%)  ???:openssl_rs::property::store::query_cmp [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       520 ( 0.00%)  ./elf/../sysdeps/x86_64/dl-trampoline.h:_dl_runtime_resolve_xsave [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       504 ( 0.00%)  ./elf/../sysdeps/x86/dl-cacheinfo.h:handle_intel.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       497 ( 0.00%)  ???:openssl_rs::provider::seeding::ossl_prov_seeding_from_dispatch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       496 ( 0.00%)  ???:openssl_rs::provider::digest::ossl_default_provider_init [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       477 ( 0.00%)  ./elf/./elf/dl-open.c:dl_open_worker_begin [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       464 ( 0.00%)  ???:<openssl_rs::runtime::err::ErrState>::clear [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       440 ( 0.00%)  ???:openssl_rs::property::store::query_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       418 ( 0.00%)  ./elf/./elf/dl-cache.c:search_cache [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       393 ( 0.00%)  ./elf/./elf/dl-hwcaps_split.c:_dl_hwcaps_split [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       390 ( 0.00%)  ./elf/./elf/dl-init.c:call_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       388 ( 0.00%)  ./malloc/./malloc/malloc.c:sysmalloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
       387 ( 0.00%)  ???:openssl_rs::property::defn_cache::property_defn_cmp [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       362 ( 0.00%)  ???:openssl_rs::runtime::rcu::ossl_synchronize_rcu [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       360 ( 0.00%)  ???:<alloc::raw_vec::RawVecInner<_>>::reserve::do_reserve_and_handle::<alloc::alloc::Global> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       360 ( 0.00%)  ???:openssl_rs::runtime::thread::mutex_acquire [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       345 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:memcpy [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       344 ( 0.00%)  ./elf/./dl-find_object.h:_dl_find_object_from_map [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       333 ( 0.00%)  ./elf/../elf/dl-tls.c:_dl_allocate_tls_storage [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       332 ( 0.00%)  ./elf/./get-dynamic-info.h:dl_main

