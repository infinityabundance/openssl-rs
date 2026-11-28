--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-chachapoly-16k-big.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 4389361
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op chachapoly-16k --iters 64 --runs 1 (PID 488, part 1)
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
72,263,603 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                   file:function
--------------------------------------------------------------------------------
49,768,320 (68.87%)  ???:openssl_rs::chacha::ChaCha20_ctr32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 9,372,000 (12.97%)  ???:openssl_rs::mac::poly1305::poly1305_blocks [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 4,190,840 ( 5.80%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   683,498 ( 0.95%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   677,237 ( 0.94%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   536,426 ( 0.74%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   433,653 ( 0.60%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
   343,214 ( 0.47%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   342,640 ( 0.47%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   333,156 ( 0.46%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   294,010 ( 0.41%)  ./elf/./elf/do-rel.h:_dl_relocate_object
   285,018 ( 0.39%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   255,590 ( 0.35%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   226,640 ( 0.31%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   226,576 ( 0.31%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   216,516 ( 0.30%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
   188,640 ( 0.26%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   180,075 ( 0.25%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   156,097 ( 0.22%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   152,900 ( 0.21%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   151,272 ( 0.21%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   133,603 ( 0.18%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
   131,156 ( 0.18%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   125,838 ( 0.17%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   122,961 ( 0.17%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   121,013 ( 0.17%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   110,386 ( 0.15%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   102,106 ( 0.14%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    93,229 ( 0.13%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    86,379 ( 0.12%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    84,262 ( 0.12%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
    80,103 ( 0.11%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    76,960 ( 0.11%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    75,330 ( 0.10%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    64,661 ( 0.09%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    60,160 ( 0.08%)  ???:openssl_rs::mac::poly1305::Poly1305_Final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    57,344 ( 0.08%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
    55,380 ( 0.08%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    50,627 ( 0.07%)  ???:openssl_rs::evp::cipher::evp_cipher_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    50,424 ( 0.07%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    42,880 ( 0.06%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_aead_cipher [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    42,075 ( 0.06%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    41,387 ( 0.06%)  ???:openssl_rs::evp::cipher_ctx::evp_cipher_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    39,398 ( 0.05%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    36,207 ( 0.05%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,500 ( 0.05%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,419 ( 0.05%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,360 ( 0.05%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_get_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    33,240 ( 0.05%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    32,088 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_realloc
    31,847 ( 0.04%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,616 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc_zeroed
    29,824 ( 0.04%)  ???:openssl_rs::runtime::stack::sk_reserve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    27,897 ( 0.04%)  ???:openssl_rs::context::namemap::get_legacy_evp_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    27,772 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/alloc.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    25,725 ( 0.04%)  ./malloc/./malloc/arena.c:free
    25,182 ( 0.03%)  ???:OSSL_LIB_CTX_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    25,146 ( 0.03%)  ./misc/../sysdeps/unix/sysv/linux/x86_64/syscall.S:syscall [/usr/lib/x86_64-linux-gnu/libc.so.6]
    24,960 ( 0.03%)  ???:OSSL_PARAM_set_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,998 ( 0.03%)  ./string/../sysdeps/x86_64/multiarch/strlen-avx2.S:__strlen_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    23,939 ( 0.03%)  ./string/../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:__memset_avx2_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
    23,920 ( 0.03%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_set_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,202 ( 0.03%)  ???:openssl_rs::property::store::ossl_method_store_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,167 ( 0.03%)  ???:openssl_rs::runtime::sparse_array::ossl_sa_set [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,033 ( 0.03%)  ???:CRYPTO_zalloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,643 ( 0.03%)  ???:OPENSSL_LH_retrieve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,300 ( 0.03%)  ???:OSSL_PARAM_set_uint64 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,249 ( 0.03%)  ???:<hashbrown::raw::RawTable<(alloc::vec::Vec<u8>, i32)>>::reserve_rehash::<hashbrown::map::make_hasher<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>::{closure#0}> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,031 ( 0.03%)  ???:openssl_rs::property::store::ossl_method_store_cache_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,414 ( 0.03%)  ???:OBJ_NAME_cleanup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    19,695 ( 0.03%)  ./string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S:__memcmp_avx2_movbe [/usr/lib/x86_64-linux-gnu/libc.so.6]
    19,396 ( 0.03%)  ???:openssl_rs::evp::cipher::evp_cipher_cache_constants [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    18,336 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    16,849 ( 0.02%)  ???:openssl_rs::context::namemap::ossl_namemap_stored [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    16,122 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/alloc/layout.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    16,122 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/cmp.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    16,122 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/result.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    16,044 ( 0.02%)  ./malloc/./malloc/arena.c:realloc
    15,520 ( 0.02%)  ???:openssl_rs::provider::cipher::cipher_generic_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,635 ( 0.02%)  ???:CRYPTO_strndup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,592 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    12,160 ( 0.02%)  ???:OSSL_PARAM_get_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,926 ( 0.02%)  ???:OPENSSL_LH_new [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,921 ( 0.02%)  ???:openssl_rs::evp::fetch::inner_evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,547 ( 0.02%)  ???:openssl_rs::context::namemap::ossl_namemap_doall_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,440 ( 0.02%)  ???:EVP_CIPHER_CTX_ctrl [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,360 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/pal/unix/futex.rs:<std::sync::poison::condvar::Condvar>::notify_all
    10,480 ( 0.01%)  ???:aead_round.constprop.0 [/work/court/tmp/pfp12/bench_pfp12]
    10,360 ( 0.01%)  ./malloc/./malloc/malloc.c:alloc_perturb [/usr/lib/x86_64-linux-gnu/libc.so.6]
    10,276 ( 0.01%)  ./elf/./elf/dl-version.c:_dl_check_map_versions [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    10,105 ( 0.01%)  ./elf/./elf/dl-tunables.c:__GI___tunables_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    10,080 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_cipher [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,984 ( 0.01%)  ???:openssl_rs::context::lib_ctx_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,930 ( 0.01%)  ./elf/../sysdeps/generic/ldsodefs.h:do_lookup_x
     9,880 ( 0.01%)  ???:openssl_rs::evp::fetch::put_evp_method_in_store [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,600 ( 0.01%)  ???:__rustc::__rust_no_alloc_shim_is_unstable_v2 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,280 ( 0.01%)  ???:EVP_CIPHER_CTX_get_iv_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,080 ( 0.01%)  ./nptl/./nptl/pthread_self.c:pthread_self [/usr/lib/x86_64-linux-gnu/libc.so.6]
     8,960 ( 0.01%)  ???:EVP_DecryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,272 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,272 ( 0.01%)  ???:__rustc::__rust_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,202 ( 0.01%)  ./elf/../sysdeps/generic/ldsodefs.h:_dl_relocate_object
     7,944 ( 0.01%)  ./elf/../sysdeps/generic/dl-protected.h:do_lookup_x
     7,840 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_initiv [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,680 ( 0.01%)  ???:EVP_EncryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,644 ( 0.01%)  ./nptl/./nptl/pthread_getspecific.c:pthread_getspecific@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     7,360 ( 0.01%)  ???:EVP_CIPHER_CTX_get_key_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,282 ( 0.01%)  ???:OPENSSL_sk_new_null [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,205 ( 0.01%)  ???:OPENSSL_sk_dup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,168 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,168 ( 0.01%)  ???:__rustc::__rust_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,640 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,221 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/strcmp-avx2.S:__strcmp_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     6,068 ( 0.01%)  ???:<alloc::vec::Vec<openssl_rs::runtime::obj::NameRec> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<openssl_rs::runtime::obj::NameRec, core::iter::adapters::copied::Copied<core::iter::adapters::filter::Filter<core::slice::iter::Iter<openssl_rs::runtime::obj::NameRec>, openssl_rs::runtime::obj::OBJ_NAME_do_all::{closure#0}::{closure#0}>>>>::from_iter [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,760 ( 0.01%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_set_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,120 ( 0.01%)  ???:openssl_rs::evp::fetch::evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,940 ( 0.01%)  ???:openssl_rs::evp::method_store::ossl_method_construct_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,939 ( 0.01%)  ???:openssl_rs::property::defn_cache::ossl_prop_defn_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,878 ( 0.01%)  ./malloc/./malloc/arena.c:calloc
     4,800 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,095 ( 0.01%)  ???:openssl_rs::property::strings::property_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,074 ( 0.01%)  ???:EVP_CIPHER_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,030 ( 0.01%)  ???:OSSL_PARAM_set_uint32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,840 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_newctx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,744 ( 0.01%)  ???:CRYPTO_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,717 ( 0.01%)  ./malloc/./malloc/arena.c:malloc
     3,680 ( 0.01%)  ???:EVP_EncryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,680 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_dinit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,680 ( 0.01%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_einit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,640 ( 0.01%)  ???:openssl_rs::evp::fetch::construct_evp_method [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,555 ( 0.00%)  ???:openssl_rs::context::namemap::get_legacy_md_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,446 ( 0.00%)  ???:openssl_rs::evp::c_allc::openssl_add_all_ciphers_int [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,360 ( 0.00%)  ???:EVP_DecryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,360 ( 0.00%)  ???:openssl_rs::provider::cipher::chacha20_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,284 ( 0.00%)  ???:openssl_rs::evp::cipher::set_legacy_nid [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,120 ( 0.00%)  ???:<alloc::raw_vec::RawVec<usize>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,980 ( 0.00%)  ./elf/../sysdeps/x86/dl-cacheinfo.h:intel_check_word.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,951 ( 0.00%)  ./nptl/./nptl/pthread_once.c:pthread_once@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,880 ( 0.00%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,872 ( 0.00%)  ./elf/./elf/dl-load.c:_dl_map_object_from_fd [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,661 ( 0.00%)  ./stdio-common/./stdio-common/printf_fp.c:__printf_fp_l [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,604 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/strchr-avx2.S:__strchr_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,526 ( 0.00%)  ???:OBJ_NAME_do_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,474 ( 0.00%)  ???:<std::sync::once::Once>::call_once::<openssl_rs::provider::cipher::fill_exported_ciphers>::{closure#0} [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,432 ( 0.00%)  ???:__rustc::__rust_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,340 ( 0.00%)  ???:EVP_CIPHER_free [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,292 ( 0.00%)  ./malloc/./malloc/malloc.c:malloc_consolidate [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,292 ( 0.00%)  ???:__rustc::__rust_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,272 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/sync/atomic.rs:<std::sync::poison::condvar::Condvar>::notify_all
     2,272 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sync/poison/condvar.rs:<std::sync::poison::condvar::Condvar>::notify_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,268 ( 0.00%)  ./elf/../bits/stdlib-bsearch.h:intel_check_word.constprop.0
     2,226 ( 0.00%)  ???:openssl_rs::property::store::query_cmp [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,210 ( 0.00%)  ???:openssl_rs::provider::ossl_provider_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,201 ( 0.00%)  ./elf/./elf/dl-deps.c:_dl_map_object_deps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,821 ( 0.00%)  ./malloc/./malloc/malloc.c:unlink_chunk.constprop.0 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,760 ( 0.00%)  ???:openssl_rs::property::store::query_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,525 ( 0.00%)  ???:openssl_rs::runtime::mem::default_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,423 ( 0.00%)  ./elf/./elf/dl-load.c:_dl_map_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,382 ( 0.00%)  ???:EVP_add_digest [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,372 ( 0.00%)  ./elf/./elf/dl-misc.c:_dl_name_match_p [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]

