--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-aes128gcm-16k-small.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 12821486
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op aes128gcm-16k --iters 16 --runs 1 (PID 461, part 1)
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
308,849,137 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                    file:function
--------------------------------------------------------------------------------
152,148,160 (49.26%)  ???:openssl_rs::modes::gcm::crypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
144,091,440 (46.65%)  ???:AES_encrypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  4,190,840 ( 1.36%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    683,498 ( 0.22%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    648,671 ( 0.21%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
    525,342 ( 0.17%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    433,653 ( 0.14%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
    342,640 ( 0.11%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    333,734 ( 0.11%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    333,219 ( 0.11%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    294,010 ( 0.10%)  ./elf/./elf/do-rel.h:_dl_relocate_object
    267,698 ( 0.09%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    226,640 ( 0.07%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    216,516 ( 0.07%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
    214,816 ( 0.07%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    194,070 ( 0.06%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    175,035 ( 0.06%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
    156,097 ( 0.05%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    139,320 ( 0.05%)  ???:CRYPTO_gcm128_finish [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    136,120 ( 0.04%)  ???:CRYPTO_gcm128_aad [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    132,899 ( 0.04%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
    132,792 ( 0.04%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    125,180 ( 0.04%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    122,961 ( 0.04%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    121,004 ( 0.04%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    116,358 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    113,916 ( 0.04%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    110,386 ( 0.04%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     94,506 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     80,218 ( 0.03%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     76,960 ( 0.02%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     75,330 ( 0.02%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     73,782 ( 0.02%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
     66,949 ( 0.02%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     64,661 ( 0.02%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     56,384 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
     55,380 ( 0.02%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     53,240 ( 0.02%)  ???:openssl_rs::provider::cipher_gcm::aes_gcm_freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     50,627 ( 0.02%)  ???:openssl_rs::evp::cipher::evp_cipher_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     50,424 ( 0.02%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     45,745 ( 0.01%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     41,000 ( 0.01%)  ???:openssl_rs::provider::cipher_gcm::aes_block_encrypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     39,398 ( 0.01%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     35,500 ( 0.01%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     35,331 ( 0.01%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     33,240 ( 0.01%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     32,967 ( 0.01%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     31,847 ( 0.01%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     31,616 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc_zeroed
     30,195 ( 0.01%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     29,824 ( 0.01%)  ???:openssl_rs::runtime::stack::sk_reserve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     28,168 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_realloc
     27,897 ( 0.01%)  ???:openssl_rs::context::namemap::get_legacy_evp_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     25,932 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/alloc.rs:<alloc::raw_vec::RawVecInner>::finish_grow
     25,005 ( 0.01%)  ./malloc/./malloc/arena.c:free
     24,960 ( 0.01%)  ???:OSSL_PARAM_set_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     23,202 ( 0.01%)  ???:openssl_rs::property::store::ossl_method_store_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     23,167 ( 0.01%)  ???:openssl_rs::runtime::sparse_array::ossl_sa_set [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     21,249 ( 0.01%)  ???:<hashbrown::raw::RawTable<(alloc::vec::Vec<u8>, i32)>>::reserve_rehash::<hashbrown::map::make_hasher<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>::{closure#0}> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     21,186 ( 0.01%)  ./misc/../sysdeps/unix/sysv/linux/x86_64/syscall.S:syscall [/usr/lib/x86_64-linux-gnu/libc.so.6]
     20,414 ( 0.01%)  ???:OBJ_NAME_cleanup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     19,396 ( 0.01%)  ???:openssl_rs::evp::cipher::evp_cipher_cache_constants [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     19,318 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/strlen-avx2.S:__strlen_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     19,313 ( 0.01%)  ???:CRYPTO_zalloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     17,472 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S:__memcmp_avx2_movbe [/usr/lib/x86_64-linux-gnu/libc.so.6]
     17,262 ( 0.01%)  ???:OSSL_LIB_CTX_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     16,659 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:__memset_avx2_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
     16,096 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     14,922 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/alloc/layout.rs:<alloc::raw_vec::RawVecInner>::finish_grow
     14,922 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/cmp.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
     14,922 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/result.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
     14,635 ( 0.00%)  ???:CRYPTO_strndup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     14,592 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     14,100 ( 0.00%)  ???:OSSL_PARAM_set_uint64 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     14,084 ( 0.00%)  ./malloc/./malloc/arena.c:realloc
     13,249 ( 0.00%)  ???:openssl_rs::context::namemap::ossl_namemap_stored [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     13,123 ( 0.00%)  ???:OPENSSL_LH_retrieve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     12,560 ( 0.00%)  ???:openssl_rs::aes::aes_expand [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     11,926 ( 0.00%)  ???:OPENSSL_LH_new [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     11,547 ( 0.00%)  ???:openssl_rs::context::namemap::ossl_namemap_doall_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     11,460 ( 0.00%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_get_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     10,336 ( 0.00%)  ./malloc/./malloc/malloc.c:alloc_perturb [/usr/lib/x86_64-linux-gnu/libc.so.6]
     10,307 ( 0.00%)  ???:openssl_rs::evp::cipher_ctx::evp_cipher_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     10,276 ( 0.00%)  ./elf/./elf/dl-version.c:_dl_check_map_versions [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     10,105 ( 0.00%)  ./elf/./elf/dl-tunables.c:__GI___tunables_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      9,930 ( 0.00%)  ./elf/../sysdeps/generic/ldsodefs.h:do_lookup_x
      9,880 ( 0.00%)  ???:openssl_rs::evp::fetch::put_evp_method_in_store [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
      9,560 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/pal/unix/futex.rs:<std::sync::poison::condvar::Condvar>::notify_all
      9,480 ( 0.00%)  ???:__rustc::__rust_no_alloc_shim_is_unstable_v2 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
      8,800 ( 0.00%)  ???:openssl_rs::provider::cipher_gcm::aes_gcm_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]

