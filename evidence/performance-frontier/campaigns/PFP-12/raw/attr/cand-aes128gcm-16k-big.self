--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-aes128gcm-16k-big.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 44426088
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op aes128gcm-16k --iters 64 --runs 1 (PID 464, part 1)
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
1,199,333,945 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                    file:function
--------------------------------------------------------------------------------
608,592,640 (50.74%)  ???:openssl_rs::modes::gcm::crypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
576,365,760 (48.06%)  ???:AES_encrypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  4,190,840 ( 0.35%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    683,498 ( 0.06%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    664,031 ( 0.06%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
    557,280 ( 0.05%)  ???:CRYPTO_gcm128_finish [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    544,480 ( 0.05%)  ???:CRYPTO_gcm128_aad [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    525,342 ( 0.04%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    433,653 ( 0.04%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
    343,214 ( 0.03%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    342,640 ( 0.03%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    332,336 ( 0.03%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    302,310 ( 0.03%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    294,010 ( 0.02%)  ./elf/./elf/do-rel.h:_dl_relocate_object
    281,978 ( 0.02%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    226,640 ( 0.02%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    226,576 ( 0.02%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    216,516 ( 0.02%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
    212,960 ( 0.02%)  ???:openssl_rs::provider::cipher_gcm::aes_gcm_freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    180,075 ( 0.02%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
    164,000 ( 0.01%)  ???:openssl_rs::provider::cipher_gcm::aes_block_encrypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    156,097 ( 0.01%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    152,900 ( 0.01%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    140,712 ( 0.01%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    133,559 ( 0.01%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
    122,961 ( 0.01%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    121,998 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    120,932 ( 0.01%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    120,276 ( 0.01%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    110,386 ( 0.01%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     99,066 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     93,229 ( 0.01%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     80,742 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
     80,218 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     78,111 ( 0.01%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     76,960 ( 0.01%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     75,330 ( 0.01%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     64,661 ( 0.01%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     57,344 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
     55,380 ( 0.00%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     50,627 ( 0.00%)  ???:openssl_rs::evp::cipher::evp_cipher_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     50,424 ( 0.00%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     50,240 ( 0.00%)  ???:openssl_rs::aes::aes_expand [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     45,840 ( 0.00%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_get_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     42,075 ( 0.00%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     41,387 ( 0.00%)  ???:openssl_rs::evp::cipher_ctx::evp_cipher_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     39,398 ( 0.00%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     36,207 ( 0.00%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     35,500 ( 0.00%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     35,200 ( 0.00%)  ???:openssl_rs::provider::cipher_gcm::aes_gcm_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     34,803 ( 0.00%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     33,240 ( 0.00%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     31,847 ( 0.00%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]

