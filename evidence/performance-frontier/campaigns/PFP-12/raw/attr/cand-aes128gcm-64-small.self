--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-aes128gcm-64-small.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 4011229
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op aes128gcm-64 --iters 250 --runs 1 (PID 455, part 1)
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
43,025,223 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                   file:function
--------------------------------------------------------------------------------
13,145,184 (30.55%)  ???:AES_encrypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 9,306,336 (21.63%)  ???:openssl_rs::modes::gcm::crypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 4,190,840 ( 9.74%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 2,173,392 ( 5.05%)  ???:CRYPTO_gcm128_finish [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 2,123,472 ( 4.94%)  ???:CRYPTO_gcm128_aad [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   830,544 ( 1.93%)  ???:openssl_rs::provider::cipher_gcm::aes_gcm_freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   723,423 ( 1.68%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   720,838 ( 1.68%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   683,498 ( 1.59%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   525,342 ( 1.22%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   433,653 ( 1.01%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
   379,870 ( 0.88%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   342,640 ( 0.80%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   337,194 ( 0.78%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   332,954 ( 0.77%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   294,010 ( 0.68%)  ./elf/./elf/do-rel.h:_dl_relocate_object
   272,048 ( 0.63%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   260,084 ( 0.60%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   226,640 ( 0.53%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   216,516 ( 0.50%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
   203,406 ( 0.47%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   199,563 ( 0.46%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   195,936 ( 0.46%)  ???:openssl_rs::aes::aes_expand [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   194,845 ( 0.45%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   178,776 ( 0.42%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_get_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   171,336 ( 0.40%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   161,563 ( 0.38%)  ???:openssl_rs::evp::cipher_ctx::evp_cipher_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   156,097 ( 0.36%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   144,868 ( 0.34%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   143,806 ( 0.33%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   137,280 ( 0.32%)  ???:openssl_rs::provider::cipher_gcm::aes_gcm_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   136,100 ( 0.32%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
   122,961 ( 0.29%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   120,963 ( 0.28%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   116,698 ( 0.27%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   110,386 ( 0.26%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   107,654 ( 0.25%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
    94,536 ( 0.22%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_set_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    88,011 ( 0.20%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    87,984 ( 0.20%)  ???:openssl_rs::provider::cipher_gcm::gcm_cipher_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    82,279 ( 0.19%)  ???:openssl_rs::property::store::ossl_method_store_cache_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    80,218 ( 0.19%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    76,960 ( 0.18%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    75,330 ( 0.18%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    64,661 ( 0.15%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    61,056 ( 0.14%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
    57,539 ( 0.13%)  ./string/../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:__memset_avx2_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
    55,806 ( 0.13%)  ???:OSSL_LIB_CTX_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    55,380 ( 0.13%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    54,587 ( 0.13%)  ???:OPENSSL_LH_retrieve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    50,627 ( 0.12%)  ???:openssl_rs::evp::cipher::evp_cipher_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    50,424 ( 0.12%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    49,140 ( 0.11%)  ???:OSSL_PARAM_set_uint64 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    48,735 ( 0.11%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    47,424 ( 0.11%)  ???:OSSL_PARAM_get_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    46,257 ( 0.11%)  ???:openssl_rs::evp::fetch::inner_evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    44,616 ( 0.10%)  ???:EVP_CIPHER_CTX_ctrl [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    42,094 ( 0.10%)  ./string/../sysdeps/x86_64/multiarch/strlen-avx2.S:__strlen_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    40,872 ( 0.09%)  ???:aead_round.constprop.0 [/work/court/tmp/pfp12/bench_pfp12]
    40,458 ( 0.09%)  ./misc/../sysdeps/unix/sysv/linux/x86_64/syscall.S:syscall [/usr/lib/x86_64-linux-gnu/libc.so.6]
    39,398 ( 0.09%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    37,417 ( 0.09%)  ???:CRYPTO_zalloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    36,344 ( 0.08%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_realloc
    36,192 ( 0.08%)  ???:EVP_CIPHER_CTX_get_iv_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,500 ( 0.08%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    35,329 ( 0.08%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    34,944 ( 0.08%)  ???:EVP_DecryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    33,240 ( 0.08%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,847 ( 0.07%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,772 ( 0.07%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/alloc.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    31,616 ( 0.07%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc_zeroed
    30,769 ( 0.07%)  ???:openssl_rs::context::namemap::ossl_namemap_stored [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    29,952 ( 0.07%)  ???:EVP_EncryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    29,824 ( 0.07%)  ???:openssl_rs::runtime::stack::sk_reserve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    28,704 ( 0.07%)  ???:EVP_CIPHER_CTX_get_key_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    28,509 ( 0.07%)  ./malloc/./malloc/arena.c:free
    28,026 ( 0.07%)  ./string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S:__memcmp_avx2_movbe [/usr/lib/x86_64-linux-gnu/libc.so.6]
    27,897 ( 0.06%)  ???:openssl_rs::context::namemap::get_legacy_evp_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    24,960 ( 0.06%)  ???:OSSL_PARAM_set_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,712 ( 0.06%)  ???:CRYPTO_gcm128_setiv [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,202 ( 0.05%)  ???:openssl_rs::property::store::ossl_method_store_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    23,167 ( 0.05%)  ???:openssl_rs::runtime::sparse_array::ossl_sa_set [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,249 ( 0.05%)  ???:<hashbrown::raw::RawTable<(alloc::vec::Vec<u8>, i32)>>::reserve_rehash::<hashbrown::map::make_hasher<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>::{closure#0}> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,768 ( 0.05%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,414 ( 0.05%)  ???:OBJ_NAME_cleanup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    19,968 ( 0.05%)  ???:openssl_rs::evp::fetch::evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    19,708 ( 0.05%)  ./nptl/./nptl/pthread_getspecific.c:pthread_getspecific@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    19,396 ( 0.05%)  ???:openssl_rs::evp::cipher::evp_cipher_cache_constants [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    19,032 ( 0.04%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_dinit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    19,032 ( 0.04%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_einit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    18,426 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/alloc/layout.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    18,426 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/cmp.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    18,426 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/result.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    18,336 ( 0.04%)  ???:openssl_rs::context::lib_ctx_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    18,320 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/pal/unix/futex.rs:<std::sync::poison::condvar::Condvar>::notify_all
    18,172 ( 0.04%)  ./malloc/./malloc/arena.c:realloc
    17,472 ( 0.04%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_stream_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    15,401 ( 0.04%)  ./string/../sysdeps/x86_64/multiarch/strcmp-avx2.S:__strcmp_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    15,288 ( 0.04%)  ???:openssl_rs::params::get_string_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,648 ( 0.03%)  ./nptl/./nptl/pthread_self.c:pthread_self [/usr/lib/x86_64-linux-gnu/libc.so.6]
    14,635 ( 0.03%)  ???:CRYPTO_strndup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,592 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,352 ( 0.03%)  ???:EVP_EncryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,352 ( 0.03%)  ???:openssl_rs::provider::cipher_gcm::aes128gcm_newctx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    13,104 ( 0.03%)  ???:EVP_DecryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    12,792 ( 0.03%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_cipher_final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    12,168 ( 0.03%)  ???:openssl_rs::provider::cipher_gcm::sm4_gcm_cipher_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,926 ( 0.03%)  ???:OPENSSL_LH_new [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,547 ( 0.03%)  ???:openssl_rs::context::namemap::ossl_namemap_doall_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,608 ( 0.02%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_stream_final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,570 ( 0.02%)  ???:EVP_CIPHER_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,336 ( 0.02%)  ./malloc/./malloc/malloc.c:alloc_perturb [/usr/lib/x86_64-linux-gnu/libc.so.6]
    10,276 ( 0.02%)  ./elf/./elf/dl-version.c:_dl_check_map_versions [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    10,105 ( 0.02%)  ./elf/./elf/dl-tunables.c:__GI___tunables_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    10,064 ( 0.02%)  ???:__rustc::__rust_no_alloc_shim_is_unstable_v2 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,930 ( 0.02%)  ./elf/../sysdeps/generic/ldsodefs.h:do_lookup_x
     9,880 ( 0.02%)  ???:openssl_rs::evp::fetch::put_evp_method_in_store [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,736 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,736 ( 0.02%)  ???:OSSL_PARAM_set_octet_string [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,736 ( 0.02%)  ???:__rustc::__rust_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,722 ( 0.02%)  ???:openssl_rs::property::store::query_cmp [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,202 ( 0.02%)  ./elf/../sysdeps/generic/ldsodefs.h:_dl_relocate_object
     7,944 ( 0.02%)  ./elf/../sysdeps/generic/dl-protected.h:do_lookup_x
     7,632 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,632 ( 0.02%)  ???:__rustc::__rust_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,591 ( 0.02%)  ./nptl/./nptl/pthread_once.c:pthread_once@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     7,282 ( 0.02%)  ???:OPENSSL_sk_new_null [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,205 ( 0.02%)  ???:OPENSSL_sk_dup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,864 ( 0.02%)  ???:openssl_rs::property::store::query_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,068 ( 0.01%)  ???:<alloc::vec::Vec<openssl_rs::runtime::obj::NameRec> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<openssl_rs::runtime::obj::NameRec, core::iter::adapters::copied::Copied<core::iter::adapters::filter::Filter<core::slice::iter::Iter<openssl_rs::runtime::obj::NameRec>, openssl_rs::runtime::obj::OBJ_NAME_do_all::{closure#0}::{closure#0}>>>>::from_iter [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,616 ( 0.01%)  ???:OSSL_PARAM_get_octet_string [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,616 ( 0.01%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_aad_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,992 ( 0.01%)  ???:EVP_DecryptInit_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,992 ( 0.01%)  ???:EVP_EncryptInit_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,940 ( 0.01%)  ???:openssl_rs::evp::method_store::ossl_method_construct_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,939 ( 0.01%)  ???:openssl_rs::property::defn_cache::ossl_prop_defn_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,878 ( 0.01%)  ./malloc/./malloc/arena.c:calloc
     4,095 ( 0.01%)  ???:openssl_rs::property::strings::property_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,030 ( 0.01%)  ???:OSSL_PARAM_set_uint32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,744 ( 0.01%)  ???:CRYPTO_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,744 ( 0.01%)  ???:openssl_rs::provider::cipher_gcm::ossl_gcm_setiv [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,719 ( 0.01%)  ./malloc/./malloc/arena.c:malloc
     3,664 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/sync/atomic.rs:<std::sync::poison::condvar::Condvar>::notify_all
     3,664 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sync/poison/condvar.rs:<std::sync::poison::condvar::Condvar>::notify_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,640 ( 0.01%)  ???:openssl_rs::evp::fetch::construct_evp_method [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,555 ( 0.01%)  ???:openssl_rs::context::namemap::get_legacy_md_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,446 ( 0.01%)  ???:openssl_rs::evp::c_allc::openssl_add_all_ciphers_int [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,284 ( 0.01%)  ???:openssl_rs::evp::cipher::set_legacy_nid [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,120 ( 0.01%)  ???:<alloc::raw_vec::RawVec<usize>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,120 ( 0.01%)  ???:openssl_rs::provider::cipher_gcm::aes_block_encrypt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,980 ( 0.01%)  ./elf/../sysdeps/x86/dl-cacheinfo.h:intel_check_word.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,872 ( 0.01%)  ./elf/./elf/dl-load.c:_dl_map_object_from_fd [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,661 ( 0.01%)  ./stdio-common/./stdio-common/printf_fp.c:__printf_fp_l [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,604 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/strchr-avx2.S:__strchr_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,596 ( 0.01%)  ???:__rustc::__rust_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,526 ( 0.01%)  ???:OBJ_NAME_do_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,474 ( 0.01%)  ???:<std::sync::once::Once>::call_once::<openssl_rs::provider::cipher::fill_exported_ciphers>::{closure#0} [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,432 ( 0.01%)  ???:__rustc::__rust_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,340 ( 0.01%)  ???:EVP_CIPHER_free [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,268 ( 0.01%)  ./elf/../bits/stdlib-bsearch.h:intel_check_word.constprop.0
     2,210 ( 0.01%)  ???:openssl_rs::provider::ossl_provider_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,201 ( 0.01%)  ./elf/./elf/dl-deps.c:_dl_map_object_deps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,989 ( 0.00%)  ???:openssl_rs::runtime::mem::default_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,979 ( 0.00%)  ./malloc/./malloc/malloc.c:malloc_consolidate [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,801 ( 0.00%)  ./malloc/./malloc/malloc.c:unlink_chunk.constprop.0 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,423 ( 0.00%)  ./elf/./elf/dl-load.c:_dl_map_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,382 ( 0.00%)  ???:EVP_add_digest [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,372 ( 0.00%)  ./elf/./elf/dl-misc.c:_dl_name_match_p [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,300 ( 0.00%)  ???:openssl_rs::provider::cipher::set_size_param [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,249 ( 0.00%)  ./elf/./elf/rtld.c:dl_main [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,233 ( 0.00%)  ./stdio-common/./stdio-common/printf_fp.c:hack_digit [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,224 ( 0.00%)  ./elf/./elf/dl-runtime.c:_dl_fixup [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,219 ( 0.00%)  ./elf/./elf/dl-sym.c:do_sym [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,209 ( 0.00%)  ./elf/./elf/get-dynamic-info.h:_dl_map_object_from_fd
     1,170 ( 0.00%)  ./nptl/./nptl/pthread_mutex_lock.c:pthread_mutex_lock@@GLIBC_2.2.5 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,169 ( 0.00%)  ./elf/./elf/dl-tunables.h:__GI___tunables_init
     1,131 ( 0.00%)  ???:openssl_rs::evp::algorithm::algorithm_do_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,085 ( 0.00%)  ???:OPENSSL_LH_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,082 ( 0.00%)  ./elf/./elf/dl-cache.c:_dl_cache_libcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,036 ( 0.00%)  ./elf/./elf/dl-error-skeleton.c:_dl_catch_exception [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,014 ( 0.00%)  ./stdlib/./stdlib/divrem.c:__mpn_divrem [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,005 ( 0.00%)  ???:openssl_rs::property::strings::ossl_property_string [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       990 ( 0.00%)  ./nptl/./nptl/pthread_mutex_unlock.c:__pthread_mutex_unlock_usercnt [/usr/lib/x86_64-linux-gnu/libc.so.6]
       963 ( 0.00%)  ./elf/./elf/dl-object.c:_dl_new_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       962 ( 0.00%)  ./stdio-common/./stdio-common/vfprintf-internal.c:__vfprintf_internal [/usr/lib/x86_64-linux-gnu/libc.so.6]
       936 ( 0.00%)  ???:cipher_of [/work/court/tmp/pfp12/bench_pfp12]
       897 ( 0.00%)  ./dlfcn/./dlfcn/dlerror.c:_dlerror_run [/usr/lib/x86_64-linux-gnu/libc.so.6]
       807 ( 0.00%)  ./elf/./elf/dl-load.c:open_path [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       776 ( 0.00%)  ./malloc/./malloc/malloc.c:ptmalloc_init.part.0
       763 ( 0.00%)  ???:openssl_rs::runtime::mem::default_free [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       744 ( 0.00%)  ???:<alloc::raw_vec::RawVec<alloc::vec::Vec<usize>>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       720 ( 0.00%)  ./elf/./elf/dl-hwcaps.c:_dl_important_hwcaps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       704 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:mempcpy [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       696 ( 0.00%)  ./elf/./elf/dl-load.c:open_verify.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       696 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strchr-sse2.S:index [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]

