--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-chachapoly-64-big.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 5819877
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op chachapoly-64 --iters 1000 --runs 1 (PID 482, part 1)
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
36,598,738 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                  file:function
--------------------------------------------------------------------------------
6,255,000 (17.09%)  ???:openssl_rs::chacha::ChaCha20_ctr32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
4,190,840 (11.45%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
2,947,500 ( 8.05%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
1,682,990 ( 4.60%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
1,170,977 ( 3.20%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
1,087,500 ( 2.97%)  ???:openssl_rs::mac::poly1305::poly1305_blocks [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  940,000 ( 2.57%)  ???:openssl_rs::mac::poly1305::Poly1305_Final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  837,441 ( 2.29%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  693,440 ( 1.89%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  693,206 ( 1.89%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
  683,498 ( 1.87%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
  670,000 ( 1.83%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_aead_cipher [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  647,447 ( 1.77%)  ???:openssl_rs::evp::cipher_ctx::evp_cipher_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  607,938 ( 1.66%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  605,689 ( 1.65%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  552,500 ( 1.51%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_get_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  528,074 ( 1.44%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
  460,152 ( 1.26%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
  455,896 ( 1.25%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  433,653 ( 1.18%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
  414,296 ( 1.13%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
  373,750 ( 1.02%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_set_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  342,640 ( 0.94%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  332,849 ( 0.91%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  329,911 ( 0.90%)  ???:openssl_rs::property::store::ossl_method_store_cache_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  294,010 ( 0.80%)  ./elf/./elf/do-rel.h:_dl_relocate_object
  291,978 ( 0.80%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  278,355 ( 0.76%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
  273,735 ( 0.75%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  271,462 ( 0.74%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
  242,500 ( 0.66%)  ???:openssl_rs::provider::cipher::cipher_generic_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  235,486 ( 0.64%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  226,640 ( 0.62%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
  216,516 ( 0.59%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
  190,000 ( 0.52%)  ???:OSSL_PARAM_get_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  187,783 ( 0.51%)  ???:OPENSSL_LH_retrieve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  185,081 ( 0.51%)  ???:openssl_rs::evp::fetch::inner_evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  179,622 ( 0.49%)  ???:OSSL_LIB_CTX_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  178,750 ( 0.49%)  ???:EVP_CIPHER_CTX_ctrl [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  171,359 ( 0.47%)  ./string/../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:__memset_avx2_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
  163,750 ( 0.45%)  ???:aead_round.constprop.0 [/work/court/tmp/pfp12/bench_pfp12]
  161,700 ( 0.44%)  ???:OSSL_PARAM_set_uint64 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  157,500 ( 0.43%)  ???:openssl_rs::provider::cipher::chacha20_cipher [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  156,097 ( 0.43%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
  146,462 ( 0.40%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
  145,000 ( 0.40%)  ???:EVP_CIPHER_CTX_get_iv_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  140,000 ( 0.38%)  ???:EVP_DecryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  122,961 ( 0.34%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
  122,500 ( 0.33%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_initiv [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  121,036 ( 0.33%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  120,000 ( 0.33%)  ???:EVP_EncryptUpdate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  115,258 ( 0.31%)  ./string/../sysdeps/x86_64/multiarch/strlen-avx2.S:__strlen_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
  115,000 ( 0.31%)  ???:EVP_CIPHER_CTX_get_key_length [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  110,386 ( 0.30%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
  103,750 ( 0.28%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
  102,366 ( 0.28%)  ./misc/../sysdeps/unix/sysv/linux/x86_64/syscall.S:syscall [/usr/lib/x86_64-linux-gnu/libc.so.6]
   99,387 ( 0.27%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   97,608 ( 0.27%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_realloc
   95,573 ( 0.26%)  ???:CRYPTO_zalloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   90,000 ( 0.25%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_set_ctx_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   87,049 ( 0.24%)  ???:openssl_rs::context::namemap::ossl_namemap_stored [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   80,103 ( 0.22%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   80,000 ( 0.22%)  ???:openssl_rs::evp::fetch::evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   76,960 ( 0.21%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   76,064 ( 0.21%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
   75,330 ( 0.21%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   75,000 ( 0.20%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_update [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   68,484 ( 0.19%)  ./nptl/./nptl/pthread_getspecific.c:pthread_getspecific@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
   64,661 ( 0.18%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   61,794 ( 0.17%)  ./string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S:__memcmp_avx2_movbe [/usr/lib/x86_64-linux-gnu/libc.so.6]
   60,532 ( 0.17%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/alloc.rs:<alloc::raw_vec::RawVecInner>::finish_grow
   60,000 ( 0.16%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_newctx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   57,500 ( 0.16%)  ???:EVP_EncryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   57,500 ( 0.16%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_dinit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   57,500 ( 0.16%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_einit [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   55,776 ( 0.15%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   55,380 ( 0.15%)  ???:openssl_rs::provider::cipher::ossl_cipher_generic_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   52,992 ( 0.14%)  ./string/../sysdeps/x86_64/multiarch/strcmp-avx2.S:__strcmp_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
   52,500 ( 0.14%)  ???:EVP_DecryptFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   52,500 ( 0.14%)  ???:openssl_rs::provider::cipher::chacha20_initkey [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   52,104 ( 0.14%)  ???:openssl_rs::context::lib_ctx_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   50,627 ( 0.14%)  ???:openssl_rs::evp::cipher::evp_cipher_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   50,424 ( 0.14%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   48,804 ( 0.13%)  ./malloc/./malloc/arena.c:realloc
   46,460 ( 0.13%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/pal/unix/futex.rs:<std::sync::poison::condvar::Condvar>::notify_all
   45,000 ( 0.12%)  ???:openssl_rs::provider::cipher::chacha20_poly1305_final [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   39,765 ( 0.11%)  ./malloc/./malloc/arena.c:free
   39,398 ( 0.11%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   37,182 ( 0.10%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/alloc/layout.rs:<alloc::raw_vec::RawVecInner>::finish_grow
   37,182 ( 0.10%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/cmp.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
   37,182 ( 0.10%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/result.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
   37,160 ( 0.10%)  ./nptl/./nptl/pthread_self.c:pthread_self [/usr/lib/x86_64-linux-gnu/libc.so.6]
   36,834 ( 0.10%)  ???:EVP_CIPHER_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   35,500 ( 0.10%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   35,264 ( 0.10%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   34,986 ( 0.10%)  ???:openssl_rs::property::store::query_cmp [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   33,240 ( 0.09%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   31,847 ( 0.09%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   31,616 ( 0.09%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc_zeroed
   29,824 ( 0.08%)  ???:openssl_rs::runtime::stack::sk_reserve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   27,897 ( 0.08%)  ???:openssl_rs::context::namemap::get_legacy_evp_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   27,500 ( 0.08%)  ???:openssl_rs::property::store::query_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   26,351 ( 0.07%)  ./nptl/./nptl/pthread_once.c:pthread_once@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
   24,960 ( 0.07%)  ???:OSSL_PARAM_set_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   23,202 ( 0.06%)  ???:openssl_rs::property::store::ossl_method_store_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   23,167 ( 0.06%)  ???:openssl_rs::runtime::sparse_array::ossl_sa_set [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   21,249 ( 0.06%)  ???:<hashbrown::raw::RawTable<(alloc::vec::Vec<u8>, i32)>>::reserve_rehash::<hashbrown::map::make_hasher<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>::{closure#0}> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   20,414 ( 0.06%)  ???:OBJ_NAME_cleanup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   20,000 ( 0.05%)  ???:EVP_DecryptInit_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   20,000 ( 0.05%)  ???:EVP_EncryptInit_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   19,396 ( 0.05%)  ???:openssl_rs::evp::cipher::evp_cipher_cache_constants [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   17,500 ( 0.05%)  ???:openssl_rs::provider::cipher::chacha20_initiv [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   14,635 ( 0.04%)  ???:CRYPTO_strndup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   14,592 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   11,940 ( 0.03%)  ???:__rustc::__rust_no_alloc_shim_is_unstable_v2 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   11,926 ( 0.03%)  ???:OPENSSL_LH_new [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   11,547 ( 0.03%)  ???:openssl_rs::context::namemap::ossl_namemap_doall_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   10,612 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   10,612 ( 0.03%)  ???:__rustc::__rust_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   10,360 ( 0.03%)  ./malloc/./malloc/malloc.c:alloc_perturb [/usr/lib/x86_64-linux-gnu/libc.so.6]
   10,276 ( 0.03%)  ./elf/./elf/dl-version.c:_dl_check_map_versions [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   10,105 ( 0.03%)  ./elf/./elf/dl-tunables.c:__GI___tunables_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    9,930 ( 0.03%)  ./elf/../sysdeps/generic/ldsodefs.h:do_lookup_x
    9,880 ( 0.03%)  ???:openssl_rs::evp::fetch::put_evp_method_in_store [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    9,508 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    9,508 ( 0.03%)  ???:__rustc::__rust_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    9,292 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/sync/atomic.rs:<std::sync::poison::condvar::Condvar>::notify_all
    9,292 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sync/poison/condvar.rs:<std::sync::poison::condvar::Condvar>::notify_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    8,202 ( 0.02%)  ./elf/../sysdeps/generic/ldsodefs.h:_dl_relocate_object
    7,944 ( 0.02%)  ./elf/../sysdeps/generic/dl-protected.h:do_lookup_x
    7,282 ( 0.02%)  ???:OPENSSL_sk_new_null [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    7,205 ( 0.02%)  ???:OPENSSL_sk_dup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    6,972 ( 0.02%)  ???:__rustc::__rust_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    6,250 ( 0.02%)  ???:cipher_of [/work/court/tmp/pfp12/bench_pfp12]
    6,068 ( 0.02%)  ???:<alloc::vec::Vec<openssl_rs::runtime::obj::NameRec> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<openssl_rs::runtime::obj::NameRec, core::iter::adapters::copied::Copied<core::iter::adapters::filter::Filter<core::slice::iter::Iter<openssl_rs::runtime::obj::NameRec>, openssl_rs::runtime::obj::OBJ_NAME_do_all::{closure#0}::{closure#0}>>>>::from_iter [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    4,940 ( 0.01%)  ???:openssl_rs::evp::method_store::ossl_method_construct_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    4,939 ( 0.01%)  ???:openssl_rs::property::defn_cache::ossl_prop_defn_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    4,878 ( 0.01%)  ./malloc/./malloc/arena.c:calloc
    4,095 ( 0.01%)  ???:openssl_rs::property::strings::property_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    4,030 ( 0.01%)  ???:OSSL_PARAM_set_uint32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    3,865 ( 0.01%)  ???:openssl_rs::runtime::mem::default_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    3,744 ( 0.01%)  ???:CRYPTO_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    3,717 ( 0.01%)  ./malloc/./malloc/arena.c:malloc
    3,640 ( 0.01%)  ???:openssl_rs::evp::fetch::construct_evp_method [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    3,555 ( 0.01%)  ???:openssl_rs::context::namemap::get_legacy_md_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    3,446 ( 0.01%)  ???:openssl_rs::evp::c_allc::openssl_add_all_ciphers_int [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    3,284 ( 0.01%)  ???:openssl_rs::evp::cipher::set_legacy_nid [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    3,120 ( 0.01%)  ???:<alloc::raw_vec::RawVec<usize>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    2,980 ( 0.01%)  ./elf/../sysdeps/x86/dl-cacheinfo.h:intel_check_word.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    2,872 ( 0.01%)  ./elf/./elf/dl-load.c:_dl_map_object_from_fd [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    2,639 ( 0.01%)  ???:openssl_rs::runtime::mem::default_free [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    2,604 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/strchr-avx2.S:__strchr_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    2,526 ( 0.01%)  ???:OBJ_NAME_do_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    2,500 ( 0.01%)  ???:EVP_chacha20_poly1305 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    2,499 ( 0.01%)  ./stdio-common/./stdio-common/printf_fp.c:__printf_fp_l [/usr/lib/x86_64-linux-gnu/libc.so.6]
    2,474 ( 0.01%)  ???:<std::sync::once::Once>::call_once::<openssl_rs::provider::cipher::fill_exported_ciphers>::{closure#0} [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    2,432 ( 0.01%)  ???:__rustc::__rust_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    2,340 ( 0.01%)  ???:EVP_CIPHER_free [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    2,292 ( 0.01%)  ./malloc/./malloc/malloc.c:malloc_consolidate [/usr/lib/x86_64-linux-gnu/libc.so.6]
    2,268 ( 0.01%)  ./elf/../bits/stdlib-bsearch.h:intel_check_word.constprop.0
    2,210 ( 0.01%)  ???:openssl_rs::provider::ossl_provider_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    2,201 ( 0.01%)  ./elf/./elf/dl-deps.c:_dl_map_object_deps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    1,821 ( 0.00%)  ./malloc/./malloc/malloc.c:unlink_chunk.constprop.0 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    1,423 ( 0.00%)  ./elf/./elf/dl-load.c:_dl_map_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    1,382 ( 0.00%)  ???:EVP_add_digest [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    1,372 ( 0.00%)  ./elf/./elf/dl-misc.c:_dl_name_match_p [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    1,300 ( 0.00%)  ???:openssl_rs::provider::cipher::set_size_param [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    1,249 ( 0.00%)  ./elf/./elf/rtld.c:dl_main [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    1,224 ( 0.00%)  ./elf/./elf/dl-runtime.c:_dl_fixup [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    1,219 ( 0.00%)  ./elf/./elf/dl-sym.c:do_sym [/usr/lib/x86_64-linux-gnu/libc.so.6]
    1,209 ( 0.00%)  ./elf/./elf/get-dynamic-info.h:_dl_map_object_from_fd
    1,170 ( 0.00%)  ./nptl/./nptl/pthread_mutex_lock.c:pthread_mutex_lock@@GLIBC_2.2.5 [/usr/lib/x86_64-linux-gnu/libc.so.6]
    1,169 ( 0.00%)  ./elf/./elf/dl-tunables.h:__GI___tunables_init
    1,131 ( 0.00%)  ???:openssl_rs::evp::algorithm::algorithm_do_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    1,085 ( 0.00%)  ???:OPENSSL_LH_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    1,082 ( 0.00%)  ./elf/./elf/dl-cache.c:_dl_cache_libcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    1,077 ( 0.00%)  ./stdio-common/./stdio-common/printf_fp.c:hack_digit [/usr/lib/x86_64-linux-gnu/libc.so.6]
    1,036 ( 0.00%)  ./elf/./elf/dl-error-skeleton.c:_dl_catch_exception [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    1,005 ( 0.00%)  ???:openssl_rs::property::strings::ossl_property_string [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
      990 ( 0.00%)  ./nptl/./nptl/pthread_mutex_unlock.c:__pthread_mutex_unlock_usercnt [/usr/lib/x86_64-linux-gnu/libc.so.6]
      963 ( 0.00%)  ./elf/./elf/dl-object.c:_dl_new_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      962 ( 0.00%)  ./stdio-common/./stdio-common/vfprintf-internal.c:__vfprintf_internal [/usr/lib/x86_64-linux-gnu/libc.so.6]
      897 ( 0.00%)  ./dlfcn/./dlfcn/dlerror.c:_dlerror_run [/usr/lib/x86_64-linux-gnu/libc.so.6]
      894 ( 0.00%)  ./stdlib/./stdlib/divrem.c:__mpn_divrem [/usr/lib/x86_64-linux-gnu/libc.so.6]
      807 ( 0.00%)  ./elf/./elf/dl-load.c:open_path [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      776 ( 0.00%)  ./malloc/./malloc/malloc.c:ptmalloc_init.part.0
      744 ( 0.00%)  ???:<alloc::raw_vec::RawVec<alloc::vec::Vec<usize>>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
      720 ( 0.00%)  ./elf/./elf/dl-hwcaps.c:_dl_important_hwcaps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      704 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:mempcpy [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      696 ( 0.00%)  ./elf/./elf/dl-load.c:open_verify.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      696 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strchr-sse2.S:index [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      679 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/memset-vec-unaligned-erms.S:memset [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      672 ( 0.00%)  ./dlfcn/./dlfcn/dlsym.c:dlsym@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
      667 ( 0.00%)  ./elf/./elf/dl-error-skeleton.c:_dl_catch_error [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      640 ( 0.00%)  ./elf/./elf/dl-sort-maps.c:dfs_traversal.part.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      628 ( 0.00%)  ./elf/./elf/dl-tunables.c:__tunable_get_val [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      620 ( 0.00%)  ./elf/./elf/dl-minimal-malloc.c:__minimal_malloc [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      615 ( 0.00%)  ./setjmp/../sysdeps/x86_64/setjmp.S:__sigsetjmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
      606 ( 0.00%)  ./elf/./elf/dl-close.c:_dl_close_worker [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]

