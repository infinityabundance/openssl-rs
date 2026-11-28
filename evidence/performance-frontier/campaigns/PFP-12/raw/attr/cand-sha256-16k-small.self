--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-sha256-16k-small.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 2674150
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op sha256-16k --iters 16 --runs 1 (PID 491, part 1)
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
33,299,986 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                   file:function
--------------------------------------------------------------------------------
24,026,162 (72.15%)  ???:<openssl_rs::digest::sha2::Sha256Ctx as openssl_rs::digest::md32::Md32>::block [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 2,937,844 ( 8.82%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   683,498 ( 2.05%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   591,146 ( 1.78%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   433,653 ( 1.30%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
   384,680 ( 1.16%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   342,640 ( 1.03%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   294,010 ( 0.88%)  ./elf/./elf/do-rel.h:_dl_relocate_object
   274,208 ( 0.82%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   252,795 ( 0.76%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   226,640 ( 0.68%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   216,516 ( 0.65%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
   203,720 ( 0.61%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   166,600 ( 0.50%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   156,156 ( 0.47%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   156,097 ( 0.47%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   132,994 ( 0.40%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
   122,961 ( 0.37%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   110,386 ( 0.33%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    87,786 ( 0.26%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    85,470 ( 0.26%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    80,218 ( 0.24%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    74,646 ( 0.22%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    71,497 ( 0.21%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    68,240 ( 0.20%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    61,644 ( 0.19%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    51,933 ( 0.16%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
    51,271 ( 0.15%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    49,610 ( 0.15%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    46,456 ( 0.14%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
    39,398 ( 0.12%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    33,240 ( 0.10%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    32,985 ( 0.10%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    32,427 ( 0.10%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,616 ( 0.09%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc_zeroed
    28,400 ( 0.09%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    28,273 ( 0.08%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    27,897 ( 0.08%)  ???:openssl_rs::context::namemap::get_legacy_evp_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    22,894 ( 0.07%)  ???:openssl_rs::runtime::stack::sk_reserve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    22,308 ( 0.07%)  ./malloc/./malloc/arena.c:free
    21,249 ( 0.06%)  ???:<hashbrown::raw::RawTable<(alloc::vec::Vec<u8>, i32)>>::reserve_rehash::<hashbrown::map::make_hasher<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>::{closure#0}> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,190 ( 0.06%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,414 ( 0.06%)  ???:OBJ_NAME_cleanup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,104 ( 0.06%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/alloc.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    18,130 ( 0.05%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_realloc
    17,455 ( 0.05%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    14,592 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,462 ( 0.03%)  ./misc/../sysdeps/unix/sysv/linux/x86_64/syscall.S:syscall [/usr/lib/x86_64-linux-gnu/libc.so.6]
    11,289 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/alloc/layout.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    11,289 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/cmp.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    11,289 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/result.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    11,078 ( 0.03%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,360 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,276 ( 0.03%)  ./elf/./elf/dl-version.c:_dl_check_map_versions [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    10,105 ( 0.03%)  ./elf/./elf/dl-tunables.c:__GI___tunables_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     9,930 ( 0.03%)  ./elf/../sysdeps/generic/ldsodefs.h:do_lookup_x
     9,909 ( 0.03%)  ./string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S:__memcmp_avx2_movbe [/usr/lib/x86_64-linux-gnu/libc.so.6]
     9,828 ( 0.03%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,537 ( 0.03%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,436 ( 0.03%)  ???:openssl_rs::evp::digest::evp_md_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,065 ( 0.03%)  ./malloc/./malloc/arena.c:realloc
     8,239 ( 0.02%)  ???:__rustc::__rust_no_alloc_shim_is_unstable_v2 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,202 ( 0.02%)  ./elf/../sysdeps/generic/ldsodefs.h:_dl_relocate_object
     7,944 ( 0.02%)  ./elf/../sysdeps/generic/dl-protected.h:do_lookup_x
     7,821 ( 0.02%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,376 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,376 ( 0.02%)  ???:__rustc::__rust_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,068 ( 0.02%)  ???:<alloc::vec::Vec<openssl_rs::runtime::obj::NameRec> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<openssl_rs::runtime::obj::NameRec, core::iter::adapters::copied::Copied<core::iter::adapters::filter::Filter<core::slice::iter::Iter<openssl_rs::runtime::obj::NameRec>, openssl_rs::runtime::obj::OBJ_NAME_do_all::{closure#0}::{closure#0}>>>>::from_iter [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,880 ( 0.02%)  ./malloc/./malloc/malloc.c:alloc_perturb [/usr/lib/x86_64-linux-gnu/libc.so.6]
     5,807 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,807 ( 0.02%)  ???:__rustc::__rust_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,704 ( 0.02%)  ???:CRYPTO_zalloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,140 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/pal/unix/futex.rs:<std::sync::poison::condvar::Condvar>::notify_all
     4,987 ( 0.01%)  ???:openssl_rs::runtime::sparse_array::ossl_sa_set [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,878 ( 0.01%)  ./malloc/./malloc/arena.c:calloc
     4,806 ( 0.01%)  ???:openssl_rs::provider::digest::ossl_digest_default_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,708 ( 0.01%)  ???:OPENSSL_sk_new_null [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,509 ( 0.01%)  ???:OSSL_LIB_CTX_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,390 ( 0.01%)  ???:OPENSSL_LH_retrieve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,355 ( 0.01%)  ???:openssl_rs::property::store::ossl_method_store_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,209 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:__memset_avx2_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
     4,104 ( 0.01%)  ./nptl/./nptl/pthread_self.c:pthread_self [/usr/lib/x86_64-linux-gnu/libc.so.6]
     4,095 ( 0.01%)  ???:openssl_rs::property::strings::property_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,555 ( 0.01%)  ???:openssl_rs::context::namemap::get_legacy_md_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,446 ( 0.01%)  ???:openssl_rs::evp::c_allc::openssl_add_all_ciphers_int [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,379 ( 0.01%)  ???:openssl_rs::context::namemap::ossl_namemap_stored [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,300 ( 0.01%)  ???:openssl_rs::provider::digest::sha256_192_internal::freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,980 ( 0.01%)  ./elf/../sysdeps/x86/dl-cacheinfo.h:intel_check_word.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,872 ( 0.01%)  ./elf/./elf/dl-load.c:_dl_map_object_from_fd [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,759 ( 0.01%)  ???:OPENSSL_LH_new [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,708 ( 0.01%)  ???:openssl_rs::evp::digest::evp_md_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,655 ( 0.01%)  ./stdio-common/./stdio-common/printf_fp.c:__printf_fp_l [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,583 ( 0.01%)  ???:openssl_rs::context::namemap::ossl_namemap_doall_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,551 ( 0.01%)  ???:openssl_rs::property::store::ossl_method_store_cache_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,526 ( 0.01%)  ???:OBJ_NAME_do_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,479 ( 0.01%)  ???:CRYPTO_strndup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,474 ( 0.01%)  ???:<std::sync::once::Once>::call_once::<openssl_rs::provider::cipher::fill_exported_ciphers>::{closure#0} [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,432 ( 0.01%)  ???:__rustc::__rust_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,268 ( 0.01%)  ./elf/../bits/stdlib-bsearch.h:intel_check_word.constprop.0
     2,201 ( 0.01%)  ./elf/./elf/dl-deps.c:_dl_map_object_deps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,052 ( 0.01%)  ???:openssl_rs::evp::fetch::put_evp_method_in_store [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,960 ( 0.01%)  ???:openssl_rs::digest::md32::finalize::<openssl_rs::digest::sha2::Sha256Ctx> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,902 ( 0.01%)  ???:openssl_rs::context::lib_ctx_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,889 ( 0.01%)  ./malloc/./malloc/malloc.c:malloc_consolidate [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,781 ( 0.01%)  ./malloc/./malloc/malloc.c:unlink_chunk.constprop.0 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,728 ( 0.01%)  ???:OSSL_PARAM_set_int32 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,703 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/strlen-avx2.S:__strlen_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,620 ( 0.00%)  ???:OSSL_PARAM_set_uint64 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,561 ( 0.00%)  ???:openssl_rs::evp::fetch::inner_evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,540 ( 0.00%)  ???:OPENSSL_sk_dup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,479 ( 0.00%)  ./malloc/./malloc/arena.c:malloc
     1,423 ( 0.00%)  ./elf/./elf/dl-load.c:_dl_map_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,382 ( 0.00%)  ???:EVP_add_digest [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,372 ( 0.00%)  ./elf/./elf/dl-misc.c:_dl_name_match_p [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,370 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/strcmp-avx2.S:__strcmp_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,326 ( 0.00%)  ./nptl/./nptl/pthread_getspecific.c:pthread_getspecific@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,295 ( 0.00%)  ???:__rustc::__rust_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,249 ( 0.00%)  ./elf/./elf/rtld.c:dl_main [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,233 ( 0.00%)  ./stdio-common/./stdio-common/printf_fp.c:hack_digit [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,224 ( 0.00%)  ./elf/./elf/dl-runtime.c:_dl_fixup [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,219 ( 0.00%)  ./elf/./elf/dl-sym.c:do_sym [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,209 ( 0.00%)  ./elf/./elf/get-dynamic-info.h:_dl_map_object_from_fd
     1,170 ( 0.00%)  ./nptl/./nptl/pthread_mutex_lock.c:pthread_mutex_lock@@GLIBC_2.2.5 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,169 ( 0.00%)  ./elf/./elf/dl-tunables.h:__GI___tunables_init
     1,085 ( 0.00%)  ???:OPENSSL_LH_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,082 ( 0.00%)  ./elf/./elf/dl-cache.c:_dl_cache_libcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     1,066 ( 0.00%)  ???:CRYPTO_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,036 ( 0.00%)  ./elf/./elf/dl-error-skeleton.c:_dl_catch_exception [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,028 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/sync/atomic.rs:<std::sync::poison::condvar::Condvar>::notify_all
     1,028 ( 0.00%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sync/poison/condvar.rs:<std::sync::poison::condvar::Condvar>::notify_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,026 ( 0.00%)  ./stdlib/./stdlib/divrem.c:__mpn_divrem [/usr/lib/x86_64-linux-gnu/libc.so.6]
     1,026 ( 0.00%)  ???:openssl_rs::evp::method_store::ossl_method_construct_this [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,025 ( 0.00%)  ???:openssl_rs::property::defn_cache::ossl_prop_defn_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,020 ( 0.00%)  ???:EVP_DigestFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     1,005 ( 0.00%)  ???:openssl_rs::property::strings::ossl_property_string [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       990 ( 0.00%)  ./nptl/./nptl/pthread_mutex_unlock.c:__pthread_mutex_unlock_usercnt [/usr/lib/x86_64-linux-gnu/libc.so.6]
       963 ( 0.00%)  ./elf/./elf/dl-object.c:_dl_new_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       962 ( 0.00%)  ./stdio-common/./stdio-common/vfprintf-internal.c:__vfprintf_internal [/usr/lib/x86_64-linux-gnu/libc.so.6]
       897 ( 0.00%)  ./dlfcn/./dlfcn/dlerror.c:_dlerror_run [/usr/lib/x86_64-linux-gnu/libc.so.6]
       807 ( 0.00%)  ./elf/./elf/dl-load.c:open_path [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       800 ( 0.00%)  ???:EVP_MD_CTX_get_size_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       798 ( 0.00%)  ???:openssl_rs::evp::digest::set_legacy_nid [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       780 ( 0.00%)  ???:openssl_rs::digest::md32::update::<openssl_rs::digest::sha2::Sha256Ctx> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       776 ( 0.00%)  ./malloc/./malloc/malloc.c:ptmalloc_init.part.0
       760 ( 0.00%)  ???:sha_round.constprop.0 [/work/court/tmp/pfp12/bench_pfp12]
       756 ( 0.00%)  ???:openssl_rs::evp::fetch::construct_evp_method [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       744 ( 0.00%)  ???:<alloc::raw_vec::RawVec<alloc::vec::Vec<usize>>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       720 ( 0.00%)  ./elf/./elf/dl-hwcaps.c:_dl_important_hwcaps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       704 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:mempcpy [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       696 ( 0.00%)  ./elf/./elf/dl-load.c:open_verify.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       696 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strchr-sse2.S:index [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       679 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/memset-vec-unaligned-erms.S:memset [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       672 ( 0.00%)  ./dlfcn/./dlfcn/dlsym.c:dlsym@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
       672 ( 0.00%)  ???:<alloc::raw_vec::RawVec<usize>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       672 ( 0.00%)  ???:EVP_MD_up_ref [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       667 ( 0.00%)  ./elf/./elf/dl-error-skeleton.c:_dl_catch_error [/usr/lib/x86_64-linux-gnu/libc.so.6]
       652 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strlen-sse2.S:strlen [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       640 ( 0.00%)  ./elf/./elf/dl-sort-maps.c:dfs_traversal.part.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       632 ( 0.00%)  ???:openssl_rs::runtime::mem::default_malloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       628 ( 0.00%)  ./elf/./elf/dl-tunables.c:__tunable_get_val [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       620 ( 0.00%)  ./elf/./elf/dl-minimal-malloc.c:__minimal_malloc [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       615 ( 0.00%)  ./setjmp/../sysdeps/x86_64/setjmp.S:__sigsetjmp [/usr/lib/x86_64-linux-gnu/libc.so.6]
       606 ( 0.00%)  ./elf/./elf/dl-close.c:_dl_close_worker [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       592 ( 0.00%)  ./elf/./dl-map-segments.h:_dl_map_object_from_fd
       576 ( 0.00%)  ./stdlib/../sysdeps/x86_64/mul_1.S:__mpn_mul_1 [/usr/lib/x86_64-linux-gnu/libc.so.6]
       568 ( 0.00%)  ./elf/./elf/dl-sort-maps.c:_dl_sort_maps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       555 ( 0.00%)  ???:EVP_PKEY_asn1_get0 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       550 ( 0.00%)  ./libio/./libio/fileops.c:_IO_file_xsputn@@GLIBC_2.2.5 [/usr/lib/x86_64-linux-gnu/libc.so.6]
       540 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/strchr-avx2.S:__strchr_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
       521 ( 0.00%)  ./nptl/./nptl/pthread_once.c:pthread_once@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
       520 ( 0.00%)  ./elf/../sysdeps/x86_64/dl-trampoline.h:_dl_runtime_resolve_xsave [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       504 ( 0.00%)  ./elf/../sysdeps/x86/dl-cacheinfo.h:handle_intel.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
       497 ( 0.00%)  ???:openssl_rs::provider::seeding::ossl_prov_seeding_from_dispatch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       496 ( 0.00%)  ???:openssl_rs::provider::digest::ossl_default_provider_init [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
       486 ( 0.00%)  ???:EVP_MD_free [/work/court/tmp/pfp12/distribution/libcrypto.so.3]

