--------------------------------------------------------------------------------
Profile data file '/work/court/tmp/pfp12/attr/cand-sha256-16k-big.cg' (creator: callgrind-3.19.0)
--------------------------------------------------------------------------------
I1 cache: 
D1 cache: 
LL cache: 
Timerange: Basic block 0 - 5452924
Trigger: Program termination
Profiled target:  /work/court/tmp/pfp12/bench_pfp12 --lib /work/court/tmp/pfp12/distribution/libcrypto.so.3 --op sha256-16k --iters 64 --runs 1 (PID 494, part 1)
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
105,537,909 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
Ir                   file:function
--------------------------------------------------------------------------------
96,104,642 (91.06%)  ???:<openssl_rs::digest::sha2::Sha256Ctx as openssl_rs::digest::md32::Md32>::block [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
 2,937,844 ( 2.78%)  ???:openssl_rs::runtime::obj::name_find [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   683,498 ( 0.65%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   598,826 ( 0.57%)  ./malloc/./malloc/malloc.c:_int_free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   433,653 ( 0.41%)  ./elf/../sysdeps/x86_64/dl-machine.h:_dl_relocate_object
   384,680 ( 0.36%)  ./malloc/./malloc/malloc.c:_int_malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   342,640 ( 0.32%)  ???:OBJ_obj2txt [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   294,010 ( 0.28%)  ./elf/./elf/do-rel.h:_dl_relocate_object
   276,150 ( 0.26%)  ???:openssl_rs::context::namemap::namemap_add_name [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   257,535 ( 0.24%)  ./malloc/./malloc/malloc.c:malloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   226,640 ( 0.21%)  ./elf/./elf/dl-lookup.c:_dl_lookup_symbol_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   216,516 ( 0.21%)  ./elf/../sysdeps/generic/dl-new-hash.h:_dl_lookup_symbol_x
   209,060 ( 0.20%)  ???:<std::hash::random::DefaultHasher as core::hash::Hasher>::write [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   172,480 ( 0.16%)  ???:<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::vec::Vec<u8>> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
   158,676 ( 0.15%)  ./malloc/./malloc/malloc.c:free [/usr/lib/x86_64-linux-gnu/libc.so.6]
   156,097 ( 0.15%)  ./malloc/./malloc/malloc.c:calloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
   133,774 ( 0.13%)  ???:main [/work/court/tmp/pfp12/bench_pfp12]
   122,961 ( 0.12%)  ./elf/./elf/dl-reloc.c:_dl_relocate_object [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
   110,386 ( 0.10%)  ./elf/./elf/dl-lookup.c:check_match [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    89,166 ( 0.08%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    85,470 ( 0.08%)  ./malloc/./malloc/malloc.c:realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    80,218 ( 0.08%)  ./string/../sysdeps/x86_64/multiarch/../multiarch/strcmp-sse2.S:strcmp [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    75,504 ( 0.07%)  ???:CRYPTO_THREAD_unlock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    74,646 ( 0.07%)  ./malloc/./malloc/malloc.c:_int_realloc [/usr/lib/x86_64-linux-gnu/libc.so.6]
    72,637 ( 0.07%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/raw_vec/mod.rs:<alloc::raw_vec::RawVec<u8>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    68,240 ( 0.06%)  ???:<alloc::raw_vec::RawVecInner>::finish_grow [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    54,093 ( 0.05%)  ./string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:__memcpy_avx_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
    51,271 ( 0.05%)  ???:CRYPTO_THREAD_write_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    49,610 ( 0.05%)  ???:CRYPTO_strdup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    46,936 ( 0.04%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc
    39,398 ( 0.04%)  ???:OBJ_NAME_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    34,185 ( 0.03%)  ???:<hashbrown::map::HashMap<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>>::insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    34,047 ( 0.03%)  ???:OBJ_nid2obj [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    33,240 ( 0.03%)  ???:<alloc::raw_vec::RawVec<i32>>::grow_one [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    31,616 ( 0.03%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_alloc_zeroed
    30,595 ( 0.03%)  ???:CRYPTO_THREAD_read_lock [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    28,400 ( 0.03%)  ???:OPENSSL_sk_insert [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    28,348 ( 0.03%)  ???:openssl_rs::context::namemap::ossl_namemap_add_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    27,897 ( 0.03%)  ???:openssl_rs::context::namemap::get_legacy_evp_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    22,894 ( 0.02%)  ???:openssl_rs::runtime::stack::sk_reserve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    22,668 ( 0.02%)  ./malloc/./malloc/arena.c:free
    21,249 ( 0.02%)  ???:<hashbrown::raw::RawTable<(alloc::vec::Vec<u8>, i32)>>::reserve_rehash::<hashbrown::map::make_hasher<alloc::vec::Vec<u8>, i32, std::hash::random::RandomState>::{closure#0}> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    21,190 ( 0.02%)  ???:OBJ_NAME_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,536 ( 0.02%)  ???:openssl_rs::context::namemap::name2num_inner [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    20,464 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/alloc/src/alloc.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    20,414 ( 0.02%)  ???:OBJ_NAME_cleanup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    18,130 ( 0.02%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_realloc
    14,592 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    13,761 ( 0.01%)  ???:<alloc::vec::Vec<(u64, usize)>>::remove [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    13,442 ( 0.01%)  ./misc/../sysdeps/unix/sysv/linux/x86_64/syscall.S:syscall [/usr/lib/x86_64-linux-gnu/libc.so.6]
    13,200 ( 0.01%)  ???:openssl_rs::provider::digest::sha256_192_internal::freectx [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    11,469 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/alloc/layout.rs:<alloc::raw_vec::RawVecInner>::finish_grow
    11,469 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/cmp.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    11,469 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/core/src/result.rs:<alloc::raw_vec::RawVec<u8>>::grow_one
    11,196 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S:__memcmp_avx2_movbe [/usr/lib/x86_64-linux-gnu/libc.so.6]
    11,078 ( 0.01%)  ???:openssl_rs::property::defn_cache::property_defn_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,928 ( 0.01%)  ???:openssl_rs::evp::digest::evp_md_init_internal [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,471 ( 0.01%)  ???:openssl_rs::property::store::ossl_method_store_cache_get [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,360 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_realloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
    10,276 ( 0.01%)  ./elf/./elf/dl-version.c:_dl_check_map_versions [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    10,105 ( 0.01%)  ./elf/./elf/dl-tunables.c:__GI___tunables_init [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     9,930 ( 0.01%)  ./elf/../sysdeps/generic/ldsodefs.h:do_lookup_x
     9,828 ( 0.01%)  ???:OSSL_PARAM_locate [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,436 ( 0.01%)  ???:openssl_rs::evp::digest::evp_md_from_algorithm [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     9,065 ( 0.01%)  ./malloc/./malloc/arena.c:realloc
     8,650 ( 0.01%)  ???:OPENSSL_LH_retrieve [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,469 ( 0.01%)  ???:OSSL_LIB_CTX_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,299 ( 0.01%)  ???:__rustc::__rust_no_alloc_shim_is_unstable_v2 [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     8,202 ( 0.01%)  ./elf/../sysdeps/generic/ldsodefs.h:_dl_relocate_object
     7,944 ( 0.01%)  ./elf/../sysdeps/generic/dl-protected.h:do_lookup_x
     7,840 ( 0.01%)  ???:openssl_rs::digest::md32::finalize::<openssl_rs::digest::sha2::Sha256Ctx> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,564 ( 0.01%)  ???:CRYPTO_zalloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,436 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/alloc/unix.rs:__rustc::__rdl_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     7,436 ( 0.01%)  ???:__rustc::__rust_dealloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,068 ( 0.01%)  ???:<alloc::vec::Vec<openssl_rs::runtime::obj::NameRec> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<openssl_rs::runtime::obj::NameRec, core::iter::adapters::copied::Copied<core::iter::adapters::filter::Filter<core::slice::iter::Iter<openssl_rs::runtime::obj::NameRec>, openssl_rs::runtime::obj::OBJ_NAME_do_all::{closure#0}::{closure#0}>>>>::from_iter [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     6,040 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/sys/pal/unix/futex.rs:<std::sync::poison::condvar::Condvar>::notify_all
     6,001 ( 0.01%)  ???:openssl_rs::evp::fetch::inner_evp_generic_fetch [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,949 ( 0.01%)  ./string/../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:__memset_avx2_unaligned_erms [/usr/lib/x86_64-linux-gnu/libc.so.6]
     5,880 ( 0.01%)  ./malloc/./malloc/malloc.c:alloc_perturb [/usr/lib/x86_64-linux-gnu/libc.so.6]
     5,867 ( 0.01%)  /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/alloc.rs:__rustc::__rdl_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,867 ( 0.01%)  ???:__rustc::__rust_alloc [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     5,179 ( 0.00%)  ???:openssl_rs::context::namemap::ossl_namemap_stored [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,987 ( 0.00%)  ???:openssl_rs::runtime::sparse_array::ossl_sa_set [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,878 ( 0.00%)  ./malloc/./malloc/arena.c:calloc
     4,824 ( 0.00%)  ./nptl/./nptl/pthread_self.c:pthread_self [/usr/lib/x86_64-linux-gnu/libc.so.6]
     4,806 ( 0.00%)  ???:openssl_rs::provider::digest::ossl_digest_default_get_params [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,708 ( 0.00%)  ???:OPENSSL_sk_new_null [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,355 ( 0.00%)  ???:openssl_rs::property::store::ossl_method_store_add [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,095 ( 0.00%)  ???:openssl_rs::property::strings::property_hash [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     4,080 ( 0.00%)  ???:EVP_DigestFinal_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,555 ( 0.00%)  ???:openssl_rs::context::namemap::get_legacy_md_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,446 ( 0.00%)  ???:openssl_rs::evp::c_allc::openssl_add_all_ciphers_int [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,200 ( 0.00%)  ???:EVP_MD_CTX_get_size_ex [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,120 ( 0.00%)  ???:openssl_rs::digest::md32::update::<openssl_rs::digest::sha2::Sha256Ctx> [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     3,040 ( 0.00%)  ???:sha_round.constprop.0 [/work/court/tmp/pfp12/bench_pfp12]
     2,982 ( 0.00%)  ???:openssl_rs::context::lib_ctx_get_data [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,980 ( 0.00%)  ./elf/../sysdeps/x86/dl-cacheinfo.h:intel_check_word.constprop.0 [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,886 ( 0.00%)  ./nptl/./nptl/pthread_getspecific.c:pthread_getspecific@@GLIBC_2.34 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,872 ( 0.00%)  ./elf/./elf/dl-load.c:_dl_map_object_from_fd [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
     2,759 ( 0.00%)  ???:OPENSSL_LH_new [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,604 ( 0.00%)  ./stdio-common/./stdio-common/printf_fp.c:__printf_fp_l [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,583 ( 0.00%)  ???:openssl_rs::context::namemap::ossl_namemap_doall_names [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,570 ( 0.00%)  ./string/../sysdeps/x86_64/multiarch/strcmp-avx2.S:__strcmp_avx2 [/usr/lib/x86_64-linux-gnu/libc.so.6]
     2,526 ( 0.00%)  ???:OBJ_NAME_do_all [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,479 ( 0.00%)  ???:CRYPTO_strndup [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,474 ( 0.00%)  ???:<std::sync::once::Once>::call_once::<openssl_rs::provider::cipher::fill_exported_ciphers>::{closure#0} [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,432 ( 0.00%)  ???:__rustc::__rust_alloc_zeroed [/work/court/tmp/pfp12/distribution/libcrypto.so.3]
     2,268 ( 0.00%)  ./elf/../bits/stdlib-bsearch.h:intel_check_word.constprop.0
     2,201 ( 0.00%)  ./elf/./elf/dl-deps.c:_dl_map_object_deps [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]

