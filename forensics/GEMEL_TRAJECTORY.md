# Gemel trajectory (generated projection)

Generated from the local `.gemel` store by
`forensics/tools/render_gemel_trajectory.sh` inside the FRF tooling
container. Gemel's store is **not** Git-tracked (Gemel ships a
`.gemel/.gitignore` containing `*`), so this projection, Gemel's own
`exchange/` namespace, and the identities quoted below are what travel
in Git. See `docs/DECISIONS.md` D17.

## `gemel log`

```
C65  The name map lands: crypto/core_namemap.c, 584 lines, as src/context/namemap.rs -- all ten internal functions over a real STACK_OF(NAMES). It adds NO export, so what moves is slot 4: RT-LIBCTX goes from 79 to 81 observations, comparing the slot's presence, stability, per-context distinctness and difference from the object's own address. Five of the eighteen index slots are filled now. Three behaviours are the ones a plausible reading gets wrong. (1) The comparison is a BIT MASK, not a case fold: ossl_ht_strcase is tgt[i] = ~0x20 & src[i], which folds case for ASCII letters and does something else for every other byte -- '!' (0x21) and 0x01 both map to 0x01, so two names differing only by bit 5 in a non-letter position are the same name to this map. Reproduced rather than normalised. The same macro caps the key at 63 bytes, so two names sharing a 63-byte prefix are one name; the explicit-length form keys on a prefix instead. (2) NDEBUG is defined in the admitted build -- read from the authority's own configdata.pm -- and that decides a branch: the two ossl_asserts here are OPENSSL_die in a debug build and a plain (x) != 0 under NDEBUG, so a NULL namemap REACHES the ERR_R_PASSED_NULL_PARAMETER raise rather than aborting the process. The opposite assumption turns a raise into a process death. (3) The conflict refusal is ORDER-DEPENDENT, and the first run of the unit test found it: the test asserted that add_names(nm, 0, "fresh:known", ':') is refused because 'known' belongs to another number, and it FAILED because the call is ACCEPTED -- the number being built starts as the caller's, a part only sets it when that part resolves to an existing number, so 'fresh' resolves to 0 and changes nothing, 'known' then resolves to its number, and no comparison against 'fresh' ever happens. The conflict is reachable only between a part that comes after one that already resolved. Both halves are asserted now and the behaviour is documented, because it is what a later reader would otherwise 'fix'. Also reproduced: max_number is stored on every successful addition, so appending an alias can LOWER it -- the only reader asks whether it is zero, so the oddity is invisible and still reproduced; and the stored flag makes ossl_namemap_free a no-op, with the context's destructor clearing it first. The legacy pre-population is deferred WHOLE: running the four RSA-PSS aliases alone would make the emptiness guard false, and a later phase adding the legacy load would then skip it entirely, silently leaving the legacy names out of a map already numbered wrongly. The container is not the authority's hashtable -- lookups are identical and the CRYPTO_R_TOO_MANY_NAMES collision failure is unreachable, recorded as a residual with one allow(dead_code) function that says why a raise which cannot happen is not called. crypto/core_namemap.c is now in gen_err_raise_sites.py's covered set, and regeneration was purely additive: 767 sites to 772, nothing removed or changed. One of the five is the first site in the table whose reason is chosen at run time, and the generator classified it dynamic_reason rather than guessing. A gap this exposed is recorded rather than fixed here: err_sites.rs and err-raise-sites.json are generated but are in neither evidence_determinism.py's generator list nor its comparison list, so CI would not notice stale coordinates -- and they are contract, since ERR_get_error_all reports them. The FRF store is recreated: 44 receipts, 88 challenges, 5 claims, graph_verified.
    state state.412c476ce38dc12187f435df98bc50405ca8de34b3766952768ae734198cdd45 -> state.b540f7ab44c3e9e622e85c2fa981110f901ade7885d7eb5f101033dd1664f29f
C64  All nine exports of self_test.h and indicator.h land in src/selftest/{mod,indicator}.rs from crypto/self_test_core.c and crypto/indicator_core.c. RT-SELFTEST observes them in 71 observations with zero residuals on the first run, and slots 12 and 22 join RT-LIBCTX's filled_slots list, taking that court from 75 to 79. The probe IS the callback, because both surfaces are callback plumbing and there is nothing else to observe; four things came out of that. (1) The array's entries ALIAS the object's own fields: self_test_setparams builds st-phase/st-type/st-desc with OSSL_PARAM_construct_utf8_string(key, st->field, 0), which stores the ADDRESS of the field rather than a copy, and OSSL_SELF_TEST_onend reassigns all three fields to None AFTER calling the callback without rebuilding the array -- so the same array reports Pass inside the callback and None afterwards. The probe stashes the array pointer inside the callback and reads through it again after the call, which is the only way a C caller can see the aliasing at all, and it is why this court is worth writing rather than unit-testing. (2) onend treats anything other than 1 as a failure, including 0 and negative values. (3) oncorrupt_byte's answer is the callback's inverted: the callback answering 0 flips the first byte and the call answers 1. (4) The object's callback is the one passed to OSSL_SELF_TEST_new, not the context's, so the probe sets them to different things and checks which one ran -- an implementation that read the context's callback from inside onbegin would pass a probe that only ever set both to the same function. The prototype court found a real defect the runtime court could not: an earlier revision declared OSSL_SELF_TEST_get_callback's second parameter as *mut *mut c_void, but the authority's is OSSL_CALLBACK **, a pointer to a FUNCTION POINTER. Both spellings work at run time for any caller that passes correctly sized storage, so RT-SELFTEST passed 71 observations against the wrong prototype while ABI-PROTOTYPE reported it as one of two type mismatches and named the canonical form; OSSL_INDICATOR_get_callback had the same defect. That is the blind spot D98 and D103 each recorded from the other direction: a runtime court compares answers, and a prototype wrong only in the SHAPE of an output parameter has no answer to compare. Two safety divergences are recorded rather than reproduced: oncorrupt_byte with a NULL bytes and a refusing callback answers 0 where the authority writes through the NULL, and both setters store nothing and both getters answer NULL when the slot cannot be read. The indicator half is storage without a caller, and that is stated rather than implied: nothing invokes the indicator callback, because the code that reports an indicator is provider-side. The FRF store is recreated: 44 receipts, 88 challenges, 5 claims, graph_verified.
    state state.0d74316188bac1d3fa066deb9e32ce6859deceee93435daa9339bf8ea0048f30 -> state.412c476ce38dc12187f435df98bc50405ca8de34b3766952768ae734198cdd45
C63  Slot 19 of the library context lands, with the two accessors that read it. The slot is crypto/thread/internal.c's ossl_threads_ctx_new/_free -- two counters, a mutex and a condition variable -- created by context_init, which now fails the whole context if the slot cannot be built, and released by context_deinit_objs in the authority's OPENSSL_NO_THREAD_POOL position between the two callback slots and child_provider. RT-THREADDATA observes it in 39 observations with zero residuals on the first run, and RT-LIBCTX grows from 73 to 75 as slot 19 joins its filled_slots list, which is the mechanism 6.6a described for exactly this. The two accessors look trivial and are not: everything about them is in the plural. The counter is per CONTEXT, so setting it on one must not move another's and the default context is one of the contexts rather than a special case; a NULL context resolves through the library context default chain, so the same call answers differently once this thread installs a default, which the probe observes by installing one, reading through NULL, restoring and reading again; and the value is stored verbatim with no range check, so UINT64_MAX is legal to set and to read back and zero is a value rather than unset -- a uint64_t that was clipped, or a setter that refused a large value, would be a plausible reading and a wrong one. The pool's primitives come with it because ossl_threads_ctx_new allocates a mutex and a condition variable and FAILS if either cannot be built, so they are the constructor's and cannot be deferred with it. src/runtime/thread.rs gains ossl_crypto_mutex_* and ossl_crypto_condvar_* over the same primitives, with two design points recorded: the mutex is not recursive, because PTHREAD_MUTEX_DEFAULT deadlocks on re-lock and std::sync::Mutex would instead error or panic, so it parks on a flag and deadlocks as the authority does; and a condition variable is paired with one mutex with the pairing made explicit, bound on first wait, because Rust's Condvar::wait needs the guard of the mutex it waits on while the C API creates the two independently -- every use in the authority pairs one condvar with one mutex for its lifetime, so this makes an invariant the authority relies on explicit and a mismatched pair is reported rather than becoming a lost wakeup. Nothing waits on the condition variable yet: it is created and released because the constructor creates and releases it. 6.6e is split, and the reason is a file rather than a distance: the counter pair needs only the slot, but OPENSSL_thread_stop/_ex need crypto/initthread.c's per-thread event-handler table and OPENSSL_atexit needs DSO_dsobyaddr to pin its handler's object, so those three become 6.6e-ii with both dependencies named and context_deinit's missing ossl_ctx_thread_stop call is the line it unblocks. The FRF store is recreated: 43 receipts, 86 challenges, 5 claims, graph_verified.
    state state.5856f8075027b3886decc069f9bdb4e7538257aaa1ba8f14bb00dcac5ae826e4 -> state.0d74316188bac1d3fa066deb9e32ce6859deceee93435daa9339bf8ea0048f30
C62  OSSL_LIB_CTX lands with the seven of its ten exports that need nothing else: new, free, get0_global_default, set0_default, get_data, get_conf_diagnostics, set_conf_diagnostics. RT-LIBCTX observes all of it -- 73 observations, zero residuals, first run -- covering three behaviours that are in no documentation: the default chain, in which a NULL context resolves to this thread's slot and OSSL_LIB_CTX_set0_default returns the PREVIOUS default while installing a new one; the free rules, where two of the three arguments are no-ops (NULL, and whatever the calling thread's default resolves to, which includes the global default and any context the thread installed itself) so a caller that frees its own thread default and keeps using it is not reading released memory; and the index registry, whose shape a caller can see through the exported function alone. The probe was run against the authority before any Rust was written, and the reconnaissance changed the design: the switch answers a pointer for eighteen indices and NULL for 7, 8, 9, 13 and everything past 22, index 19 answers a pointer (so this profile has the thread pool compiled in), and index 21 answers the ADDRESS OF A FIELD inside the object, so it is non-NULL for a context whose compression stack is empty -- which is also the arm most likely to be simplified into returning the field's value and answering NULL for every context, so it has a unit test of its own. Three of the ten exports are not writable yet and the split is by dependency, not convenience: new_from_dispatch needs the core BIO (6.6c), new_child needs ossl_provider_init_as_child (6.8) and is what sets ischild, load_config is a one-line forward to CONF_modules_load_file_ex (6.10). So 6.6 becomes 6.6a-g with each dependency named. Seventeen of the eighteen live index slots belong to a later stratum and the arms answer NULL until their owner lands: that gap is invisible to every symbol ledger, because a field that was never filled is not a symbol, which is the a2d_ASN1_OBJECT defect class one layer down. It is made visible three ways -- the per-slot owner table in docs/PHASE-6-SUBPHASES.md and in the module documentation with the closure rule stated in both, the probe printing libctx.slots.live/.filled/.deferred so the transcript states the scope of its own table, and nothing filled with a placeholder, because the value is a live object of a type a later stratum owns and a one-byte allocation would satisfy the observation while saying something false about the object. An unfilled slot may not be observed either: comparing a missing subsystem is the ledger's business, not a court's. Two further deferrals are named in the code rather than left as absences: context_deinit's ossl_ctx_thread_stop waits for 6.6e, and ossl_do_ex_data_init's per-context registry stays the process-global Phase 3 deferral it already was. The FRF store is recreated: 42 receipts, 84 challenges, 5 claims, graph_verified.
    state state.d277ea2db6f2934071fc81ed3dae9d99e821742661da2c8855dbe43b70eb37be -> state.5856f8075027b3886decc069f9bdb4e7538257aaa1ba8f14bb00dcac5ae826e4
C61  The divergence RT-PARAM reported was not a divergence. courts/phase6/rt_param_probe.c filled a sixteen-byte buffer with 0xaa and handed it to OSSL_PARAM_construct_utf8_string(..., buf, 0), which measures the buffer with strlen, so the terminator was whatever followed the array on the stack. Measured on the committed source: -O0 answers 22 for both sides, -O1/-O2/-O3 answer 16 for both, and the capture the receipt was bound to recorded 24 against 22. The residual a0eaeb5b2946497400a7b63f1d0d78efe4f90ae91ee24ef1e910c7ce19551a7 was the optimizer's frame compared against itself. The probe now terminates its own buffer and observes two declared lengths, so the court compares strlen+1 of a declared object rather than a number a frame produced. Added forensics/tools/probe_hygiene.py: it compiles every courts/phase<N>/*_probe.c against each side at -O0/-O1/-O2, runs each twice, and fails on level drift (uninitialised or out-of-bounds reads) or run drift (nondeterminism no court can compare). It was falsified against the pre-fix text before being trusted and reports both signatures on it, including 22 then 17 from two executions of the same -O0 binary. A sanitizer cannot be used: ASan reserves a terabyte-scale shadow and aborts under the court's own RLIMIT_DATA cap, which stays. The store was recreated from clean, which is what the README already requires for a rebuilt candidate and what a probe edit also requires: the previous store held transcripts from a probe source that no longer existed, and that is why this court's stdout-first-line mutant could not adjudicate. 41 receipts, 82 challenges, 5 claims, all 37 runtime courts isolated on both axes. Also fixed phase6_courts.py declaring GENERATOR as phase5_courts.py, which no gate compared.
    state state.cac3350896083fe525a9e628021df2eb3d42b7eb670dec564a2c8194a6c208dc -> state.d277ea2db6f2934071fc81ed3dae9d99e821742661da2c8855dbe43b70eb37be
C47  RT-PARAM is 1161 observations on each side with zero residuals: the descriptor as a matrix of accessor x width x signedness x type, the setters' NULL-buffer size queries, the string and pointer forms, BIGNUM, dup/merge/free, text allocation and the builder. It found two defects in the new code and one in Phase 5, whose signed encoders accepted five destinations the authority refuses. Phase 5's seal gains a correction section, RT-BN gains 860 observations, and phase_state.py gains the Phase 6 evidence registry that makes run_courts.py run this stratum at all.
    state state.d13b7eabc061c85276030b14eb654fbef4f46fa0686967a514af9befb195a54b -> state.cac3350896083fe525a9e628021df2eb3d42b7eb670dec564a2c8194a6c208dc
C46  56 + 3 + 2 + 20 exports across src/params/mod.rs, dup.rs, from_text.rs and build.rs. Both prototype planes now read every one, after two instrument fixes: fifteen exports returning a struct by value were checked by neither plane, because an unclassified class plane skipped the type plane as well, and a macro_rules scalar push put a metavariable in a type position, which the court refuses by design. RT-PARAM does not exist yet, so the surface is implemented and uncourted and 6.5 stays in progress.
    state state.2c91cb79897ee2f92df8e2f0b3ccc6f03266c6a5a8fa4305132bcec6924d4e4c -> state.d13b7eabc061c85276030b14eb654fbef4f46fa0686967a514af9befb195a54b
C45  Two new Phase 3 courts measure the branch a consumer who never embeds is in. Thirteen zero-length divergences, a CRYPTO_realloc(addr,0) release hidden behind its own NULL return, a candidate-only out-of-bounds read in CRYPTO_memdup, two CRYPTO_set/get_mem_functions dispatch gaps, one invented constant name, and the params.c raise-site macro plane in the generator.
    state state.bfb0e5c1af845a49043f8ce28ad5c6dbfcec3f15833292a131788ef6254e6ea1 -> state.2c91cb79897ee2f92df8e2f0b3ccc6f03266c6a5a8fa4305132bcec6924d4e4c
C44  The ownership atlas is reconciled against the ledgers in both directions, the prototype court judges every implemented export, and the 47 obligations that reconciliation exposed are discharged or handed on
    state state.e37e2612ce18778003bd493480dcb5338c3f108bf61f91ee0ef5bad6f970e415 -> state.bfb0e5c1af845a49043f8ce28ad5c6dbfcec3f15833292a131788ef6254e6ea1
C43  PEM_proc_type and PEM_dek_info implemented and courted; the 25 remaining pem.h exports handed on with the dependency each waits for; open obligations reach zero and the phase-5 seal is rewritten from the ledgers
    state state.a2d15e14bf47e8737740783806df1b10919f4749b3013836b191ee6a80c109cf -> state.e37e2612ce18778003bd493480dcb5338c3f108bf61f91ee0ef5bad6f970e415
C42  SMIME_crlf_copy and i2d_ASN1_bio_stream implemented and courted; SMIME_crlf_copy removed from the Phase 12 hand-off set because its reason was a file rather than a dependency; PEM_write_bio_ASN1_stream handed to Phase 7 for its base64 BIO; the authority unbounded unwind loop recorded as D-MIME-1
    state state.967494a4aa380bf6a345ea55e84fb1e9901f4b0fc94df3a9048bd9a777d4d786 -> state.a2d15e14bf47e8737740783806df1b10919f4749b3013836b191ee6a80c109cf
C41  ASN1_item_print implemented and courth; the EMBED stack-slot defect the court found; the v3_utl.c raise coordinates and the phase 4 to phase 5 hand-off reconciliation
    state state.06d7e5252a13d7ebf03db77fe2b9f15e1776e93adb37cc181713b660e8df098b -> state.967494a4aa380bf6a345ea55e84fb1e9901f4b0fc94df3a9048bd9a777d4d786
C40  Subphase 5.8 half landed: crypto/asn1/bio_asn1.c (BIO_f_asn1, the four BIO_asn1_ prefix/suffix controls) and the BIO_new_NDEF half of bio_ndef.c, with its two prefix and two suffix callbacks. The filter is a state machine, not a wrapper: seven states because each write may have to emit a prefix, a header, some content and then more content on the next call, with a partial-write cursor for the header and a declared length that bounds how much content passes through before a fresh header. Added RT-BIO-ASN1 with 114 observations, and it found one defect, which crashed the candidate. The authority tests the three setup calls as ; I wrote them as , which multiplies by zero on SUCCESS, so BIO_new_NDEF took the error path on every call and freed the support block a second time - the state machine had already handed it to the BIO, whose destroy callback releases it. glibc reported a double free in tcache and the probe dumped core. The lesson is the one this stratum keeps teaching from the other direction: a faithful transcription of three lines would have been right, and the tidy-looking rewrite was wrong. Fixed to the authority shape. Implemented libcrypto exports 921 -> 927; Phase 5 open obligations 37 -> 30.
    state state.5ef38880d6673996c7801ac89d7043d9e6423aac626fa6098879d1e59c8d4458 -> state.06d7e5252a13d7ebf03db77fe2b9f15e1776e93adb37cc181713b660e8df098b
C39  ASN1_str2mask lands with the asn1_str2tag table it depends on. The two other exports of asn1_gen.c, ASN1_generate_v3 and ASN1_generate_nconf, are handed to Phase 11: both take an X509V3_CTX pointer, and ASN1_generate_nconf constructs one through the X509V3_set_nconf macro even on its null-CONF path, so neither can be written without a structure this stratum does not own. The fifty-four-name table lives in this module rather than beside the generator because ASN1_str2mask needs it now and Phase 11 will need the same table; a second copy is a duplicated registry. RT-ASN1-STR grew to 5831 observations with thirty-eight str2mask cases covering accepted names, the DIR special case that shadows the table, the lowercase and mixed-case forms, the two separators, empty and separator-only lists, unknown names before and after an accepted one, the six modifier names that the ASN1_GEN_FLAG range test rejects, and the partial mask a refusal leaves behind. All pass on the first run, which is the first time in this stratum that a module written from a reading of the source needed no correction. Implemented libcrypto exports 920 -> 921; Phase 5 open obligations 39 -> 37.
    state state.6b6aa057e39335f1cca6e8705e88fe15c60b8cf5b0db243627ded409f5e2585b -> state.5ef38880d6673996c7801ac89d7043d9e6423aac626fa6098879d1e59c8d4458
C38  Completed subphase 5.6: a_strex.c lands, so the string surface has no open export left except ASN1_str2mask, which belongs to asn1_gen.c. ASN1_STRING_print_ex and ASN1_STRING_print_ex_fp are one implementation with two sinks, and ASN1_STRING_to_UTF8 is the same tag2nbyte table read for a different purpose. The char_type table is the authority generated charmap.h artifact rather than a re-derivation of charmap.pl, and RT-ASN1-STR is extended to pin it behaviourally: every one of the 256 byte values printed under RFC2253, under ESC_MSB alone and under ESC_QUOTE, plus twenty-three flag sets over thirty string types. RT-ASN1-STR is now 5714 observations and passes. One finding, and it is about the probe rather than the crate: do_dump builds a stack ASN1_TYPE whose value.ptr is the ASN1_STRING, so with DUMP_DER the encoder reinterprets that pointer according to the string type - for BOOLEAN that is the low byte of a heap address, so the authority and the candidate each printed their own address and the comparison was invalid rather than failing. The probe now restricts DUMP_DER to types where the union member really is the string, and the restriction is written down where it is applied. Also fixed two clippy findings on the way (collapsible match, and i2d_ASN1_TYPE taking a const pointer). Implemented libcrypto exports 917 -> 920; Phase 5 open obligations 42 -> 39.
    state state.f0d8841f77ad4b4159c5a699b212bf169331d68da2827ed44291f170fac6935c -> state.6b6aa057e39335f1cca6e8705e88fe15c60b8cf5b0db243627ded409f5e2585b
C37  Implemented 14 of the 20 exports of subphase 5.6: a_print.c (ASN1_PRINTABLE_type, ASN1_UNIVERSALSTRING_to_string, ASN1_STRING_print), a_mbstr.c (ASN1_mbstring_copy, ASN1_mbstring_ncopy), a_strnid.c (the 28-row standard table, the runtime stack that shadows it, ASN1_STRING_TABLE_add/get/cleanup, ASN1_STRING_set_by_NID, the three global-mask accessors) and t_pkey.c (ASN1_buf_print, ASN1_bn_print). Two exports are handed on rather than written: ASN1_add_oid_module to Phase 6 and ASN1_add_stable_module to Phase 11, because both register a CONF module through CONF_module_add, which Phase 4 handed to Phase 6 since only the module registry constructs a CONF_MODULE. Added RT-ASN1-STR: 581 observations, passing after three fixes it found. (1) ASN1_PRINT_MAX_INDENT is 128, not 80 - I wrote 80 from the ASCII line width instead of reading t_pkey.c, and with an indent of 81 the authority writes 81 spaces where the candidate truncated to 80. That is exactly the transcription class D33 forbids and the reason the constant now names its source. (2) ASN1_STRING_set_default_mask_asc must reject MASK: with an empty remainder; I accepted it because strtoul accepts it as zero. (3) The court exposed a Phase-3 decision rather than a Phase-5 defect: OPENSSL_INIT_LOAD_CONFIG was refused with ERR_R_INIT_FAIL because the authority action was said to be non-empty, but the authority reaches CONF_modules_load_file_ex with DEFAULT_CONF_MFLAGS, which carries CONF_MFLAGS_IGNORE_MISSING_FILE, so on a profile with no default config file the step succeeds having loaded nothing. ASN1_STRING_TABLE_get calls it on every lookup, so the refusal made the whole table raise. The flag is now accepted with the load a no-op, and applying a config file that does exist remains a Phase-6 obligation recorded as D86. Also added setvbuf line buffering to the probe, so a probe that dies part-way leaves the observations it did make rather than an empty transcript. Implemented libcrypto exports 903 -> 917; Phase 5 open obligations 58 -> 42.
    state state.59eeed712ec296d8be516d1dc49380b12eda93547de1db3fd169b9725f17355d -> state.f0d8841f77ad4b4159c5a699b212bf169331d68da2827ed44291f170fac6935c
C36  Implemented the 29 exports of the ASN.1 time family (crypto/asn1/a_time.c, a_utctm.c, a_gentm.c) and the three crypto/o_time.c calendar symbols they stand on. The parser is one function, ossl_asn1_time_to_tm, with everything else a wrapper: the four constructors and their year-window choice, the two type guards, the three cmp_time_t answers, the four printers over a memory BIO, the duplicates and the two in-place converters. Added RT-ASN1-TIME: 1071 observations, all matching, on the first run after one defect was fixed. The defect is the reason the court exists: ASN1_TIME_print called the internal three-valued printer directly instead of going through the public ASN1_TIME_print_ex that collapses its -1 to 0, so an unparseable value returned -1 where the authority returns 0. No unit test would have found it - the difference is only observable through the public entry point. Also added src/runtime/time.rs: the glibc struct tm projection the exported signatures are written against, OPENSSL_gmtime over gmtime_r, and the Fliegel and Van Flandern Julian-day arithmetic of OPENSSL_gmtime_adj and OPENSSL_gmtime_diff, with the Julian-day unit tests and the struct layout assertion. Implemented libcrypto exports 871 -> 903; Phase 5 open obligations 87 -> 58.
    state state.6218370ade549f6470b9b1a5c822d6d70ac101fd24a1937aed4462dc979d53d0 -> state.59eeed712ec296d8be516d1dc49380b12eda93547de1db3fd169b9725f17355d
C35  Phase 5.3: the shared DER codec lands in both halves, the 26 primitive item descriptors, the 36 tasn_typ.c wrappers, ASN1_BIT_STRING, ASN1_NULL and d2i_ASN1_UINTEGER. RT-ASN1 goes 644 -> 1306 observations over 0 residuals, phase 5 open obligations 226 -> 155 and implemented[libcrypto] 734 -> 805, moving together as they must. Restructuring the decoder found two defects in the file D76 had landed and neither was reachable from the three wrappers it shipped: asn1_ex_c2i frees the value unconditionally and nulls the callers slot on an allocation failure, where the old code freed only what it had allocated, so a d2i_* into an existing string would have handed back a slot pointing at a half-filled object the authority had destroyed; and asn1_item_embed_d2i raises ASN1_R_TOO_SMALL for len <= 0 before any header is read, where the old code reported a different reason for the same failure. The court then found an ownership contract rather than a bug: asn1_item_ex_d2i_intern ends with if (rv <= 0) ASN1_item_ex_free(pval, it), so a failed decode frees the callers value and nulls the callers slot. RT-ASN1 bsd.keepstate, authority=0 candidate=1, is what produced src/asn1/fre.rs, and it also explains why asn1_ex_c2i nulls the slot after freeing: that null is what stops the item layer freeing the same string twice. The 26 descriptors are compared field by field because ASN1_ITEM fields are readable in asn1t.h, and that found IMPLEMENT_ASN1_TYPE passes 0 and not -1 as the items size, which is the field that decides whether a BOOLEAN is omitted. Reason codes are generated now: gen_err_reasons.py reads 1839 LIB_R_NAME defines over 541 authority headers and cross-checks itself against gen_err_strings.parse_reason_codes before writing, so the two codes D76 had typed wrong become references and that class of mistake is gone rather than fixed once. The subphase plan had 5.4 before 5.3 and reading the file showed the dependency points the other way: ASN1_item_d2i reaches the primitive arms with no template involved, so the wrappers need the primitive path, which is the work 5.3 owns. FRF: run run-openssl-rs-rt-asn1-2053f9dbaa2d8e2fe0ce0fb78259b91735264d11405d6e227cf82d0efff062bf, receipt receipt-run-openssl-rs-rt-asn1-2053f9dbaa2d8e2fe0ce0fb78259b91735264d11405d6e227cf82d0efff062bf-3ce41207fbca8cd851ed8818e2a250452cd9ee16fe63ad06705f7cc977a29f70, challenges 3c70b564a201f55de682d7d9409f542dfeece2dab705faa18b8d895f60d1b2b4 (stdout-first-line on the stdout axis) and 6229f4ca6cc3b646872d56976633d9434ef813307bdc52018b9196faff74e40d (exit-class on the exit axis), claim 414204ce21684e41a0352d4d33a303244ff2fedbe0c6abd6acd52e598b729617 over the 25 runtime receipts plus the ABI, dgst and inventory courts. D77 records it and docs/PHASE-5-SUBPHASES.md corrects the ordering and gains the authority facts this section established.
    state state.ffc65cf51aaa8caf989a94c1cfa21fb53ab84cd2fdea8b7259d5891c31ddbebf -> state.6218370ade549f6470b9b1a5c822d6d70ac101fd24a1937aed4462dc979d53d0
C31  The ASN.1 leaf surface is implemented, wired in and courted: 109 exports, RT-ASN1 at 644 observations with no residuals, phase 5 open obligations 362 -> 226 after D73 hand-offs
    state state.cae66a95a90b21ac673e9b4d9041094b4d051acd5af8496a783b5f067becb2cc -> state.ffc65cf51aaa8caf989a94c1cfa21fb53ab84cd2fdea8b7259d5891c31ddbebf
C30  The prototype court compares the canonical type of every implemented export return and parameter, not only return class and arity; twelve wrong declarations found and fixed; the RT-BN BN_GENCB section added and a thirteenth behavioural defect found
    state state.f48f703c3fc7896f18ac74e6848843bd301f48b25869f6d07598966c16e0b4b9 -> state.cae66a95a90b21ac673e9b4d9041094b4d051acd5af8496a783b5f067becb2cc
C29  GF(2^m) closes BN. src/bn/gf2m.rs implements all fifteen BN_GF2m_* exports — add, poly2arr, arr2poly, mod, mod_arr, mod_mul, mod_mul_arr, mod_sqr, mod_sqr_arr, mod_exp, mod_exp_arr, mod_inv, mod_inv_arr, mod_div, mod_div_arr — as field arithmetic rather than as the authority carry chains: carry-less multiply, shift-and-xor reduction, polynomial long division, and extended Euclid over GF(2)[x] that reports a non-unit gcd as no-inverse rather than as a wrong answer. RT-BN goes 577 -> 633 observations over 0 residuals, and unlike the eleven earlier passes in this stratum both findings were the implementation and not the probe: poly_rem compared the value bit length against the modulus rather than against the field degree, so 0xa5 * 0x57 in the AES field, exactly one bit longer than the field, came back unreduced but plausible; and BN_GF2m_mod_inv raised nothing on an invalid modulus, when the authority reaches that case through BN_GF2m_mod_mul and a caller therefore sees that function INVALID_LENGTH coordinate. Both are recorded with the coordinate, and the probe now compares the error queue after those failures and not only the return value. The non-_arr entry points convert through BN_GF2m_poly2arr and call the _arr ones, so the two spellings are not independent but they are separately observable, and the court drives both, cross-checks them against each other, and checks the field identities a * a^-1 == 1 and (a/b) * b == a. Two divergences are recorded rather than reproduced: D-GF2M-1, the authority blinds BN_GF2m_mod_inv with BN_priv_rand_ex and this does not because BN_priv_rand_ex is Phase 9 and a fixed blinding value is not blinding, so the returned value is identical and the TIMING claim is removed; and D-GF2M-2, the arithmetic is not the authority unrolled carry chains, so no timing claim is made in either direction. Obligation OBL-GF2M-INV-BLINDING is owned by Phase 9 and closes by adding the blinding when RAND exists. Every one of the 201 exports bn.h declares is now implemented or handed to a named later stratum, so Phase 5 open_in_this_stratum falls from 333 to 318: 280 ASN.1 and 38 PEM, which is the whole of what remains. FRF: run 33d75fee81d80354eda5b7f051aefa6dea3eb9084dc6f1fc00ac1ec0a4948f9b, receipt receipt-run-openssl-rs-rt-bn-33d75fee81d80354eda5b7f051aefa6dea3eb9084dc6f1fc00ac1ec0a4948f9b-bbb16ce6b43b3246f0cc7983dc7f9c5b9c3d46ed212defbb6234bce8f286d2b6, challenges 7894d4ef788712701fb9ce57e5573d93b065b8f0de3ee51e33e413e8576f2702 (stdout-first-line on the stdout axis) and 3e8c880cb9f235f254a17298783daca09ba50dee1b005639a62094e6c91801de (exit-class on the exit axis), claim 564889652b055cbffa62df560f376117dffda456ae674120b166a4c5a02a11c5 over the 24 runtime receipts. The seal FRF section was corrected in this change: it named a capture identity from a superseded store generation, and the identity it names now is the clean run above plus the two challenged runs, which are the three capture directories on disk.
    state state.a5011f9ae7e414dd7ad7814c7bf30290fb1bc84ae250838d4d8683ad552b4db6 -> state.f48f703c3fc7896f18ac74e6848843bd301f48b25869f6d07598966c16e0b4b9
C21  The BN surface is closed: every one of the 201 exports bn.h declares is implemented or handed to a named later stratum, and the stratum court now covers the whole of it. Six new modules: mont (BN_MONT_CTX and the Montgomery arithmetic over it, with R = 2^ceil(bits/64)*64 as the authority picks it), recp (BN_RECP_CTX and reciprocal division, whose quotient and remainder the probe checks against BN_div directly because the reciprocal is a speed device and not a different division), primes (the thirteen named primes, whose values are generated from the authority by forensics/tools/gen_bn_primes.py rather than transcribed, and whose five static NIST objects are cached so two calls answer the same pointer the authority returns), nist (the five reducers and the value-based selector), kron (BN_kronecker, Cohen 1.4.10 including the reciprocity sign written the way the authority writes it), and blinding (BN_BLINDING: new/free, the flag and thread surface, the lock, and invert/invert_ex). The court went from 475 to 577 observations over 0 residuals, and extending it found one defect which was again the probe: the first version handed BN_mod_exp_mont a BN_MONT_CTX re-set to a different modulus, and the authority answered 0 for it because a context is bound to one modulus. With a matching context everything agreed on the first run, and two claims the source only suggested are now measured: that BN_nist_mod_* is BN_nnmod against a fixed prime and ignores the field argument it is handed, and that BN_nist_mod_func selects by value rather than by identity. Thirty-one BN exports are handed to Phase 9 with the dependency as the reason: the RAND families, the prime generators, the five Miller-Rabin primality tests, the X931 generators, BN_generate_dsa_nonce, the GF2m square-root and quadratic-solver pair, and the four blinding entry points that re-create the blinding factor through BN_BLINDING_create_param. Fifteen remain open and all of them are GF(2^m): add, arr2poly, poly2arr, mod, mod_arr, mod_mul, mod_mul_arr, mod_sqr, mod_sqr_arr, mod_exp, mod_exp_arr, mod_inv, mod_inv_arr, mod_div, mod_div_arr. Phase 5 is in-progress and derived: 333 open of 1099 covered, 280 ASN.1, 15 BN, 38 PEM. FRF: run 92c14e395079b876c00b21062faaff4d887ddb913419eb73ea6c1efd9e2e17c4, receipt bfc1b9169a88d2e60a682a69612465eb6b520e653097ba3f75719d6f07b8df82, challenge 551ff830a4b500afa06a1c117f842434634e470122b35e0f5cb0c97cafc70301, claim 62ccbb07477191b275df2601447473095452b7b409c94b0d56b8059bab507b43. The prototype court added in the previous change is now a CI gate and reproduces in evidence_determinism: 550 of 610 implemented exports checked, 0 mismatches.
    state state.ebcc96f517c951fc5431bb54f9e43b20a390d8f6c6d8645b10598f83edcf4c1e -> state.a5011f9ae7e414dd7ad7814c7bf30290fb1bc84ae250838d4d8683ad552b4db6
C20  Phase 5 BN arithmetic closed, and the court that closed it found nine behaviours first. RT-BN compiles one C probe against the admitted authority and against the candidate and diffs the transcripts: 45 residuals on its first real run, 0 at closure, over 475 observations. The first run was a probe bug (a freed BIGNUM slot reused through BN_asc2bn, because BN_free does not clear the caller pointer) and that is the tenth time in this project that the probe was the suspect. The 45 were real: BN_bn2hex is byte-oriented and not nibble-oriented (32 of them were one nibble wide), BN_cmp orders by sign before magnitude and negating the magnitude answer inverts exactly the mixed-sign case, BN_asc2bn answers 1 or 0 and not a digit count, BN_usub reports only a limb-count shortfall and otherwise lets the final borrow escape, BN_mask_bits reports a width past the value top limb, the mod family reduces last rather than first so a negative operand contributes its sign, the _quick variants are their own algorithms, a negative exponent is not rejected because the ladder reads the magnitude, and the error queue is part of the answer at the authority own coordinates (all nineteen raising crypto/bn translation units now covered by gen_err_raise_sites.py). One residual was a panic rather than a wrong value: BN_mod_inverse(a,0) reached limbs::rem division-by-zero assertion, which guard_ffi caught into a null return with no error raised because the raise happens after the arithmetic; limbs::mod_inverse now answers None for a zero modulus, which is also the mathematically right answer. The most important finding was a call convention: BN_signed_lebin2bn and its relatives were declared -> c_int while the authority declares BIGNUM *, and they required a non-null ret, so the documented NULL-means-allocate form failed. The atlas recorded the prototype and nothing compared it, so forensics/tools/prototype_court.py now compares return class and arity for every implemented export (resolving both sides through their typedef chains so spelling never reads as shape), with symbols it cannot check named by class and never counted as passes. Its first real run found two more, in this stratum own new code: BN_CTX_new_ex and BN_CTX_secure_new_ex carried a const char *propq that belongs to the EVP constructors and not to these, harmless at every call site on this ABI which is exactly why only a prototype comparison finds it. Recorded: the RAND-dependent exports of this stratum (BN_rand family, BN_generate_prime family, BN_generate_dsa_nonce, BN_BLINDING_create_param, the X931 generators and the GF2m sqrt/solve_quad pair) are handed to Phase 9 with the dependency as the reason; the two ABI_ONLY_EXPORTED symbols the atlas has no prototype for (OPENSSL_DIR_read, OPENSSL_DIR_end) are reported rather than skipped. Phase 5 is in-progress and derived: 391 open of 1099 covered, 280 ASN.1, 73 BN, 38 PEM. FRF: run-openssl-rs-rt-bn-5580515d5fb3a457d26b65acfbb5b448e525df3a596f248f74418b3f55d3fdef, receipt f58c3b404fe7832043ddeca4fa58ad8dbec69b3beed1071a5502e4be7e9350bf, challenge 37815ebd91f5a0fc28e7417539a4706bb0fef1e577fa256c495dfcd5d4d112e9, claim 7648b6178e10d5b50f9dae13fcc0335283737f5abe7ec259d5ea18973c17f69c.
    state state.3b639aa874b366dd8e46bfd6d8f395c89cfa35c9b813f0f5c3ac260c43531c51 -> state.ebcc96f517c951fc5431bb54f9e43b20a390d8f6c6d8645b10598f83edcf4c1e
C19  Phase 5 archaeology and the BN substrate. The stratum owns 513 of the authority exports, measured rather than typed: 201 in bn.h, 274 in asn1.h/asn1t.h and 38 generic PEM entry points, with 580 handed to later strata by declaring header (23 to phase 7, 58 to 8, 12 to 10, 346 to 11, 141 to 12). The families had to be derived because the candidate surface spans 270 distinct ASN.1 type names and prefix lists cannot separate d2i_X509 from d2i_ASN1_INTEGER; typed families are also how the D49/D51 defect class arose twice. The ledger fails closed on an unknown header. The BN substrate is written but not committed and not wired in: making the entry points unsafe extern C cascades into about sixty internal SAFETY comments, and there is no differential court yet, so committing would put symbols in the ABI shell as implemented on unit-test evidence alone. Twelve limb unit tests pass, and three of their expectations were wrong while the implementation was right.
    state state.e0c7044436a5db04f8a67931be2e8532bae6af04741d0789a736157bd367f2ab -> state.3b639aa874b366dd8e46bfd6d8f395c89cfa35c9b813f0f5c3ac260c43531c51
C18  Phase 4 evidence reproducibility: the RT-BIO-DEBUG probe leaked an ASLR-dependent subject address to stderr through the NULL-destination fallback of BIO_debug_callback_ex. The court declares stdout and exit as its axes, and its stdout was already stable and scrubbed, so the claim was never affected; but the capture includes stderr, so every run produced a different evidence identity, and that one court was enough to make the aggregate runtime claim identity unstable. Measured: three re-runs of the court in one store produced three different run ids. setarch -R is refused in both court containers, so ASLR cannot be disabled. The probe now redirects descriptor 2 to a temporary file for that one call, restores it, and reports the scrubbed text as two further observations. Three re-runs now return the identical run id and FRF refuses to re-capture, which is the falsifiable test that it is fixed.
    state state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5 -> state.e0c7044436a5db04f8a67931be2e8532bae6af04741d0789a736157bd367f2ab
C17  Record correction: the Phase 4 ledger hands thirty-one exports to later strata, in five groups, each with a named owning phase and a stated reason. Six to Phase 5 (the ASN.1 prefix and suffix hooks plus BIO_f_asn1 and BIO_new_NDEF), seventeen to Phase 6 (BIO_s_core, BIO_new_from_core_bio and the fifteen CONF module-registry entry points), five to Phase 7 (the digest, cipher, reliable and base64 filters and BIO_set_cipher), one to Phase 9 (BIO_f_nbio_test, whose read and write call RAND_priv_bytes), and two to Phase 12 (BIO_new_CMS and BIO_new_PKCS7). The eleven symbols Phase 3 handed to Phase 4 are recorded on the Phase 3 side as discharged, not as Phase 4 deferrals. No file content changed.
    state state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5 -> state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5
C16  Record correction: the Phase 4 closure change C15 says the ledger hands twenty-two symbols to later strata. The ledger hands thirty-one, and two of the thirty-one are the ASN.1 prefix hooks and CMS/PKCS#7 BIO bindings; the eleven discharged Phase 3 hand-offs are counted on the Phase 3 side, not as Phase 4 deferrals. No file content changed with this correction; the Git commit remains the authoritative record of the diff.
    state state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5 -> state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5
C15  Phase 4 complete: sixteen differential BIO, BIO-adjacent, OBJ and CONF courts with no residual over 3215 observations; the whole CONF reader including both character-class tables; the lhash insertion-order defect the dump text exposed; the ERR data formatting the authority does through BIO_vsnprintf; and a ledger that hands twenty-two symbols to named later strata. The FRF runtime claim is now sensitivity-backed over twenty-three courts.
    state state.6fe2d6a4caa8fde4a5aed8933bcac4e4a7e403eb92165dfc85b56f54dfce9c5a -> state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5
C13  Record correction: Gemel names changes by derived order, so the name C9 that Phase 3 closure (change.0321160b...) quotes in its summary is not stable. The placeholder change it means is change.e58167ada98b43af520cd6b8c39c103a30560c406cfd91e6004019fd0b75f326, currently named C11, and it is the change that carries the Phase 3 working-tree operations because it was created first. No content changed; this change exists so the durable identity is recorded in the store rather than only in prose.
    state state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c -> state.6fe2d6a4caa8fde4a5aed8933bcac4e4a7e403eb92165dfc85b56f54dfce9c5a
C10  Phase 3 complete: seven differential runtime courts with no residual, generated ERR reason tables and raise-site coordinates, load-gated string visibility, fail-closed obligation ledger. Supersedes C9, which was created accidentally by a command-line probe of the claim-kind enum and carries only a placeholder claim.
    state state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c -> state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c
C11  p
    state state.46cf9bcff7dad1b49b613c87d2458196666c4d2e787c76ea29702255e3913716 -> state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c
C6  Phase 2.1 structural closure: dynamic contract, exact symbol comparison, evidence-derived phase state
    state state.ba6b30cf8a7741640b349cf65bff4a30247994151265f119bd5f2d6a4073a42b -> state.46cf9bcff7dad1b49b613c87d2458196666c4d2e787c76ea29702255e3913716
C5  Phase 2 complete: distribution shell, ABI matrix, substitution, constants, FRF ABI court
    state state.c86c4178c1597a82a06176665f752d3aa9107c30b5be2178f67ba5d5f4526621 -> state.ba6b30cf8a7741640b349cf65bff4a30247994151265f119bd5f2d6a4073a42b
C2  Phase 1 foundation closure: differential atlas, completeness, FRF sensitivity-backed claim, FFI boundary
    state state.85d1e8ede88fb9f355d3d7e01f71483f9b28f0a857898a706a5fe5a3099a44f2 -> state.c86c4178c1597a82a06176665f752d3aa9107c30b5be2178f67ba5d5f4526621
C1  Phase 0 constitution and Phase 1 archaeology atlas, evidence-bound
    state (initial) -> state.85d1e8ede88fb9f355d3d7e01f71483f9b28f0a857898a706a5fe5a3099a44f2
```

## Checkpoints

* `K1` — `checkpoint.2a1ca2279b999e7740976a4958d6d6bb66e5312203ed9d15816d340a38073328`
* `K10` — `checkpoint.51ac8d8e9e91d360fe1bb94630661f0fd4071dd844baa1cd42c82b4e1504ba08`
* `K11` — `checkpoint.843b3f72da905eec1a0fc67a16ee8f1dc4811f86f51dfa75ae68a4d0c88ac4c6`
* `K12` — `checkpoint.3d4d0ddafc52a6635d9cf963b6fd27888133ca39ccc83243082477e7ddfaec45`
* `K13` — `checkpoint.f8f1061c5592c5dc801b31439f949ed21470126cd32b0f320fea3bf561acba55`
* `K14` — `checkpoint.c3c9dd019cd987d9753cda5e521b8993decd99c01b97fcebeef888727f56512e`
* `K15` — `checkpoint.be15113912c9856c707bdd4c9317edc7c750663fd96e76e1a5b5e2b9a4420c3d`
* `K16` — `checkpoint.6efde8d368887ea3895c564c33f8cc2ea84b211d56971fb3055ae89c576c10e2`
* `K17` — `checkpoint.5fd6e1426ad1bf8934578ecdb7020b8bf72c4ca401136e0884da0b7c0f4b22c6`
* `K18` — `checkpoint.945a0214a4146448bc80b811fa2d65ffa531a1d49396b93cc0bbf715e26dba62`
* `K19` — `checkpoint.73c21457ed3266796156fb1e55e8a60bc559a8d9398b610297c336bb30b956fd`
* `K2` — `checkpoint.67a75f9a16d008e6e5aec0984c93dfc7549bd7a33708b909fbf6424b04fcb4a6`
* `K20` — `checkpoint.528dbaef805d3e05304fbc9ae6e8bee5c1a5bb2e75486f2998933b875732bed5`
* `K21` — `checkpoint.6933308364494b57c6c48ab9e4246d741e27a9e013ea2bfac9ce0dfda8fe2f48`
* `K22` — `checkpoint.5c49d38a618be5dfb2a1d350b73a7f13b5dc9b4f2629a36ce4bf882ad814752f`
* `K23` — `checkpoint.4d121775b53e8369dd0457ad230f82a3b375db10e9df7077ad4d564dcdc756fd`
* `K24` — `checkpoint.1a2e3a5565633ce851d7dadbcbc9c5cd2be4cf8d61b6463f45b54cc7fa39ec8a`
* `K25` — `checkpoint.72f7fa3b2028e181c38bcb2d904f665cad991c15dfbe446629b3aee4147edc15`
* `K26` — `checkpoint.4e8675a95b17554b5113e18653828e79c7c859cc37f7c3a2183a9c4864041d34`
* `K27` — `checkpoint.cd670f06b0cd5409439a863fffb94c388c24bf3617eafdbf012d833da79a7e13`
* `K28` — `checkpoint.5f82da003df177c43703c768867caf5616b5bcb1a85f3376494d2730c74abdb9`
* `K29` — `checkpoint.a3713ea56466fccba028c053d2e9f17756e5067eec4a78fb90347aed6d8aad10`
* `K3` — `checkpoint.b1516eb6364ad075785911cb204a75a6e1b83b08c1a7ca39a2de6e3983dc9aed`
* `K30` — `checkpoint.76a96561abab60000acae0b6e28920a3bb935d6b9439dcc8625d6088e944f7dc`
* `K31` — `checkpoint.2cd5a115653b46223c9f08a5fde8e27816bca65403178271723fed449cc83585`
* `K32` — `checkpoint.762086a51a9fb6a0560b5334da2fe6afc6742b9b378e090fe0b5ba2f998812d3`
* `K33` — `checkpoint.78b36f5a69bdf87eee41a35af9d1d98747954289da20f803a1a48608ab264b31`
* `K34` — `checkpoint.a2096945c7a295a6f4b0ce77afd38ff1651b2167d49ea198dc1085892334a3a8`
* `K35` — `checkpoint.5c340ead0989bb79b5832ae7d3d0bf1dffad4e5043a9089f397e71e9391d0fea`
* `K36` — `checkpoint.b2246933fc4896371a88f1b965fb27f01bc107a4fbcaecc3790e219edc435416`
* `K4` — `checkpoint.1bde75b37e1ca3972037c29cbd3ba5291079544436db9176a82f097a6bf832fe`
* `K5` — `checkpoint.6b0d12f1ecf380c0808bc95675222fbed7256f99bc8e9f475a0ec2693f804a0a`
* `K6` — `checkpoint.8958092650197b473c5b00d9c0de22e075c4765efc2e8a4ab9d452ffae97cf61`
* `K7` — `checkpoint.0c5d62d5f78d2c4ebdc7174affd4464f04d1315708e5a87962cded63439818d3`
* `K8` — `checkpoint.7eb3dba97cbf20f2b34d14cce7e93bc2171ebd0d7ee66d1f7508cc6e199567de`
* `K9` — `checkpoint.60105b4c8189d2668c48e173fe2c92c0ddf76160caae24efecc707bd576f506f`

current: `checkpoint.b2246933fc4896371a88f1b965fb27f01bc107a4fbcaecc3790e219edc435416`

## Note: derived names are not identities

Gemel names changes by derived order, so a name quoted inside one change's
summary can be renumbered later. The Phase 3 closure change
(`change.0321160b791013c5904bb61fe65b4932da674bdbc7f1043b50e2e4369544c227`)
says it supersedes `C9`; that name no longer exists in the store. The change it
means is
`change.e58167ada98b43af520cd6b8c39c103a30560c406cfd91e6004019fd0b75f326`,
currently named `C11`: a placeholder created by a command-line probe of Gemel's
claim-kind enum, which — because it was created first — is also the change that
carries the Phase 3 working-tree operations. The correction
(`change.8423b2c8fe75201fb070e0b21df03d122c8675cde393c9b2d88d9ea1800ee5de`)
records that mapping in the store rather than only in prose. No file content
changed with it; the Git commit is the authoritative record of the diff.

## Open residuals at this boundary

```
open [low] ossl_namemap_stored does not pre-populate from the legacy OBJ_NAME database or the EVP_PKEY_ASN1_METHOD set, so a provider-registered name gets number 1 where the authority continues after the legacy names; deferred whole to Phase 13 because the RSA-PSS block alone would make the emptiness guard false
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] OSSL_SELF_TEST_oncorrupt_byte with a NULL bytes and a refusing callback answers 0 where the authority writes through the NULL
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] nothing invokes the indicator callback; the code that reports an approved or non-approved state is provider-side
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] OPENSSL_atexit needs DSO_dsobyaddr to pin its handler's object and waits for 6.9
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] OPENSSL_thread_stop and OPENSSL_thread_stop_ex need the per-thread event-handler table in crypto/initthread.c and are 6.6e-ii; context_deinit therefore does not yet call ossl_ctx_thread_stop
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the thread slot's condition variable is created and released but nothing waits on it; the thread pool that signals it is not a Phase 6 subsystem
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] each OSSL_LIB_CTX has its own ex-data registry in the authority; this crate has one process-global one, which src/runtime/ex_data.rs records as a Phase 3 deferral and this subphase does not change
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] context_deinit does not call ossl_ctx_thread_stop, because no per-thread object can exist until 6.6e registers threads against a context
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] seventeen of the eighteen live OSSL_LIB_CTX index slots answer NULL until their owning stratum lands; each slot's owner and the closure rule are in docs/PHASE-6-SUBPHASES.md, and no symbol ledger can see them
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the runtime-court count in forensics/frf/README.md is prose rather than a projection and said 25 while the store held 37; it is corrected, not derived
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] ASan is refused by the court's OOM protection, so the level-differential method is a substitute for a sanitizer rather than equivalent to one
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] probe_hygiene.py detects frame dependence, not out-of-bounds reads that land deterministically; a probe can read a fixed wrong location and still agree at every level
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] OSSL_PARAM_BLD_push_BN_pad with a negative BIGNUM leaves the value bytes uninitialised because BN_signed_bn2native refuses the recorded width; the refusal is compared, the bytes are not
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] OSSL_PARAM_print_to_bio answers 0 for a NULL array where the authority dereferences it, and the probe records the boundary rather than the behaviour
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] OSSL_PARAM_merge sorts stably where the authority's qsort is unspecified among equal keys within one list
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] setbuf_fromparams is reproduced from the two WPACKET operations it uses rather than from crypto/packet.c, which belongs to Phase 7
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] OSSL_PARAM_print_to_bio answers 0 for a NULL array where the authority dereferences it
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] OSSL_PARAM_merge sorts stably where the authority's qsort is unspecified among equal keys within one list
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] setbuf_fromparams is reproduced from the two WPACKET operations it uses rather than from crypto/packet.c, which belongs to Phase 7
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [medium] RT-PARAM does not exist, so no differential court observes the parameter surface and 6.5 cannot close on the rule in D73
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the zero-length and realloc-zero unit tests were deleted rather than repaired: the test harness shares one process and the allocator branch is chosen once
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] CRYPTO_malloc allocation failure raises ERR_R_MALLOC_FAILURE and cannot be exercised in the venue without inducing OOM, which the court forbids
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the authority faults writing through a NULL freeptr in CRYPTO_aligned_alloc and its _array sibling; the candidate answers NULL and the boundary is recorded rather than compared
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] seven implemented exports are declared in headers the authority does not install, so the Phase 1 atlas has no prototype for them; their ABI is still proved by the Phase 2 loader court
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the 22 ASYNC_* exports are deferred to Phase 13; the authority in-tree callers are the async engines and the SSL async API, and OPENSSL_NO_ASYNC is not defined in this profile
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] five Phase 3 exports are deferred to Phase 6 with the dependency named: the two libctx thread-count accessors, the thread-stop pair, and OPENSSL_atexit whose DSO pinning this profile compiles in
    class: verification_gap
    persistence: 0 descendant change(s)
open [medium] OPENSSL_info answers NULL for the build-dependent codes where the authority answers a build-tree path, the same divergence already recorded for CONF_get1_default_config_file, reached by a second route
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] two conf_ssl_* exports index a store that nothing populates until the ssl_conf CONF module runs, which needs CONF_module_add in Phase 6.9
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] four COMP_* exports take a live COMP_CTX and no consumer in this profile can obtain one, because every factory answers NULL and libssl returns entries with a NULL method
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the 25 pem.h exports handed to phases 7 and 11 remain unimplemented
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the authority i2d_ASN1_bio_stream unwind loop does not terminate for a callback returning a detached BIO, and the candidate stops
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] the 27 pem.h exports and PEM_write_bio_ASN1_stream and i2d_ASN1_bio_stream remain unimplemented
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] i2d_ASN1_bio_stream in asn_mime.c remains open pending a check for Phase 12 entanglement
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the NDEF streaming happy path needs a caller-declared item with an ASN1_AUX callback; the probe declares one, and the in-tree items that do this are CMS and PKCS7, which are Phase 12
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] a refused name in ASN1_str2mask leaves the mask accumulated by the earlier names; reproduced and courted, and it is the authority behaviour rather than a defect
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [medium] ASN1_generate_v3 and ASN1_generate_nconf are handed to Phase 11, so no caller can build an ASN1_TYPE from a string until then
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] X509_NAME_print_ex and X509_NAME_print_ex_fp are the other half of a_strex.c and belong to Phase 11, so do_name_ex is not written here
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the char_type table is the generated artifact rather than a re-derivation of charmap.pl; the probe pins it through behaviour over all 256 byte values under three flag sets
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] ASN1_STRING_print_ex with DUMP_DER on a non-character type encodes the string pointer reinterpreted as that type value, so the output is address-dependent and no probe can compare it; the restriction to comparable types is stated in the probe
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the string-table stack is reached through an AtomicPtr where the authority uses a bare pointer and documents that its own sort is unsynchronised; the observable contract is the same and the crate avoids a mutable static
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] ASN1_STRING_print_ex, ASN1_STRING_print_ex_fp, ASN1_STRING_to_UTF8 (a_strex.c) and ASN1_str2mask (asn1_gen.c) remain open in this subphase
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] ASN1_add_oid_module is handed to Phase 6 and ASN1_add_stable_module to Phase 11, so neither registers its CONF module until then
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [medium] OPENSSL_INIT_LOAD_CONFIG succeeds without loading a config file, so a config file that exists is not applied, and a stbl_section entry in it is not visible to ASN1_STRING_TABLE_get; the loader needs OSSL_LIB_CTX and the module registry, both Phase 6
    class: contract_mismatch
    persistence: 0 descendant change(s)
open [low] the crate answers a null struct tm destination or a null from/to in OPENSSL_gmtime_diff with the failure value where the authority faults; recorded in SECURITY_DIVERGENCE_POLICY
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] the time family raises nothing on a parse failure, so ASN1_TIME_adj raising ASN1_R_ERROR_GETTING_TIME is the one raise site and it needs a libc gmtime_r failure to reach; recorded but not courted
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the offset branch applies OPENSSL_gmtime_adj only when the destination is non-null, so a value whose offset would move the Julian day below zero is accepted by the checker and refused by a fill; reproduced and courted, not a defect
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] the item descriptors size fields are compared through the probe rather than through a generated ABI constant court, because struct ASN1_ITEM_st is not in the ABI-LAYOUT aggregate set the phase 2 probe measures
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] ABI-PROTOTYPE cannot check the 36 tasn_typ.c wrappers or the 26 *_it accessors: DECLARE_ASN1_FUNCTIONS generates their declarations, so the atlas header extraction does not see them and the prototype court counts them as generated rather than checked
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the 155 remaining phase 5 obligations are unimplemented: 128 ASN.1 (the template interpreter, 14 *_it descriptors, the time accessors, the string masks and printing, ASN1_TYPE, the NDEF BIO bridge, asn1_d2i_read_bio) and 27 PEM
    class: verification_gap
    persistence: 0 descendant change(s)
open [medium] RT-ASN1 is evidence about the symbols it calls and no others
    class: other
    persistence: 0 descendant change(s)
open [medium] ASN1_parse_dump cannot be compared against a crash, so no probe exercises the paths where the authority dereferences a null pointer
    class: other
    persistence: 0 descendant change(s)
open [low] two dynamic raise reasons in d2i_ASN1_OBJECT are read from asn1err.h and checked behaviourally by RT-ASN1 rather than derived from a generator
    class: verification_gap
    persistence: 0 descendant change(s)
open [medium] the ASN.1 surface is 199 exports short of closed; the template machinery, the remaining codec wrappers, the time types, the string masks and printing, ASN1_TYPE and PEM are unimplemented
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] BN_GENCB_get_arg(NULL) is answered NULL where the authority dereferences the pointer
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [low] BN_GENCB_call on a ver==2 object whose callback is NULL is answered 0 where the authority calls through a null pointer
    class: semantic_divergence
    persistence: 0 descendant change(s)
open [medium] ABI-PROTOTYPE compares declarations as source and does not bind them at build time, so a parser defect in the court could pass a wrong declaration
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the BN_GF2m_* arithmetic is not the authority unrolled carry chains, so no timing claim is made in either direction
    class: performance_divergence
    persistence: 0 descendant change(s)
open [low] BN_GF2m_mod_inv is not blinded, so its timing profile is not claimed to match the authority: BN_priv_rand_ex is Phase 9 and a fixed blinding value is not blinding
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] BN_rand, BN_generate_prime and the other RNG consumers in bn.h are owned by phase 5 but cannot be built before the RAND stratum exists; deferring them to phase 9 on the precedent of BIO_f_nbio_test is the decision still to take
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [medium] the BN entry points need an unsafe extern C conversion plus about sixty SAFETY comments before the crate lint gate passes
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [high] the BN substrate is written but unwired and uncourted, so no BN symbol is implemented in the ABI shell and the ledger reports 513 open
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the RT-BIO-DEBUG transcript gains two observations, so its receipt identity differs from the one recorded before this fix
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] thirty-one Phase 4 family exports are handed to a named later stratum and remain SCAFFOLDED until it lands
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] the ABI-SYMBOL court compares name, version, ELF type, binding and visibility but never C prototypes; a declaration/definition arity mismatch is invisible to it
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] CONF_get1_default_config_file answers the empty string rather than the forensic build OPENSSLDIR; OBL-CONF-DEFAULT-CONFIG-FILE is owned by Phase 16
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] the FRF runtime claim covers the first stdout line, which is a digest of the whole transcript, plus exit class; stderr is not claimed because both sides write none
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the CONF court cannot compare parselist.nocb or the recursive-directory include, because the authority faults on both
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] Gemel C9 was created accidentally while probing the claim-kind enum, and Gemel is append-only so it carries a placeholder claim; C10 is the substantive record
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] the FRF runtime claim covers the first stdout line, which is a digest of the whole transcript, plus exit class; stderr is not claimed because both sides write none
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] two authority ERR raise arms (stack.c:212 and stack.c:275) need on the order of a billion elements to reach; their conditions are reproduced but no court exercises them
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the ABI-SYMBOL court compares name, version, ELF type, binding and visibility but never C prototypes; a declaration/definition arity mismatch is invisible to it, and one was found this phase by the RT-ERR probe instead
    class: verification_gap
    persistence: 0 descendant change(s)
superseded [low] FRF sensitivity coverage missing for the two non-fixture-driven courts, harness disposition, blocks a sensitivity-backed claim for them
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] candidate DSOs carry toolchain runtime dependencies the C authority does not; recorded by ABI-DYNAMIC, not removable from a Rust-linked artifact
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] Every shell symbol is SCAFFOLDED and aborts when called; Phase 2 proves structure, never semantics
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] Two macros added in 3.6.4, one of which (X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH) is security-fix related
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] OpenSSL 3.6.3 to 3.6.4 version banner divergence, disposed as an oracle-version trajectory
    class: expected_mismatch
    persistence: 0 descendant change(s)
```
