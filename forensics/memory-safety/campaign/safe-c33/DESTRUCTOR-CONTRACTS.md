# Destructor-contract audit — reusable ownership boundaries

**Source identity:** `integrate/safe-c33` at `3234cfe590e84fabd0d5747ba6d1f1172949c9b9`
(working tree at audit time). **Scope:** every destructor-contract
implementation in `src/`: `unsafe impl CtxDestroy`, `unsafe impl
CipherDestroy`, every module-local `unsafe trait *Destroy`/`DrbgCtx`/
`FreeOnDrop`, and the `Drop` owners that run those bodies or release
member-buffer resources. **This is a contract audit, not a discharge.** No
mechanism below is `SAFETY_DISCHARGED`; nothing here is
`SAFE_COMPATIBLE`.

## Method and inventory

Static source review against AGENTS.md §§1, 2, 5, 7, 9, 14, 17, 21. For every
implementation the audit records: type/module; construction path and whether
an all-zero or partially initialised state can reach the destructor;
`destroy_body`/`Drop` actions in order; whether it releases the enclosing
block or a member more than once; zero-validity witness for the fields read;
retained obligations; and status. Status uses only `CONTRACTED` or
`ESTABLISHED`; `DISCHARGED` requires independent checking and is not claimed.

**Inventory (source-grounded):**

| family | trait definitions | implementations |
|---|---:|---:|
| `CtxDestroy` (1 shared + 41 module-local copies) | 42 | 136 |
| `CipherDestroy` | 1 | 27 |
| `KdfDestroy` | 1 | 14 |
| `MacDestroy` | 1 | 7 |
| `GcmDestroy` | 1 | 3 |
| `DrbgCtx` | 1 | 5 |
| `FreeOnDrop` | 2 | 7 |
| **total** | **49 definitions (46 `*Destroy` + `DrbgCtx` + 2 `FreeOnDrop`)** | **199** |

The 46 `*Destroy` definitions comprise 42 separate `CtxDestroy` definitions
(one shared in `runtime::bio::owned`, 41 module-local copies) plus one each of
`CipherDestroy`, `KdfDestroy`, `MacDestroy` and `GcmDestroy`; they are not one
shared trait (AGENTS.md §21's dependency-closure rule still applies to each). `PROGRESS.md`'s "46 destructor traits" counts the
`*Destroy` definitions; the true total including `DrbgCtx` and the two
`FreeOnDrop` copies is **49 definitions**. This is an inventory correction,
not a code defect.

**Legend for construction path:** `Z` = safe zalloc owner (`OwnedCtx::new`,
`OwnedCtx::zalloc`, `new_zeroed`); an all-zero block can reach `Drop`, so the
implementer must satisfy the zero-validity half of the contract. `S` = staged
construction (`RawCtx`/`Raw*`/`malloc` + explicit initialisation); zero or
partial storage is released block-only and does not reach a destructor that
reads uninitialised members. `R` = `OwnedCtx::from_raw`/`from_raw_clear` only
after a completed authority construction; zero is not reachable. `N` =
`*_new` answer wrapped by `FreeOnDrop`; no zero state. `B` = block-only owner
(`GcmDestroy`, digest rows); no member destructor body.

**Status rule used here.** `ESTABLISHED` means the audit found a source witness
for the implementer's destructor and zero-validity obligations and for the
owner's liveness/single-release precondition. `CONTRACTED` means the contract
exists but at least one precondition is delegated to a callback, a reference
count, a complex multi-member teardown, or a disputed zero-validity claim, and
has not been independently checked. Every row retains the owner-level
obligations "block is live" and "`Drop` runs once"; these are discharged by
the owner type, not re-listed per row.

## 1. Trait definitions

All 49 definitions are `unsafe trait`. Every one has a `# Safety` implementer
contract. The contract families are:

| contract class | definitions | (a) destructor | (b) zero-validity |
|---|---|---:|---|
| shared `runtime::bio::owned::CtxDestroy` (`owned.rs:66`) | 1 | yes | stated |
| module-local `CtxDestroy`, zalloc owner (`async_wait:102`, `ct_log:196`, `ct_sct:203`, `ct_sct_ctx:114`, `dso/mod:208`, `ec/lib:123` (both bodies), `evp/asymcipher:212`, `evp/bio_enc:172`, `evp/digest:234`, `evp/pkey_ctx:268`, `provider/decode_der2key:542`, `provider/ec_kem:159`, `provider/ecx_kmgmt:180`, `provider/encode_key2any:389`, `provider/file_store:237`, `provider/keymgmt:444`, `provider/mac_legacy_kmgmt:139`, `provider/seed_src:224`, `provider/skeymgmt:99`, `provider/slh_dsa_sig:163`, `provider/sm2_enc:90`, `store/store_lib:149`, `ui/ui_lib:301`, `x509/by_store:206`, `x509/x509_lu:553`, `x509/x509_vfy:240`, `x509/x509_vpm:262`) | 28 | yes | stated |
| module-local `CtxDestroy`, staged/from-raw owner (`ec/ecx_key:110`, `engine/eng_dyn:368`, `evp/exchange:112`, `evp/pkey:401`, `provider/conf:161`, `rand/rand_lib:372`, `ssl/ssl_lib:563`, `x509/by_dir:234`, `x509/v3_lib:205`, `x509/v3_purp:419`, `x509/v3_utl:146`, `x509/x509_trust:159`, `x509/x_crl:198`) | 13 | yes | explicitly disclaimed (`no zero-validity claim`) |
| `CipherDestroy` (`provider/cipher.rs:461`) | 1 | yes | stated |
| `KdfDestroy` (`provider/kdf.rs:344`) | 1 | yes | stated |
| `MacDestroy` (`provider/mac.rs:227`) | 1 | yes | stated |
| `GcmDestroy` (`provider/cipher_gcm.rs:1705`) | 1 | block-only free | stated (block-validity only) |
| `DrbgCtx` (`provider/rand.rs:239`) | 1 | yes | stated, plus `release` obligation |
| `FreeOnDrop` (`ssl/statem/statem_srvr.rs:220`, `statem_clnt.rs:191`) | 2 | complete `*_free` | none; explicitly "no zero-validity claim" |

No safe destructor trait remains. The 46 `*Destroy` definitions are
deliberately module-local (their construction/release semantics differ); this
audit does **not** treat the shared `CtxDestroy` as evidence for a module-local
copy.

## 2. `CtxDestroy` implementations (136)

Rows are grouped by file; each type names its implementation line. `E` is an
empty body (`destroy_body` touches no field). "All-zero" states whether the
safe zalloc path can reach `Drop` and whether the body is sound for it; "staged"
means the construction path releases block-only before the object is complete.

| type (`file:line`) | path | destroy_body actions, in order | zero witness | status |
|---|---|---|---|---|
| `X509Info` (`asn1/x_info.rs:84`) | Z | `X509_free`, `X509_CRL_free`, `EVP_PKEY_free`, `OPENSSL_free(enc_data)` | all-zero slots NULL; each free NULL-tolerant | EST |
| `X509Pkey` (`asn1/x_pkey.rs:92`) | Z | `X509_ALGOR_free`, `ASN1_OCTET_STRING_free`, `EVP_PKEY_free`, block fields | all-zero NULL | EST |
| `AsyncWaitCtx` (`async/async_wait.rs:172`) | Z | walk `fds`; caller cleanup callback for live entries; release each node | zero `fds` skips loop | EST (subphase 38) |
| `OsslCmpCtx` (`cmp/cmp_ctx.rs:486`) | Z | 5 `OwnedStr`, 2 `X509`, name, store, 2 stacks, cert/chain/pkey, 2 octet strings, secret cleanse, digest, nonces, itavs, stacks, pkey/names/int, extensions, policies, cert/req, itavs; then remaining members | all fields NULL/zero; secret guarded by `!is_null` | EST |
| `OsslCmpSrvCtx` (`cmp/cmp_server.rs:151`) | Z | `OSSL_CMP_CTX_free(ctx)` | zero `ctx` NULL | EST |
| `BioCoreGlobals` (`context/core_bio.rs:107`) | E | none | E | EST |
| `OsslLibCtx` (`context/mod.rs:318`) | S/R | child delegate (if `ischild`), `context_deinit` | zero/partial accepted by authority teardown | EST |
| `OsslLibCtxThreads` (`context/thread_data.rs:100`) | Z | mutex free, condvar free | both NULL-tolerant | EST |
| `CtlogStore` (`ct/ct_log.rs:268`) | Z | `CRYPTO_free(propq)`, `sk_pop_free(logs)` | zero NULL/empty | EST |
| `Ctlog` (`ct/ct_log.rs:285`) | Z | `CRYPTO_free(name)`, `EVP_PKEY_free`, `CRYPTO_free(propq)` | zero NULL | EST |
| `CtlogStoreLoadCtx` (`ct/ct_log.rs:304`) | Z | `NCONF_free(conf)` | zero NULL | EST |
| `CtPolicyEvalCtx` (`ct/ct_policy.rs:117`) | Z | `X509_free(cert/issuer)`, `OwnedBlock::take(propq)` | zero NULL / `take` NULL | EST |
| `Sct` (`ct/ct_sct.rs:273`) | Z | four `CRYPTO_free` | zero NULL | EST |
| `SctCtx` (`ct/ct_sct_ctx.rs:185`) | Z | `EVP_PKEY_free`, 5 `CRYPTO_free`, remaining members | zero NULL | EST |
| `OsslDecoderInstance` (`decoder_lib.rs:111`) | Z | if decoder: `freectx(decoderctx)`, `OSSL_DECODER_free` | zero decoder NULL | EST (subphase 38) |
| `OsslDecoderCtx` (`decoder_meth.rs:774`) | Z | optional `cleanup(construct_data)`, `sk_pop_free(decoder_insts)`, pwdata clear | zero callbacks/NULL | EST (subphase 38) |
| `Dh` (`dh/object.rs:326`) | Z | method `finish` (if any), `free_ex_data`, lock, FFC params, `BN_clear_free` keys | zero method NULL; releasers NULL-tolerant | EST (subphase 38) |
| `DhPkeyCtx` (`dh/pmeth.rs:140`) | Z | `kdf_ukm` block, `kdf_oid` | zero NULL | EST |
| `Dsa` (`dsa/object.rs:264`) | Z | method `finish`, ex_data, lock, FFC params, `BN_clear_free` keys | zero method NULL | EST (subphase 38) |
| `DsaPkeyCtx` (`dsa/pmeth.rs:101`) | E | none | E | EST |
| `Dso` (`dso/mod.rs:294`) | Z | `OPENSSL_sk_free(meth_data)`, 2 names | zero NULL/empty | EST |
| `EcdsaSig` (`ec/ecdsa.rs:47`) | Z | `BN_clear_free(r)`, `BN_clear_free(s)` | zero NULL | EST |
| `EcxKey` (`ec/ecx_key.rs:126`) | S | `CRYPTO_free(propq)`, `CRYPTO_secure_clear_free(privkey,keylen)` | staged; no zero claim | EST |
| `EcGroup` (`ec/lib.rs:260`) | Z/R | plain: method `group_finish`, precomp, mont, generator, order, cofactor, seed, propq. **clear:** method `group_clear_finish`/`group_finish`, precomp, mont, `EC_POINT_clear_free`, `BN_clear_free`, seed | **defect D3 fixed:** clear body guards null `meth` on all-zero | EST (subphase 38) |
| `EcPoint` (`ec/lib.rs:301`) | Z/R | plain: method `point_finish`. **clear:** `point_clear_finish`/`point_finish` | **defect D4 fixed:** clear body guards null `meth` on all-zero | EST (subphase 38) |
| `EcPreCompSt` (`ec/mult.rs:69`) | Z | free each point, then points array | zero `points` NULL | EST |
| `EcPkeyCtx` (`ec/pmeth.rs:139`) | Z | `gen_group`, `co_key`, `kdf_ukm` | zero NULL | EST |
| `OsslEncoderInstance` (`encoder_lib.rs:494`) | Z | `freectx(encoderctx)`, `OSSL_ENCODER_free` | zero encoder NULL | EST (subphase 38) |
| `OsslEncoder` (`encoder_meth.rs:310`) | Z | name, parsed propdef, provider ref | zero NULL | EST |
| `OsslEncoderCtx` (`encoder_meth.rs:1246`) | Z | `sk_pop_free(encoder_insts)`, `CRYPTO_free(construct_data)`, pwdata clear | zero NULL/empty | EST (subphase 38) |
| `ConstructDataPkey` (`encoder_pkey.rs:301`) | E | none | E | EST |
| `DynamicDataCtx` (`engine/eng_dyn.rs:419`) | R | `DSO_free`, 2 names, `sk_pop_free(dirs)` | zero NULL | EST |
| `EnginePile` (`engine/eng_table.rs:96`) | Z | `sk_pop_free(sk)`, `ENGINE_free(funct)` | zero NULL | EST |
| `EvpAsymCipher` (`evp/asymcipher.rs:286`) | Z | `CRYPTO_free(type_name)`, provider ref | zero NULL | EST |
| `BioB64Ctx` (`evp/bio_enc.rs:267`) | Z | `EVP_ENCODE_CTX_free(base64)` | zero NULL | EST |
| `BioEncCtx` (`evp/bio_enc.rs:280`) | Z | `EVP_CIPHER_CTX_free(cipher)` | zero NULL | EST |
| `EvpCipher` (`evp/cipher.rs:404`) | Z | `CRYPTO_free(type_name)`, provider ref | zero NULL | EST |
| `EvpCipherCtx` (`evp/cipher_ctx.rs:310`) | Z | `EVP_CIPHER_CTX_reset` | reset accepts zero | EST |
| `EvpMd` (`evp/digest.rs:965`) | Z | `CRYPTO_free(type_name)`, provider ref | zero NULL | EST |
| `EvpMdCtx` (`evp/digest.rs:2103`) | Z | `EVP_MD_CTX_reset` | reset accepts zero | EST |
| `EvpEncodeCtx` (`evp/encode.rs:218`) | E | none | E | EST |
| `EvpKeyExch` (`evp/exchange.rs:164`) | R | `CRYPTO_free(type_name)`, provider ref | no zero claim | EST |
| `EvpKem` (`evp/kem.rs:199`) | Z | `CRYPTO_free(type_name)`, provider ref | zero NULL | EST |
| `EvpKeyMgmt` (`evp/keymgmt.rs:320`) | Z | `CRYPTO_free(type_name)`, provider ref | zero NULL | EST |
| `EvpPkey` (`evp/pkey.rs:421`) | S | `evp_pkey_free_it`, `free_ex_data`, lock, `sk_X509_ATTRIBUTE_pop_free(attributes)` | staged `RawPkey`; last-ref precondition; zero NULL (attributes stack no-op) | EST (subphase 38) |
| `EvpPkeyAsn1Method` (`evp/pkey_asn1.rs:572`) | Z | `CRYPTO_free(pem_str/info)`, remaining member releases | zero NULL | EST |
| `EvpPkeyCtx` (`evp/pkey_ctx.rs:1125`) | Z | free old ops/cached data, keymgmt, propquery, 2 keys, `BN_free(rsa_pubexp)` | zero NULL; old-op helpers handle zero | EST (subphase 38) |
| `EvpPkeyMethod` (`evp/pkey_ctx.rs:2228`) | E | none | E | EST |
| `EvpRand` (`evp/rand.rs:321`) | Z | `CRYPTO_free(type_name)`, provider ref | zero NULL | EST |
| `EvpSignature` (`evp/signature.rs:359`) | Z | `CRYPTO_free(type_name)`, provider ref | zero NULL | EST |
| `EvpSkeyMgmt` (`evp/skeymgmt.rs:228`) | Z | `CRYPTO_free(type_name)`, provider ref | zero NULL | EST |
| `HmacCtx` (`mac/hmac.rs:100`) | Z | `hmac_ctx_cleanup`, then free `i_ctx`/`o_ctx`/`md_ctx` | cleanup resets; free NULL-tolerant | EST |
| `OcbCtx` (`modes/ocb.rs:89`) | Z | `CRYPTO_clear_free(l, max_l_index*16)`, cleanse context | zero `l` NULL, zero index | EST |
| `Siv128Context` (`modes/siv128.rs:135`) | E | none | E | EST |
| `OsslGlobalProperties` (`property/globals.rs:89`) | Z | `ossl_property_free(list)` | zero NULL | EST |
| `ChildProvGlobals` (`provider/child.rs:197`) | Z | `CRYPTO_THREAD_lock_free(lock)` | zero NULL | EST |
| `ProviderConfGlobal` (`provider/conf.rs:176`) | S | `sk_pop_free(activated_providers)`, lock | staged `RawProviderConf` | EST |
| `ProvCtx` (`provider/ctx.rs:80`) | E | none | E | EST |
| `BarePubkey` (`provider/decode_der2key.rs:595`) | Z | `ASN1_OBJECT_free`, `ASN1_BIT_STRING_free` | zero NULL | EST |
| `Epki2pkiCtx` (`provider/decode_epki2pki.rs:104`) | E | none | E | EST |
| `Pem2DerCtx` (`provider/decode_pem2der.rs:264`) | E | none | E | EST |
| `Pvk2keyCtx` (`provider/decode_pvk2key.rs:125`) | E | none | E | EST |
| `Spki2TypespkiCtx` (`provider/decode_spki2typespki.rs:95`) | E | none | E | EST |
| `ProvEcCtx` (`provider/ec_kem.rs:177`) | Z | `CRYPTO_clear_free(ikm,ikmlen)`, clear 2 key refs | zero NULL | EST |
| `EcxGenCtx` (`provider/ecx_kmgmt.rs:376`) | Z | `CRYPTO_clear_free(ikm)`, propq | zero NULL | EST |
| `Key2anyCtx` (`provider/encode_key2any.rs:454`) | Z | pwdata clear, `EVP_CIPHER_free` | zero/embedded zero | EST |
| `Key2msCtx` (`provider/encode_key2ms.rs:83`) | Z | pwdata clear | embedded zero | EST |
| `FileCtxSt` (`provider/file_store.rs:351`) | Z | `CRYPTO_free(uri)`; if not `IS_DIR`: decoder ctx + propq + input type | zero type tag; NULL frees | EST |
| `Any2objCtx` (`provider/file_store_any2obj.rs:97`) | E | none | E | EST |
| `KdfData` (`provider/keymgmt.rs:521`) | E | none | E | EST |
| `DhGenCtx` (`provider/keymgmt.rs:531`) | Z | `CRYPTO_free(mdname/mdprops)`, `CRYPTO_clear_free(seed,seedlen)` | zero NULL | EST |
| `MacKey` (`provider/mac_legacy_kmgmt.rs:343`) | Z | secure clear private key, propq, cipher reset | zero NULL/embedded zero | EST |
| `MacGenCtx` (`provider/mac_legacy_kmgmt.rs:841`) | Z | secure clear private key, cipher reset | zero NULL/embedded zero | EST |
| `MlDsaGenCtx` (`provider/ml_dsa_kmgmt.rs:196`) | Z | cleanse entropy array, release propq, remaining members | embedded zero | EST |
| `ProvMlKemCtx` (`provider/ml_kem_kem.rs:85`) | Z | cleanse entropy if non-NULL | zero pointer skips | EST |
| `ProvMlxKemCtx` (`provider/mlx_kem.rs:84`) | E | none | E | EST |
| `ProvRsaCtx` (`provider/rsa_kem.rs:103`) | Z | `RSA_free(rsa)` | zero NULL | EST |
| `ProvSeedSrc` (`provider/seed_src.rs:337`) | E | none | E | EST |
| `ProvTestRng` (`provider/seed_src.rs:351`) | Z | release entropy/nonce, lock | zero NULL | EST |
| `ProvSkey` (`provider/skeymgmt.rs:116`) | Z | `CRYPTO_clear_free(data,length)` | zero NULL | EST |
| `SlhDsaGenCtx` (`provider/slh_dsa_kmgmt.rs:167`) | Z | cleanse entropy, release propq | embedded zero | EST |
| `ProvSlhDsaCtx` (`provider/slh_dsa_sig.rs:236`) | Z | free hash ctx, propq, cleanse add_random | zero NULL/embedded zero | EST |
| `ProvSm2Ctx` (`provider/sm2_enc.rs:101`) | Z | `EC_KEY_free`, digest reset | zero NULL | EST |
| `RandGlobal` (`rand/rand_lib.rs:422`) | R | lock, 2 DRBG ctx, 7 names | no zero claim; constructed global | EST |
| `RsaPrimeInfo` (`rsa/mp.rs:67`) | Z | `BN_free(pp)`, coefficient members | zero NULL | EST |
| `Rsa` (`rsa/object.rs:589`) | Z | method `finish`, ex_data, lock, `BN_free(n/e)`, `BN_clear_free(d,p,q,dmp1,dmq1,iqmp)`, prime infos, blinding | zero method NULL; NULL BNs | EST (subphase 38) |
| `RsaPkeyCtx` (`rsa/pmeth.rs:189`) | Z | 5 member releases (including `BN_free` pubexp) | zero NULL | EST |
| `BioBufferCtx` (`runtime/bio/bf_buff.rs:85`) | Z | `OwnedBlock::take(ibuf/obuf)` | zero NULL | EST |
| `BioLineBufferCtx` (`runtime/bio/bf_lbuf.rs:58`) | Z | `OwnedBlock::take(obuf)` | zero NULL | EST |
| `NbioTest` (`runtime/bio/bf_nbio.rs:70`) | E | none | E | EST |
| `PrefixCtx` (`runtime/bio/bf_prefix.rs:58`) | Z | `CRYPTO_free(prefix)` if non-NULL | zero NULL | EST |
| `BioAccept` (`runtime/bio/bss_acpt.rs:228`) | Z | 6 `OwnedBlock::take`, `BIO_ADDRINFO_free`, chain | zero NULL | EST |
| `BioBioSt` (`runtime/bio/bss_bio.rs:87`) | Z | `OwnedBlock::take(buf)` | zero NULL | EST |
| `BioConnect` (`runtime/bio/bss_conn.rs:240`) | Z | 2 `OwnedBlock::take`, `BIO_ADDRINFO_free` | zero NULL | EST |
| `BioDgramData` (`runtime/bio/bss_dgram.rs:275`) | E | none | E | EST |
| `BioDgramPairSt` (`runtime/bio/bss_dgram_pair.rs:259`) | Z | lock free | zero NULL | EST |
| `BioBufMem` (`runtime/bio/bss_mem.rs:66`) | Z | `OwnedBlock::take(readp)` | zero NULL | EST |
| `BssSockData` (`runtime/bio/bss_sock.rs:385`) | E | none | E | EST |
| `CompCtx` (`runtime/bio/comp.rs:167`) | Z | method `finish` if present | zero method NULL | EST (subphase 38) |
| `OsslCoreBio` (`runtime/bio/core_bio.rs:102`) | E | none | E | EST |
| `BioMethod` (`runtime/bio/method.rs:64`) | Z | `CRYPTO_free(name)` | zero NULL | EST |
| `ProbeCtx` (`runtime/bio/owned.rs:272`) | E (test) | records a call only | E; test-only | EST |
| `CryptoThread` (`runtime/thread_arch.rs:166`) | Z | 2 mutexes, condvar, thread handle block | zero NULL | EST |
| `IndicatorCb` (`selftest/indicator.rs:48`) | E | none | E | EST |
| `SelfTestCb` (`selftest/mod.rs:112`) | E | none | E | EST |
| `OsslSelfTest` (`selftest/mod.rs:175`) | E | none | E | EST |
| `BioSsl` (`ssl/bio_ssl.rs:102`) | E | none | E | EST |
| `Dtls1State` (`ssl/d1_lib.rs:107`) | E | none | E | EST |
| `Cert` (`ssl/ssl_lib.rs:995`) | S | clear 12 cert-key slots, `drop_in_place(custext)`, psk hint slot, `dh_tmp` | raw `RawCtx`; `custext` written before `assume_init` | EST |
| `SslCtx` (`ssl/ssl_lib.rs:3155`) | S/Z | 4 stacks, session cache, SRP, CA names, verify param, ex_data, store, `cert_free`, DANE, CT log, 4 member-buffer slots, supportedgroups, lock, propq slot | zero block validated before fallible members; NULL-tolerant | EST (subphase 41: field-by-field audit and S1–S4 fixes; not `DISCHARGED`) |
| `Ssl` (`ssl/ssl_lib.rs:3520`) | S/Z | 5 stacks, CA names, session, SRP, ticket, DTLS, 2 BIOs, 4 EVP ctxs/ciphers, 2 keys, cert, 2 chains, verify param, `cert_free`, 8 slots, supportedgroups, pha, ex_data, 2 `SSL_CTX_free`, lock | zero block valid; two context refs balanced | EST (subphase 41: field-by-field audit and S1–S4 fixes; not `DISCHARGED`) |
| `DanetlsRecord` (`ssl/ssl_lib.rs:11436`) | Z | `CRYPTO_free(data)`, `EVP_PKEY_free(spki)` | zero NULL | EST |
| `SslSession` (`ssl/ssl_sess.rs:559`) | Z | ex_data, cleanse master key/id, peer, peer_rpk, chain, 7 member-buffer slots | zero NULL/arrays | EST (subphase 40: destroying sentinel; re-entrant ex-data free test passes) |
| `OsslStoreCtx` (`store/store_lib.rs:262`) | E | none (`ossl_store_close_it` is explicit) | E | EST |
| `OsslStoreSearch` (`store/store_lib.rs:272`) | E | none | E | EST |
| `OsslStoreInfo` (`store/store_lib.rs:281`) | Z | switch on `type_`; one member per tag | zero tag is not a case | EST |
| `OsslStoreLoader` (`store/store_meth.rs:163`) | Z | provider ref if non-NULL | zero NULL | EST |
| `TsVerifyCtx` (`ts/ts_verify_ctx.rs:79`) | Z | `TS_VERIFY_CTX_cleanup` (re-zeroes) | zero/cleanup | EST |
| `UiString` (`ui/ui_lib.rs:475`) | Z | free `out_string` iff `OUT_STRING_FREEABLE` | zero flags skip | EST |
| `Ui` (`ui/ui_lib.rs:515`) | Z | if `UI_FLAG_DUPL_DATA`: `ui_destroy_data`; strings; ex_data; lock | zero flags skip | EST (subphase 38) |
| `UiMethod` (`ui/ui_lib.rs:545`) | Z | ex_data, name | zero NULL | EST |
| `ByDirHash` (`x509/by_dir.rs:363`) | E | none | E | EST |
| `ByDirEntry` (`x509/by_dir.rs:371`) | S | `CRYPTO_free(dir)`, `sk_pop_free(hashes)` | malloc + all read fields written before drop | EST |
| `ByDir` (`x509/by_dir.rs:386`) | Z/S | `sk_pop_free(dirs)`, `BUF_MEM_free`, lock | zero NULL | EST |
| `CachedStore` (`x509/by_store.rs:282`) | Z | `CRYPTO_free(uri)`, propq slot clear | zero NULL | EST |
| `X509PolicyCache` (`x509/pcy_cache.rs:84`) | Z/S | `ossl_policy_data_free`, `sk_pop_free(data)` | zero NULL | EST |
| `X509V3ExtMethod` (`x509/v3_lib.rs:278`) | E/R | none | E; row copied whole before drop | EST |
| `X509Purpose` (`x509/v3_purp.rs:475`) | R | free name/sname iff dynamic flag | constructed row; no zero claim | EST |
| `ConfValue` (`x509/v3_utl.rs:479`) | R | free name/value/section | constructed record; no zero claim | EST |
| `X509Lookup` (`x509/x509_lu.rs:739`) | Z | method `free` hook if method non-NULL | zero method NULL | EST (subphase 38) |
| `X509Object` (`x509/x509_lu.rs:758`) | Z | `x509_object_free_internal` by tag | zero tag `X509_LU_NONE` | EST |
| `X509Store` (`x509/x509_lu.rs:770`) | Z | shutdown/free each lookup, free stack, objects, ex_data, param, lock | zero stack/objects/lock | EST (subphase 42: lookup-`free` and ex-data re-entry controls pass; partial-release path retained) |
| `X509Trust` (`x509/x509_trust.rs:215`) | R | free name iff dynamic flag | constructed row; no zero claim | EST |
| `X509StoreCtx` (`x509/x509_vfy.rs:319`) | Z | `X509_STORE_CTX_cleanup`, propq slot clear | cleanup preserves propq; zero accepted | EST |
| `X509VerifyParam` (`x509/x509_vpm.rs:342`) | Z/R | policies, hosts, peername, email, ip | zero NULL | EST |
| `X509CrlMethod` (`x509/x_crl.rs:272`) | E/S | none | E | EST |

**CtxDestroy subtotal: 136 = 136 EST + 0 CON.** Subphase 38 independently
adjudicated the former 19 `CONTRACTED` rows: 16 are promoted to `ESTABLISHED`
(`AsyncWaitCtx`, `OsslDecoderInstance`, `OsslDecoderCtx`, `Dh`, `Dsa`,
`OsslEncoderInstance`, `OsslEncoderCtx`, `EvpPkey`, `EvpPkeyCtx`, `Rsa`, `CompCtx`,
`SslSession`, `Ui`, `X509Lookup`, `EcGroup`, `EcPoint`); subphase 41 promoted
`SslCtx` and `Ssl`; subphase 42 promoted `X509Store` (see “Subphase 42”).
(`ProvAesSivCtx`/`ProvAesGcmSivCtx` are `CipherDestroy`, counted below.)

## 3. `CipherDestroy` implementations (27)

| type (`file:line`) | path | destroy_body actions | zero witness | status |
|---|---|---|---|---|
| `ProvAesCtx` (`provider/cipher.rs:592`) | Z | `ossl_cipher_generic_reset_ctx` (`tlsmac` if `alloced`) | zero `alloced` skips | EST |
| `ProvCamelliaCtx` (`:603`) | Z | same | same | EST |
| `ProvTdesCtx` (`:614`) | Z | same | same | EST |
| `ProvAesWrapCtx` (`:625`) | Z | same | same | EST |
| `ProvAesXtsCtx` (`:636`) | Z | same | same | EST |
| `ProvSm4XtsCtx` (`:647`) | Z | same | same | EST |
| `ProvAesOcbCtx` (`:658`) | Z | `CRYPTO_ocb128_cleanup(ocb)`, generic reset | zero `l` NULL | EST |
| `ProvAesCcmCtx` (`:673`) | Z | E | E | EST |
| `ProvAriaCcmCtx` (`:683`) | Z | E | E | EST |
| `ProvSm4CcmCtx` (`:693`) | Z | E | E | EST |
| `ProvAesSivCtx` (`:703`) | Z | `((*(*ptr).hw).cleanup)(ptr)` guarded by a NULL `hw` test | **D1 fixed:** zero `hw` skips the teardown; deterministic control | EST (subphase 42) |
| `ProvNullCtx` (`:714`) | Z | E | E | EST |
| `ProvAesHmacSha1Ctx` (`:724`) | Z | generic reset | zero `alloced` | EST |
| `ProvAesHmacSha256Ctx` (`:735`) | Z | generic reset | zero `alloced` | EST |
| `ProvAesGcmSivCtx` (`:746`) | Z | `CRYPTO_clear_free(aad,aad_len)`, `((*(*ptr).hw).clean_ctx)(ptr)` guarded by a NULL `hw` test | **D2 fixed:** zero `hw` skips the teardown; deterministic control | EST (subphase 42) |
| `ProvChacha20Ctx` (`:761`) | Z | generic reset | zero `alloced` | EST |
| `ProvChacha20Poly1305Ctx` (`:772`) | Z | generic reset | zero `alloced` | EST |
| `ProvSm4Ctx` (`:783`) | Z | generic reset | zero `alloced` | EST |
| `ProvAriaCtx` (`:794`) | Z | generic reset | zero `alloced` | EST |
| `ProvCastCtx` (`:21935`) | Z | generic reset (legacy macro) | zero `alloced` | EST |
| `ProvBlowfishCtx` (`:21946`) | Z | generic reset | zero `alloced` | EST |
| `ProvIdeaCtx` (`:21957`) | Z | generic reset | zero `alloced` | EST |
| `ProvSeedCtx` (`:21968`) | Z | generic reset | zero `alloced` | EST |
| `ProvRc2Ctx` (`:21979`) | Z | generic reset | zero `alloced` | EST |
| `ProvRc4Ctx` (`:21990`) | Z | generic reset | zero `alloced` | EST |
| `ProvDesCtx` (`:22001`) | Z | generic reset | zero `alloced` | EST |
| `ProvRc4HmacMd5Ctx` (`:22012`) | Z | generic reset | zero `alloced` | EST |

**Subtotal: 27; EST 27, CON 0.**

## 4. `KdfDestroy` (14), `MacDestroy` (7), `DrbgCtx` (5), `GcmDestroy` (3), `FreeOnDrop` (7)

| family / types (`file:line`) | path | actions | zero witness | status |
|---|---|---|---|---|
| `KdfSskdf` (`kdf.rs:474`), `KdfX942` (`:485`), `KdfPkcs12` (`:496`), `KdfSshkdf` (`:507`), `KdfPbkdf2` (`:518`), `KdfHkdf` (`:529`), `Tls1Prf` (`:541`), `Kbkdf` (`:552`), `KdfScrypt` (`:563`), `Krb5kdfCtx` (`:579`), `KdfHmacDrbg` (`:590`), `KdfPbkdf1` (`:640`), `KdfPvk` (`:651`) | Z | per-row `reset`/`cleanup`: free digest/MAC/cipher, cleanse key material, zero struct | zero fields NULL/zero; resets accept zero | EST |
| `KdfArgon2` (`kdf.rs:601`) | Z | clear-free pwd/salt/secret/ad (each non-NULL), free md/mac/propq, zero struct | zero NULL skips | EST |
| **Kdf subtotal 14: EST 14** | | | | |
| `CmacData` (`mac.rs:396`) | Z | `CMAC_CTX_free`, cipher reset | zero NULL/embedded | EST |
| `GmacData` (`mac.rs:905`) | Z | `EVP_CIPHER_CTX_free`, cipher reset | zero NULL/embedded | EST |
| `SiphashData` (`mac.rs:1373`) | Z | E | E | EST |
| `HmacData` (`mac.rs:1817`) | Z | `HMAC_CTX_free`, digest reset, key clear-free | zero NULL/embedded | EST |
| `MacData` BLAKE2 (`mac.rs:2453`) | Z | cleanse embedded key array | embedded zero | EST |
| `Poly1305Data` (`mac.rs:2904`) | Z | E | E | EST |
| `KmacData` (`mac.rs:3357`) | Z | `EVP_MD_CTX_free`, digest reset, cleanse key/custom arrays | zero NULL/embedded | EST |
| **Mac subtotal 7: EST 7** | | | | |
| `ProvDrbg` (`rand.rs:509`) | Z | lock free | zero NULL | EST |
| `ProvDrbgNonceGlobal` (`rand.rs:544`) | Z | lock free | zero NULL | EST |
| `ProvDrbgCtr` (`rand.rs:1900-area, impl at 1899`) | Z | free 3 cipher ctxs + 2 ciphers | zero NULL | EST |
| `ProvDrbgHash` (`rand.rs:3346`) | Z | `EVP_MD_CTX_free`, digest reset | zero NULL | EST |
| `ProvDrbgHmac` (`rand.rs:4437`) | Z | `EVP_MAC_CTX_free`, digest reset | zero NULL | EST |
| **Drbg subtotal 5: EST 5** | | | | |
| `ProvAesGcmCtx` (`cipher_gcm.rs:1820`), `ProvAriaGcmCtx` (`:1827`), `ProvSm4GcmCtx` (`:1834`) | B | none: owner's cleansing block release is the whole `*_gcm_freectx` | block-only; zero block valid | EST |
| **Gcm subtotal 3: EST 3** | | | | |
| `FreeOnDrop` impls: `EVP_MD_CTX` / `EVP_CIPHER_CTX` / `HMAC_CTX` / `EVP_PKEY` (srvr), `EVP_MD_CTX` / `SSL_SESSION` / `EVP_PKEY` (clnt) (`statem_srvr.rs:268-312`, `statem_clnt.rs:239-270`) | N | complete matching `*_free` | no zero claim; `*_new` answer only | EST |
| **FreeOnDrop subtotal 7: EST 7** | | | | |

**Grand total: 199 = EST 199, CON 0.**

## 5. `Drop` owners of destructor/member-buffer resources

| owner (`file:line`) | bodies | action | finding |
|---|---:|---|---|
| `impl<T: CtxDestroy> Drop for OwnedCtx` | 42 | `T::destroy_body` then `CRYPTO_free` at `T::FILE`/`T::LINE_FREE` | one body per module; block release exactly once; no owner frees the block inside `destroy_body` except the `DrbgCtx::release` split |
| `impl<T: CtxDestroy> Drop for RawCtx` (`runtime/bio/owned.rs:201`, `ssl/ssl_lib.rs:685`, `provider/slh_dsa_sig.rs:296`, `provider/sm2_enc.rs:208`) | 4 | block-only release; never `destroy_body` | the staged-construction window; correct for partially built storage |
| `impl<T: CipherDestroy> Drop for OwnedCtx` / `OwnedRaw` | 2 | body then `CRYPTO_clear_free(size_of::<T>())`; partial copies plain-free only | `OwnedRaw` deliberately skips the destructor on a partially repaired copy |
| `impl<T: KdfDestroy> Drop for OwnedCtx` | 1 | body then plain free | single release |
| `impl<T: MacDestroy> Drop for OwnedCtx` / `OwnedRaw` | 2 | body then plain free; partial copies block-only | single release |
| `impl<T: DrbgCtx> Drop for OwnedCtx` / `OwnedRaw` | 2 | body then `T::release`; partial blocks `release` only | split is explicit |
| `impl<T: GcmDestroy> Drop for OwnedCtx` / `OwnedRaw` | 2 | cleansing block release; partial copies plain-free | single release |
| `impl<T: FreeOnDrop> Drop for OwnedCtx` | 2 | `T::free_on_drop` | no block/destructor split; object is a `*_new` answer |
| non-generic `impl Drop for OwnedCtx` (`evp/bio_ok:278`, `bn/blinding:212`, `hpke:1248`, `provider/decode_msblob2key:151`, `provider/ecx_exch:133`, `provider/mac_legacy_sig:163`) | 6 | member frees then block release; HPKE calls `destroy_ctx_body` | audited: `destroy_ctx_body` is all-NULL-safe; `bn/blinding` uses `Box::from_raw` because its block is a `Box` (not the C seam); others single release |
| `impl Drop for OwnedBlock` | 17 | one `CRYPTO_free` at stored `(file,line)` | single release; representative `runtime/bio/owned.rs:237`, `ssl/ssl_lib.rs:742` |
| `impl Drop for OwnedBuf` / `OwnedStr` | 128 | one `CRYPTO_free` or `CRYPTO_clear_free` at stored coordinates | uniform pattern; no destructor body and no enclosing-block overlap |
| `impl Drop for OwnedScratch` | 2 | one `CRYPTO_free` | single release |

No `Drop` owner in this inventory calls `destroy_body` and then releases the
same block again; the `OwnedRaw`/`RawCtx` split exists precisely to avoid that
on partially built or partially repaired storage.

## 6. Defects / inconsistencies (STOP findings)

These were reported by the independent audit; the four defect sites are now
fixed at the source by the sweep-37 guards below. Each was a single case of a
destructor accepting an invalid zero state. The affected boundaries remain
`CONTRACTED`/`ESTABLISHED`, **not** `DISCHARGED`: a source guard plus a
deterministic zero-state negative control is not the independent evidence §7
requires, and no Miri/sanitizer/differential run was added by this fix.

1. **D1 — `ProvAesSivCtx` null `hw` dereference.**
   `src/provider/cipher.rs:703-709`. The impl comment at `:700-702` claims
   "(b) holds: an all-zero context is valid with every release a no-op", but
   `destroy_body` executes `((*(*ptr).hw).cleanup)(ptr.cast())` with no NULL
   test. The safe `OwnedCtx::<ProvAesSivCtx>::new()` at `:488-493` returns an
   owner over a `CRYPTO_zalloc` block, and `Drop` (`:516-533`) runs
   `destroy_body`; safe code in the module that drops the owner before
   installing `hw` causes a null dereference. Current
   `aes_siv_newctx` (`:9887-9897`) installs `hw` immediately before
   `into_raw`, so no current call site reaches it — the defect is in the safe
   abstraction's contract, not an observed path. Either the body must test
   `hw` or the zero-validity claim must be removed and the safe zalloc
   constructor replaced by a staged one.
   **FIXED — sweep-37.** `ProvAesSivCtx::destroy_body` (`src/provider/cipher.rs:703-718`)
   now guards the hardware teardown with `if !(*ptr).hw.is_null()` at `:713`.
   The authority's `aes_siv_freectx` (`cipher_aes_siv.c:49-57`) calls
   `ctx->hw->cleanup(ctx)` unconditionally, but `aes_siv_newctx`
   (`cipher_aes_siv.c:37-46`) installs `hw` before returning, so the authority
   never drops a context whose `hw` was never installed. The guard is therefore
   a failure-path safety improvement for the safe `OwnedCtx::new` zero block; it
   does not change the constructed path, whose order (`hw->cleanup`, then the
   block's cleansing release) is unchanged. Negative control:
   `a_zeroed_siv_context_drops_without_a_hardware_table`
   (`src/provider/cipher.rs:22662-22696`).
2. **D2 — `ProvAesGcmSivCtx` null `hw` dereference.**
   `src/provider/cipher.rs:746-755`. Same contradiction (`:743-745` claim,
   `:753` `((*(*ptr).hw).clean_ctx)(ptr.cast())`). `OwnedCtx::new` is the same
   safe zalloc constructor; `ossl_aes_gcm_siv_newctx` installs `hw` at
   `:13804` before `into_raw`, so no current path triggers it. Same required
   fix.
   **FIXED — sweep-37.** `ProvAesGcmSivCtx::destroy_body`
   (`src/provider/cipher.rs:755-773`) keeps the unconditional AAD release and
   guards the hardware teardown with `if !(*ptr).hw.is_null()` at `:768`. The
   authority's `ossl_aes_gcm_siv_freectx` (`cipher_aes_gcm_siv.c:44-54`)
   dereferences `ctx->hw` unconditionally, but
   `ossl_aes_gcm_siv_newctx` (`cipher_aes_gcm_siv.c:27-42`) installs it before
   returning. Failure-path improvement only; the constructed order (AAD release,
   `hw->clean_ctx`, then the block's cleansing release) is unchanged. The same
   negative control covers this context.
3. **D3 — `EcGroup::clear_destroy_body` null `meth` dereference.**
   `src/ec/lib.rs:277-294`, specifically `:280-281`
   (`let meth = (*ptr).meth; (*meth).group_clear_finish`). The trait
   `ec::CtxDestroy` states at `:117-119` that *both* bodies are sound for an
   all-zero block, and the impl comment repeats it at `:255-259`. An all-zero
   `EcGroup` has `meth == NULL`. `OwnedCtx::new` (`:161-171`) is the safe
   zalloc constructor, but it sets `cleansing = false`; `clear_destroy_body`
   is selected only by the unsafe `from_raw_clear` (`:203-210`), which requires
   a live block. The false claim is a latent soundness hole if a safe
   cleansing constructor is ever added. The plain `destroy_body` is null-safe
   because it uses `meth.as_ref()`.
   **FIXED — sweep-37.** `EcGroup::clear_destroy_body` (`src/ec/lib.rs:280-301`)
   now guards the method callback block with `if !(*ptr).meth.is_null()` at
   `:284`. The authority's `EC_GROUP_clear_free` (`crypto/ec/ec_lib.c:142-159`)
   dereferences `group->meth` unconditionally, but no constructed group has a
   NULL method (`ossl_ec_group_new_ex`, `ec_lib.c:30-75`, rejects one), so the
   guard is a failure-path safety improvement for the zero state only. The
   plain body remains null-safe through `meth.as_ref()` (`:267`), and the
   clear-body order (finish callback, then the member releases) is unchanged.
   Negative control covers both this body and the plain one:
   `a_zeroed_group_and_point_drop_through_both_bodies`
   (`src/ec/lib.rs:3107-3178`).
4. **D4 — `EcPoint::clear_destroy_body` null `meth` dereference.**
   `src/ec/lib.rs:311-320`, specifically `:314-315`. Identical to D3; the
   plain body at `:302-309` is null-safe, the clear body is not.
   **FIXED — sweep-37.** `EcPoint::clear_destroy_body` (`src/ec/lib.rs:320-334`)
   now guards the method callback block with `if !(*ptr).meth.is_null()` at
   `:324`. The authority's `EC_POINT_clear_free` (`crypto/ec/ec_lib.c:758-768`)
   dereferences `point->meth` unconditionally, but no constructed point has a
   NULL method (`EC_POINT_new` requires one), so this is again a failure-path
   improvement only. The plain body is already null-safe through `meth.as_ref()`
   (`:314`), and the clear-body callback/order is unchanged. The same negative
   control covers this body.

**No other STOP was found in the audited set:** no `destroy_body` releases the
enclosing block, no member is released twice by a body, and no body reads a
field that the documented construction path leaves uninitialised. The four
sites above were zero-state contract violations; D1/D2 were reachable by safe
code inside their module, D3/D4 are latent behind an unsafe reclaim. All four
now carry the guards above.

**Non-soundness inconsistencies recorded (no STOP):**

- `Ssl::destroy_body` inconsistency **resolved in sweep-37**
  (`src/ssl/ssl_lib.rs:3524-3533`): the implementation raw-frees
  `session_ticket` (`CRYPTO_free`, `:3544`), which is the authority's contract
  (`tls1_free`, `ssl/t1_lib.c:122`), and the comment now says so rather than
  claiming a `MemberBufSlot`. No ownership change: a single release, not a
  double-free. `TlsSessionTicketExt` is one record with its data inline
  (`data = self + 1`), so it has no separate byte-length pair to model.
- `PROGRESS.md`'s "46 module-local destructor traits" counts the `*Destroy`
  definitions; `DrbgCtx` and the two `FreeOnDrop` copies make the definition
  total 49 (42 `CtxDestroy` + 4 other `*Destroy` + `DrbgCtx` + 2 `FreeOnDrop`).
- `GcmDestroy` has no `destroy_body`; its only implementer obligation is the
  `FILE` constant and the "block-only `*_gcm_freectx`" statement. This is
  sound for the three GCM rows but is a different trait shape from the other
  destructor traits; a future GCM row that owns a member would need a body.

## Adjudication (subphase 38)

Independent source adjudication of the 19 `CONTRACTED` `CtxDestroy` rows. For
each row the body, every constructor that can publish the object, and every
path that can reach `Drop`/`destroy_body` were read. `ESTABLISHED` below means
(a) the zero/partial state was checked field by field where the construction
path can reach the body, (b) each member release was traced and the body was
found not to release the enclosing block, and (c) no safe caller can hand the
body an invalid state. It is **not** `SAFETY_DISCHARGED`: no Miri, sanitizer,
differential or independent §7 package was run.

### Promoted to `ESTABLISHED` (16)

| row | source witnesses |
|---|---|
| `AsyncWaitCtx` | body `src/async/async_wait.rs:172-200`; zero `fds` NULL skips `:176`; `set_wait_fd` writes key/fd/custom_data/cleanup/add/next before linking `:300-309`; node release exactly once `:196-198`; owner release `:152-162`; callback ABI is the stored `FdLookup.cleanup` signature `:49-52` |
| `OsslDecoderInstance` | body `src/decoder_lib.rs:111-130`; zero `decoder` skips `:117`; construction `:296-373`; error arm `fail_instance` `:137-140`; `dup` is `RawCtx` and validates only after writing `:404-456`; free wrapper `:387-391` |
| `OsslDecoderCtx` | body `src/decoder_meth.rs:774-787`; `zalloc` constructor `:809-813`; `OPENSSL_sk_pop_free(NULL)` no-op `src/runtime/stack.rs:483-493`; `ossl_pw_clear_passphrase_data` is type-gated on zero `src/passphrase.rs:207-217`; free wrapper `:880-885` |
| `Dh` | body `src/dh/object.rs:326-366`; `meth` guard `:334-341`; staged constructor writes `references`/`meth`/`lock`/`libctx`/`engine` before `assume_init` `:229-318`; FFC cleanup NULL-tolerant `src/ffc/params.rs:190-200`; last-ref gate `:380-401` |
| `Dsa` | body `src/dsa/object.rs:264-304`; `meth` guard `:272-279`; staged constructor `:168-256`; same FFC cleanup witness; last-ref gate `:318-339` |
| `OsslEncoderInstance` | body `src/encoder_lib.rs:494-511`; zero `encoder` skips `:498`; construction `:384-469`; error arm `:477-480`; free wrapper `:525-532` |
| `OsslEncoderCtx` | body `src/encoder_meth.rs:1246-1256`; `zalloc` constructor `:1269-1274`; same stack and pwdata witnesses; free wrapper `:1339-1345` |
| `EvpPkey` | body `src/evp/pkey.rs:421-448`; staged `RawPkey` is `unsafe`-only and releases the block alone `:474-486`; `EVP_PKEY_new` writes all members before `finish`; last-ref gate `:650-674`; zero-validity witness: all-pointer/scalar record, NULL lock/ex-data/attributes accepted; attributes released by `sk_X509_ATTRIBUTE_pop_free` (`p_lib.c:1849`) |
| `EvpPkeyCtx` | body `src/evp/pkey_ctx.rs:1125-1156`; safe `OwnedCtx::new` zero state `:291-299`; `free_old_ops` dispatches from `operation` (zero selects no arm) `:904-947`; cached data is two NULL frees `:1006-1016`; free wrapper `:1111-1114` |
| `Rsa` | body `src/rsa/object.rs:589-651`; `meth` guard `:597-603`; staged constructor `:371-471`; blinding release is NULL-safe `src/runtime/sparse_array.rs:488-498,558-568`; last-ref gate `:685-707` |
| `CompCtx` | body `src/runtime/bio/comp.rs:167-180`; zero `meth` skips `:171`; constructor sets `meth` before `init` `:271-293`; free wrapper `:343-346` |
| `SslSession` | body `src/ssl/ssl_sess.rs:559-592`; safe `OwnedCtx::new` `:216-224`; constructors `:304-332`, `:349-497`; arrays are exactly `TLS13_MAX_RESUMPTION_PSK_LENGTH`/`SSL_MAX_SSL_SESSION_ID_LENGTH` (`src/ssl/ssl_lib.rs:2458-2470`); member slots clear NULL safely `src/ssl/ssl_lib.rs:2725-2746,2793-2799`; last-ref gate `:535-549` |
| `Ui` | body `src/ui/ui_lib.rs:515-538`; zero `flags` skips the callback `:519`; constructor sets `lock`/`meth` before any flag can be set `:586-632`; `UI_FLAG_DUPL_DATA` only set after `meth` is live `:1441-1453`; free wrapper `:664-667` |
| `X509Lookup` | body `src/x509/x509_lu.rs:739-751`; zero `method` NULL skips `:744-749`; `RawLookup` constructor/error arm `:1022-1032,663-675`; free wrapper `:1049-1052` |
| `EcGroup` | plain body `src/ec/lib.rs:263-278` reads `meth` through `as_ref` `:267`; clear body guards `meth` `:284`; safe `OwnedCtx::new` path `:371-400`; clear selection is `unsafe from_raw_clear` only `:493-497`; deterministic zero-state control `:3107-3178` |
| `EcPoint` | plain body `src/ec/lib.rs:310-318` uses `as_ref` `:314`; clear body guards `meth` `:324`; safe constructor `:1460-1479`; clear selection `:1504-1508`; same zero-state control |

### Retained `CONTRACTED` (1)

Subphase 39 re-checked these rows as runtime/alias boundaries. The
refcount gates are atomic and layout-compatible. Subphase 40 applies the
destroying-sentinel protocol to all four reference-counted types and adds a
deterministic re-entrancy test per type. Subphase 41 promoted `SslCtx` and
`Ssl` to `ESTABLISHED` (see below); `X509Store` remains `CONTRACTED`.

- **`SslCtx`** and **`Ssl`** — **promoted to `ESTABLISHED` in subphase 41**
  after the field-by-field ownership audit and the alias/lifecycle fixes (see
  “Subphase 41” below).
- **`X509Store`** (`src/x509/x509_lu.rs:770-794`). **Refcount fixed in subphase
  39:** `references` is `AtomicI32` (same size/alignment/offset as the
  authority's `int`; `:511`, `:535-541`), and `X509_STORE_new`/`_up_ref`/`_free`
  use the authority's relaxed increment and release decrement
  (`:1870`, `:1894-1900`, `:1958`). **Callback edge repaired in subphase 40:**
  the application `X509_LOOKUP_METHOD.free` hook (`:790-794`) and the store
  ex-data `free_func` (`:797-801`) run after the count reaches zero and can
  call `X509_STORE_free(xs)` again; the sentinel rejects the re-entry. Positive
  control: `x509::x509_lu::tests::store_free_reentrancy_is_defined_noop`.
  Retained: no independent §7 check.

### Subphase 41 — `Ssl`/`SslCtx` field-by-field ownership and alias fixes

The two rows were re-audited field by field against
`ssl/ssl_lib.c:1422-1547` (`SSL_free` + `ossl_ssl_connection_free`) and
`:4350-4468` (`SSL_CTX_free`). `ESTABLISHED` here retains the subphase-38
meaning: source-witnessed construction/partial states, one release per owned
member, and no release of the enclosing block or of a borrowed pointer. It is
not `SAFETY_DISCHARGED`.

**`Ssl` members.**

| member(s) | owner | rule / exact release |
|---|---|---|
| `references`, `lock` | object | sentinel gate; `CRYPTO_THREAD_lock_free` once |
| `ctx` | connection (strong) | one `SSL_CTX_up_ref` in `SSL_new` (authority `:705`); `SSL_CTX_free` once in the body (authority `:1438`) |
| `session_ctx` | connection (strong, distinct) | second `SSL_CTX_up_ref` in `SSL_new` (authority `:828`); `SSL_set_SSL_CTX` moves only `ctx`; `SSL_CTX_free` once (authority `:1485`) |
| `method`, `defltmeth` | borrowed static | never freed |
| `session` | connection (strong) | `SSL_set_session`/lookup up-ref; body calls `ssl_clear_bad_session` then `SSL_SESSION_free` once; `SSL_get_session` borrows, `SSL_get1_session` returns a new ref |
| `peer_cert` | connection | one `X509` ref; `X509_free` once |
| `peer_chain` | connection | stack of one ref per cert; `OSSL_STACK_OF_X509_free` once; `SSL_get_peer_cert_chain` borrows |
| `verified_chain` | connection | `X509_STORE_CTX_get1_chain` refs; `OSSL_STACK_OF_X509_free` once; `SSL_get0_verified_chain` borrows |
| `cert`, `param`, `dane` | connection | `cert_free`, `X509_VERIFY_PARAM_free`, `dane_final` once each |
| `cipher_list`, `cipher_list_by_id`, `tls13_ciphersuites`, `peer_ciphers` | connection | stacks of borrowed cipher pointers; `OPENSSL_sk_free` once |
| `srtp_profiles` | connection | stack of borrowed profiles; `OPENSSL_sk_free` once |
| `ca_names`, `client_ca_names`, `peer_ca_names` | connection | stacks of owned `X509_NAME` refs; `OPENSSL_sk_pop_free(X509_NAME_free)` once |
| `rbio`, `wbio` | connection | owned BIO chains (`BIO_set_bio`/`SSL_set0_*` transfer); `BIO_free_all` once each |
| `bbio` | connection | authority `ssl_free_wbio_buffer`; never allocated by this slice, so NULL |
| `ex_data` | connection | `CRYPTO_new_ex_data`; `CRYPTO_free_ex_data` once (after members, before `ctx`) |
| `ext_alpn`, `ext_npn`, `ext_hostname`, `s3_alpn_selected`, `s3_alpn_proposed`, `client_cert_type`, `server_cert_type`, `pha_context`, `supportedgroups` | connection | object-owned member buffers; cleared once through their slots/raw free |
| `session_ticket` | connection | one `TLS_SESSION_TICKET_EXT` block with inline data; `CRYPTO_free` once (`tls1_free`) |
| `hs_md_ctx`, `enc_ctx`, `dec_ctx`, `tls13_cipher`, `pkey`, `peer_tmp`, `pha_dgst` | connection | one `*_free` each; never aliased with each other |
| `srp_ctx`, `d1` | connection | `ssl_srp_ctx_free_intern`, `dtls1_free` once |
| `waitctx`, `job`, `scts`, `clienthello`, `shared_sigalgs`, `peer_sigalgs` | unset in this slice | no release path; `clienthello` is a transient stack pointer only during the callback and is cleared by the caller. Retained obligation if a future writer allocates them. |

**`SslCtx` members.**

| member(s) | owner | rule / exact release |
|---|---|---|
| `references`, `lock` | object | sentinel gate; lock freed once |
| `method`, `libctx` | borrowed | never freed (authority `:4344` reads them only) |
| `cert_store` | context (strong) | `X509_STORE_free` once; `set1` takes a ref, `set0` transfers |
| `param`, `cert`, `ctlog_store`, `dane` | context | one free each (`X509_VERIFY_PARAM_free`, `cert_free`, `CTLOG_STORE_free`, `dane_ctx_final`) |
| `srp_ctx` | context | `ssl_ctx_srp_ctx_free_intern` once |
| `client_cert_engine` | context (structural engine ref) | `ENGINE_init` in the setter; `ENGINE_finish` once in the body (authority `tls_engine_finish`, `:4409`) |
| `cipher_list`, `cipher_list_by_id`, `tls13_ciphersuites`, `srtp_profiles` | context | `OPENSSL_sk_free` once each |
| `ca_names`, `client_ca_names` | context | `OPENSSL_sk_pop_free(X509_NAME_free)` once |
| `sessions` | context cache | each entry owns one ref; `ssl_ctx_session_cache_free` clears the entry's `owner` back-pointer and releases the cache ref once |
| `propq`, `client_cert_type`, `server_cert_type`, `ext_alpn`, `supportedgroups` | context | object-owned member buffers; cleared once through their slots/raw free |
| `ex_data` | context | `CRYPTO_free_ex_data` once after the cache flush, before `cert_store`/`cert` (authority `:4388-4397`) |
| callbacks/args, `stats` | borrowed/plain | never freed |

**Defects found and fixed in subphase 41.**

1. **S1 — dangling `SslSession.owner` (use-after-free).** `owner` is a weak
   cache back-pointer, not a reference. `cache_delete_ptr`, the flush loop and
   `ssl_ctx_session_cache_free` removed a session from the cache without
   clearing it (the authority's `SSL_SESSION_list_remove` clears it,
   `ssl_sess.c:1349`). A session held by an application across
   `SSL_CTX_free` then retained a pointer into the freed context, and
   `SSL_SESSION_set_timeout` (`src/ssl/ssl_sess.rs`) dereferenced
   `owner->lock`. Fixed by clearing `owner` on removal, flush and cache
   teardown.
2. **S2 — leaked structural engine reference.** `SSL_CTX_set_client_cert_engine`
   calls `ENGINE_init` but `SslCtx::destroy_body` did not call `ENGINE_finish`.
   Added at the authority's position (`ssl_lib.c:4409`); NULL-safe.
3. **S3 — unreleased per-connection DANE state.** `Ssl::destroy_body` omitted
   `dane_final(&s->dane)` (authority `ssl_lib.c:1462`), leaking TLSA records,
   candidate certs and the matched certificate. Added before `cert_free`.
4. **S4 — missing authority session-cache teardown on `SSL_free`.** The body
   released `s->session` without the authority's preceding
   `ssl_clear_bad_session` (`ssl_lib.c:1473-1476`). Added, so a completed
   session is removed from `session_ctx`'s cache (and its `owner` cleared)
   before the connection's reference is dropped.

**Tests added (7, deterministic, not ignored, no allocator hook).**

| test | property |
|---|---|
| `ssl::ssl_lib::alias_ownership_tests::set_session_and_ssl_free_release_the_session_once` | `SSL_set_session` up-ref, caller ref release, `SSL_get1_session`, then `SSL_free` leave exactly one release per owner |
| `ssl::ssl_lib::alias_ownership_tests::ssl_free_releases_the_two_context_references_once` | `SSL_new` count `1 -> 3`; `SSL_free` count `3 -> 1` |
| `ssl::ssl_lib::alias_ownership_tests::ssl_set_ssl_ctx_keeps_the_two_context_references_distinct` | `ctx` moves, `session_ctx` does not; both freed once |
| `ssl::ssl_lib::alias_ownership_tests::peer_and_verified_chain_accessors_return_borrowed_owners` | accessors return the owned pointers, prefer `session->peer_chain`, never free them |
| `ssl::ssl_sess::alias_ownership_tests::removed_session_does_not_retain_a_context_back_pointer` | cache removal clears `owner` |
| `ssl::ssl_sess::alias_ownership_tests::flushed_session_does_not_retain_a_context_back_pointer` | flush clears `owner` |
| `ssl::ssl_sess::alias_ownership_tests::context_free_clears_the_back_pointer_of_a_surviving_session` | surviving session has `owner == NULL` and `SSL_SESSION_set_timeout` reads no freed context |

**Status.** `Ssl` and `SslCtx` promoted to `ESTABLISHED`: every column above is
source-witnessed and each release is traced once; the seven tests pass and the
adversarial court is unchanged at 18/18. Retained: the §7 independent-check
package is outstanding, and the unset-member writers (`waitctx`, `bbio`,
`scts`, `shared_sigalgs`, `peer_sigalgs`) are an explicit future obligation, not
a current release claim. Nothing is `SAFETY_DISCHARGED`.

### Subphase 42 — `X509Store` callback family and D1/D2 re-adjudication

**`X509Store` teardown order.** The body (`src/x509/x509_lu.rs:786-806`) matches
the authority's `X509_STORE_free` (`crypto/x509/x509_lu.c:226-254`): shut down and
free each lookup (`X509_LOOKUP_shutdown`/`X509_LOOKUP_free`, running the method's
`free` hook, authority `:241-245`); free the lookup stack (`:246`); pop-free the
object cache (`:247`); `CRYPTO_free_ex_data` (`:249`); free the verify param and
lock (`:250-251`); then the outer `OwnedCtx` releases the block at the authority's
`:253`. The atomic count is claimed as `REF_DESTROYING` before this body runs, so
both callback families that can re-enter `X509_STORE_free` are defined no-ops.

**Witness — lookup `free` hook.** New deterministic test
`x509::x509_lu::tests::store_free_from_lookup_free_hook_is_defined_noop` builds a
minimal `X509_LOOKUP_METHOD` with only `free` installed, adds it through
`X509_STORE_add_lookup`, and frees the store once. The hook observes
`references == REF_DESTROYING`, `X509_STORE_up_ref` answers `0` without changing
the count, the re-entrant `X509_STORE_free` leaves the sentinel in place, and the
hook ran exactly once. The block release remains the single
`OwnedCtx::<X509Store>` `Drop`: `from_raw` is constructed only on `DownRef::Last`,
so the re-entrant call cannot reach a second teardown.

**Retained partial-release path (authority parity).** The lookup `free` hook runs
before any store member is released and therefore observes a live store. The
ex-data `free_func` runs at the authority's `:249` position, **after**
`get_cert_methods` and `objs` have been freed; their struct fields remain stale
non-NULL. A callback that re-enters `X509_STORE_free`/`X509_STORE_up_ref` is
defined (sentinel/refusal), but one that calls a store mutator reading those
fields (`X509_STORE_add_lookup`, `X509_STORE_add_cert`, `X509_STORE_add_crl`)
would dereference the freed stack. This is the authority's own order and is
recorded as a retained callback-contract obligation, not a conversion regression.

**Retained callback-mutation divergence.** The body caches `OPENSSL_sk_num(sk)`
before the lookup loop; the authority re-evaluates it each iteration (`:241`). A
lookup `free` hook that pushes another lookup onto the same store is therefore
torn down by the authority but left on the freed stack by this transcription
(a leak of callback-created state only; no use-after-free).

**D1/D2 promoted to `ESTABLISHED`.** Both implementer obligations are now
witnessed: (a) the destructor body is the authority's `*_freectx` minus the
block — D1 `hw->cleanup` (`cipher_aes_siv.c:54`), D2 `CRYPTO_clear_free(aad,
aad_len)` then `hw->clean_ctx` (`cipher_aes_gcm_siv.c:51-52`); neither body frees
the enclosing block, and `OwnedCtx::drop` releases it once with
`CRYPTO_clear_free`; (b) all-zero validity is guarded by the NULL `hw` test and
exercised by `a_zeroed_siv_context_drops_without_a_hardware_table`. Both hardware
lookups always return a static table
(`src/provider/cipher.rs:10406-10408,13720-13722`; authority
`cipher_aes_siv_hw.c:136-139`, `cipher_aes_gcm_siv_hw.c:339-342`), so the guard
changes only the unconstructed/failure state. Retained: the guards are a §17
safety improvement over the authority's unconditional dereference; no sanitizer
or model-checker run backs the zero-state control. Neither row is
`SAFETY_DISCHARGED`.

### STOP defects

**Subphase 38: none found in the 19 rows.** Every body was checked for an
uninitialised field read, a double release of a member, and a release of the
enclosing block; no such path was found in that scope.

**Subphase 41: S1–S4 were found in the `Ssl`/`SslCtx` rows and fixed** (see the
table above). S1 was a dangling weak back-pointer that allowed a use-after-free;
S2 and S3 were owned references the body never released; S4 was a missing
authority teardown step in `SSL_free`. The seven deterministic controls and the
full library suite pass after the fixes.

**Subphase 42: none found.** The new lookup-`free` control passes, the teardown
order is the authority's, and the only partial-release exposure is the ex-data
callback path recorded above, which the authority also has. D1/D2 were already
fixed in sweep-37; this pass only re-adjudicated their status.

### Residual / unknown obligations

- The 16 subphase-38 promotions retain the external ABI obligation that a stored method or
  provider callback is a valid function and frees only its own data; callback
  re-entrancy was not tested.
- `SslCtx`/`Ssl` were promoted in subphase 41 after the field-by-field audit
  and S1–S4 fixes. Their retained obligation is independent §7 verification and
  the future writers for currently-unset members; it is no longer a known
  alias/double-release gap. `X509Store` was promoted in subphase 42 after the
  lookup-`free` control; it retains the §7 independent-check obligation and the
  authority-parity partial-release path recorded under “Subphase 42”.
- The 16 subphase-38 promotions retain the external ABI obligation that a stored
  method or provider callback is a valid function and frees only its own data;
  the `X509Store` lookup/ex-data families are now driven, but `BIO_free_all` and
  the CT-log callback were not driven independently.
- `EcGroup`/`EcPoint` zero-state evidence is the deterministic negative control,
  not a model-checker or sanitizer result.
- Nothing is promoted to `DISCHARGED`; §7's full dependency-closure and
  independent-check package was not attempted.

## 7. Status counts and residuals

| status | count |
|---|---:|
| implementations audited | 199 |
| `CONTRACTED` | 0 |
| `ESTABLISHED` | 199 |
| `DISCHARGED` | 0 |
| defect sites (STOP) | 8, all fixed at source (4 sweep-37, 4 subphase 41); none added in subphase 38–42 |

**Retained obligations (global):**

- Every owner retains "the block is live and exclusively owned; `Drop` runs
  once". The owner types establish this; it is not independently checked here.
- Callback-dispatching destructors retain the authority/provider callback
  contract. D1/D2 are no longer in this class: they were missing null tests and
  are fixed and re-adjudicated in subphase 42. `X509Store` retains the
  authority-parity ex-data partial-release path recorded under “Subphase 42".
- Reference-counted destructors: `SslCtx`, `Ssl`, `SslSession` and
  `X509Store` use the shared destroying-sentinel gate (`runtime/refcount.rs`).
  Its retained obligation is independent verification, not the callback edge:
  a re-entrant `*_free` is a defined no-op and `*_up_ref` refuses to resurrect
  a dying object; each type has a deterministic positive control
  (`RUNTIME-ALIAS-EVIDENCE.md` §§1–3). `EvpPkey`'s last-reference gate was
  source-witnessed in subphase 38 (`evp/pkey.rs:758-772`).
- `EcGroup`/`EcPoint` retain the clear/plain selection obligation. The D3/D4
  latent null dereference is fixed by the sweep-37 guard; the zero-state claim
  now holds, but the boundaries remain `ESTABLISHED` (no independent check).
- `CipherDestroy::OwnedCtx::new` retains the zero-validity obligation for all
  27 implementers; D1/D2 showed it was not uniformly met, and the two failing
  bodies now guard their hardware teardown. All zero-state tests are
  deterministic source/negative controls; the other 25 retain the source-witness
  status only.
- No Miri, sanitizer, negative-control, or differential run was performed for
  this audit. `ESTABLISHED` is a source-witness status, not an independently
  checked one, and nothing here is `SAFETY_DISCHARGED`.
