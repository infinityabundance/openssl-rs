import hashlib, json, re
from pathlib import Path

ROOT = Path(".")

SPAN_NORM = "split on universal newlines (Python str.splitlines), rstrip() every line, join with '\\n', sha256 over UTF-8 bytes (no trailing newline)"
SPAN_SCOPE = ("The span hash covers only the operation's own text and its attributes: from the first non-documentation attribute/qualifier line through the brace-matched closing brace. Documentation comments (///, //!, /** */) above the attributes are excluded. The hash does NOT cover dispatchers, shared guards, macro headers/invocations, caller closures, or any other code outside that span; those remain governed by the existing freeze and mechanism-scope rules. This is a narrowing claim, not a strengthening one.")

def span(path, name):
    L = (ROOT / path).read_text(encoding="utf-8").splitlines()
    pat = re.compile(r"^\s*unsafe extern \"C\" fn " + re.escape(name) + r"\b")
    start = next(i for i, l in enumerate(L) if pat.search(l))
    d = 0
    opened = False
    end = None
    for j in range(start, len(L)):
        for ch in L[j]:
            if ch == "{":
                d += 1
                opened = True
            elif ch == "}":
                d -= 1
        if opened and d == 0:
            end = j
            break
    seg = [x.rstrip() for x in L[start:end + 1]]
    return start + 1, end + 1, hashlib.sha256("\n".join(seg).encode()).hexdigest(), "\n".join(seg)

S = {
    "span_source_commit": "b8bba955503014c8fd86303314c6deebaea093b0",
    "span_schema": "safe-c33/operation-span-sha256/v1",
    "span_normalisation": SPAN_NORM,
    "span_claim_scope": SPAN_SCOPE,
}

def aux_reg(file, aux_line, item_line, item_name, itype, sym, addr):
    return {
        "file": file,
        "line": aux_line,
        "function": "static initializer " + item_name + "_aux",
        "guard": "static `Asn1Aux.asn1_cb` slot, read only by the item machinery",
        "obligation": (
            "the sole writer of the callback slot; `funcs` of `" + item_name + "_it` at :" + str(item_line)
            + " points at this aux (itype " + itype + "). The callback symbol `" + sym + "` is local `t` at "
            + addr + "; no direct caller, no `#[no_mangle]`, no address-of elsewhere."
        ),
    }

sites = []

def add(bid, file, op, aux_line, item_line, item_name, itype, sym, addr,
        contract, disposition, established, preconds, tests):
    a, b, h, body = span(file, op)
    rec = {
        "id": bid,
        "file": file,
        "kind": "UNSAFE_FN_DEF",
        "operation": op,
        "line": a,
        "line_current": a,
        "inventory_line": a,
        "span_start_line": a,
        "span_end_line": b,
        "span_sha256": h,
        "mechanism": "RAND_CMS_STORE_KEYFMT",
        "signature": (
            "unsafe extern \"C\" fn " + op + "(operation: c_int, pval: *mut *mut c_void, "
            "_it: *const Asn1Item, _exarg: *mut c_void) -> c_int"
            if op != "cms_cb"
            else "unsafe extern \"C\" fn cms_cb(operation: c_int, pval: *mut *mut c_void, _it: *const Asn1Item, exarg: *mut c_void) -> c_int"
        ),
        "body": body,
        "precondition_set": list(preconds),
        "disposition": "SAFETY_DISCHARGED: " + file + ":" + str(a) + " \u2014 " + disposition,
        "contract": contract,
        "established": list(established),
        "unsafe_operations": [],
        "caller_closure_ref": "shared caller_closure",
        "tests": list(tests),
    }
    rec.update(S)
    sites.append(rec)

add(
    "CMS-CB-001", "src/cms/cms_asn1.rs", "cms_ec_cb", 1288, 1322, "CMS_EncryptedContentInfo",
    "NDEF_SEQUENCE", "cms_ec_cb", "0x1961c0",
    "C ABI `int (int, ASN1_VALUE **, const ASN1_ITEM *, void *)`. The callback acts only on ASN1_OP_FREE_POST, where `*pval` is a live `CMS_EncryptedContentInfo`. `key` is NULL or the object's own single CRYPTO_* allocation of `keylen` bytes, and is released exactly once with `OPENSSL_clear_free(key, keylen)`. No other operation has a precondition: every other operation returns 1 without reading `*pval`.",
    "cms_ec_cb dereferences `*pval` only inside the `ASN1_OP_FREE_POST` arm. The item free walk returns before invoking any callback when a non-primitive item's stored value is NULL, and the item is an NDEF_SEQUENCE, so FREE_POST always receives a live object. The template walk has already released the ASN.1 fields (`content_type`, `content_encryption_algorithm`, `encrypted_content`); `key`/`keylen` are runtime members it does not touch, so the callback is their single release.",
    [
        "`item_embed_free` evaluates `let value = *pval; if item.itype != ASN1_ITYPE_PRIMITIVE && value.is_null() { return; }` before the SEQUENCE/CHOICE arms (src/asn1/fre.rs:217-221), so a NULL slot never reaches FREE_PRE/FREE_POST for a non-primitive item.",
        "`ASN1_item_free`/`ASN1_item_ex_free` are the only free entries (src/asn1/fre.rs:430-448); both pass a live slot to `item_embed_free`.",
        "The item is `ASN1_ITYPE_NDEF_SEQUENCE` (src/cms/cms_asn1.rs:1322-1330), so the guard applies and the FREE_POST call at src/asn1/fre.rs:345-348 has a non-NULL `*pval`.",
        "`CmsEncryptedContentInfo.key`/`keylen` are not template fields (the three templates are content_type, content_encryption_algorithm, encrypted_content); the generic walk cannot release them, so the callback owns their single release.",
        "Every other operation returns 1 without forming a reference: the arm test is `operation == ASN1_OP_FREE_POST`, so NEW_PRE (where `*pval` may be NULL) and all D2I/I2D/PRINT/DUP operations are inert.",
    ],
    ["At ASN1_OP_FREE_POST, `*pval` is a live `CmsEncryptedContentInfo` owned by the free walk; `key` is NULL or this object's own CRYPTO_* block of `keylen` bytes, released exactly once."],
    ["courts/phase25/rt_cms_asn1_callbacks.c: a CMS_encrypt RSA and EC EnvelopedData install a live session key in `ec.key`; d2i/i2d round trips, malformed/truncated decodes and CMS_ContentInfo_free exercise FREE_POST. Plain run PASS; LeakSanitizer run PASS under the recorded baseline suppression (a missing release would surface as an unsuppressed CRYPTO_* leak)."],
)

add(
    "CMS-CB-002", "src/cms/cms_asn1.rs", "cms_rek_cb", 1485, 1512, "CMS_RecipientEncryptedKey",
    "SEQUENCE", "cms_rek_cb", "0x195b80",
    "C ABI `int (int, ASN1_VALUE **, const ASN1_ITEM *, void *)`. On ASN1_OP_FREE_POST `*pval` is a live `CMS_RecipientEncryptedKey`; `pkey` is NULL or an `EVP_PKEY` reference owned by it and is released exactly once with `EVP_PKEY_free`. Every other operation returns 1 without reading `*pval`.",
    "cms_rek_cb dereferences `*pval` only inside the `ASN1_OP_FREE_POST` arm. The item is a SEQUENCE, and `item_embed_free` returns before the callback when its stored value is NULL, so FREE_POST receives a live object. `pkey` is a runtime member, not a template field, so the callback is its single release.",
    [
        "`item_embed_free` returns for a NULL non-primitive value before the SEQUENCE arm (src/asn1/fre.rs:217-221); the item is `ASN1_ITYPE_SEQUENCE` (src/cms/cms_asn1.rs:1512-1520).",
        "The FREE_POST invocation at src/asn1/fre.rs:345-348 is therefore always on a live slot.",
        "The two template fields are `rid` and `encryptedKey`; `pkey` is runtime state the generic walk does not release.",
        "The arm test is `operation == ASN1_OP_FREE_POST`, so NEW_PRE's possible NULL slot is never dereferenced.",
    ],
    ["At ASN1_OP_FREE_POST, `*pval` is a live `CMS_RecipientEncryptedKey` owned by the free walk; `pkey` is NULL or an `EVP_PKEY` reference owned by it, released exactly once."],
    ["courts/phase25/rt_cms_asn1_callbacks.c: the EC (KARI) EnvelopedData round trip carries a RecipientEncryptedKey, and CMS_ContentInfo_free drives its FREE_POST. Plain PASS; LeakSanitizer PASS under the recorded baseline suppression."],
)

add(
    "CMS-CB-003", "src/cms/cms_asn1.rs", "cms_kari_cb", 1595, 1643, "CMS_KeyAgreeRecipientInfo",
    "SEQUENCE", "cms_kari_cb", "0x195c40",
    "C ABI `int (int, ASN1_VALUE **, const ASN1_ITEM *, void *)`. At ASN1_OP_NEW_POST `*pval` is the freshly allocated and zero-initialised `CMS_KeyAgreeRecipientInfo`, so its `ctx`/`pctx` slots are writable; the callback installs a new cipher context or fails. At ASN1_OP_FREE_POST `*pval` is the live object and `ctx`/`pctx` are NULL or contexts it owns, released exactly once. All other operations return 1 after at most casting the slot contents (never dereferencing a NULL value).",
    "The body reads `*pval` unconditionally but only dereferences the resulting pointer in the NEW_POST and FREE_POST arms. NEW_POST follows the allocation in `item_embed_new` (or follows the caller-provided embedded storage), so the slot is non-NULL and the block is zeroed before the callback; FREE_POST is guarded by `item_embed_free`'s non-primitive NULL check. The callback therefore never dereferences a NULL `*pval`.",
    [
        "`item_embed_new` calls ASN1_OP_NEW_PRE before allocating (slot may be NULL) and ASN1_OP_NEW_POST after the block is allocated/zeroed (src/asn1/new.rs:264-352); the callback only acts on NEW_POST.",
        "`item_embed_free` returns for a NULL non-primitive value before the callback (src/asn1/fre.rs:217-221); the item is `ASN1_ITYPE_SEQUENCE` (src/cms/cms_asn1.rs:1643-1651).",
        "A zeroed `CmsKeyAgreeRecipientInfo` is a valid value for this callback: every field is a raw pointer, integer or pointer to `CmsCtx`; the callback writes only `ctx` and `pctx`.",
        "`EVP_CIPHER_CTX_new` failure returns 0, and the item machinery then frees the partially initialised value through `item_embed_free`; FREE_POST sees `ctx == NULL`/`pctx == NULL`, and both `EVP_CIPHER_CTX_free`/`EVP_PKEY_CTX_free` accept NULL.",
        "D2I_PRE for a SEQUENCE is invoked after allocation (src/asn1/d2i.rs:1922-1939) and D2I_POST after a successful decode (src/asn1/d2i.rs:2088-2095); both are inert arms here.",
    ],
    ["At ASN1_OP_NEW_POST `*pval` is the fresh zeroed object; at ASN1_OP_FREE_POST it is the live object. `ctx`/`pctx` are NULL or owned contexts."],
    ["courts/phase25/rt_cms_asn1_callbacks.c: an EC (P-256) certificate makes CMS_encrypt build a KARI recipient; after d2i, `CMS_RecipientInfo_kari_get0_ctx` is non-NULL, which proves NEW_POST ran; CMS_ContentInfo_free then drives FREE_POST. Plain PASS; LeakSanitizer PASS."],
)

add(
    "CMS-CB-004", "src/cms/cms_asn1.rs", "cms_kemri_cb", 1785, 1861, "CMS_KEMRecipientInfo",
    "SEQUENCE", "cms_kemri_cb", "0x195d30",
    "C ABI `int (int, ASN1_VALUE **, const ASN1_ITEM *, void *)`. At ASN1_OP_NEW_POST `*pval` is the fresh zeroed `CMS_KEMRecipientInfo`; at ASN1_OP_FREE_POST it is live. `pctx`/`ctx` are NULL or owned contexts; `ukm` is NULL or the OCTET STRING the template walk has already released and cleared. All other operations return 1 after at most casting the slot contents.",
    "The body dereferences the value only in the NEW_POST and FREE_POST arms. NEW_POST runs after `item_embed_new` allocated and zeroed the object; FREE_POST is guarded by the free walk's non-primitive NULL check. The FREE_POST `ASN1_STRING_free((*kemri).ukm)` is safe even though the template walk already released that field: it is a non-embedded pointer field, so `template_free` nulls it, and `ASN1_STRING_free(NULL)` is a no-op.",
    [
        "`item_embed_new` NEW_POST runs after allocation/zeroing (src/asn1/new.rs:264-352); NEW_PRE, where `*pval` may be NULL, is inert here.",
        "`item_embed_free` returns for a NULL non-primitive value before the callback (src/asn1/fre.rs:217-221); the item is `ASN1_ITYPE_SEQUENCE` (src/cms/cms_asn1.rs:1861-1869).",
        "`ukm` is template field 6 at offset 48, `ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL`, not EMBED (src/cms/cms_asn1.rs:1838-1844). The reverse template walk frees and nulls non-embedded pointer fields before FREE_POST, so the callback's second release is a NULL no-op.",
        "`pctx`/`ctx` are runtime members outside the template; the callback is their single release, and both frees accept NULL.",
        "The 9 template fields decode before NEW_POST/D2I_POST as applicable; the callback reads only the three runtime slots.",
    ],
    ["At ASN1_OP_NEW_POST `*pval` is the fresh zeroed object; at FREE_POST it is live. `pctx`/`ctx` are NULL or owned; `ukm` is NULL or already released and cleared by the template walk."],
    ["courts/phase25/rt_cms_asn1_callbacks.c: an ML-KEM-768 certificate (signed by an RSA key) makes CMS_encrypt build a KEM ORI recipient. After d2i, `CMS_RecipientInfo_type` is CMS_RECIPINFO_KEM (5) and `CMS_RecipientInfo_kemri_get0_ctx` is non-NULL, which prove the cms_ri_cb D2I_POST mapping and the cms_kemri_cb NEW_POST ran; free drives FREE_POST. Plain PASS; LeakSanitizer PASS."],
)

add(
    "CMS-CB-005", "src/cms/cms_asn1.rs", "cms_ri_cb", 1943, 1991, "CMS_RecipientInfo",
    "CHOICE", "cms_ri_cb", "0x196280",
    "C ABI `int (int, ASN1_VALUE **, const ASN1_ITEM *, void *)`. The value slot is live whenever the callback runs: CHOICE FREE_PRE/FREE_POST are guarded by `item_embed_free`; CHOICE D2I_POST runs only after an alternative matched and the selector was stored; CHOICE NEW_POST runs after the fresh block was allocated and the selector set to -1. When `type_` names an arm (TRANS/KEK/PASS), `d` points at that arm's live object. `encoded_type` is the CHOICE selector at offset 0.",
    "Every dereference (FREE_PRE, D2I_POST, NEW_POST) is on a non-NULL value: the free guard excludes NULL for a CHOICE, and both decode/create paths allocate before the POST callback. The FREE_PRE switch reads `type_`; the invariant 'type_ is an arm index implies d is live' is established by the constructors (which store `d` before setting `type_`) and by D2I_POST (`type_ = encoded_type`, the selector of the alternative just decoded). NEW_POST stores the selector value -1, so a fresh value takes the `_ => {}` arm rather than an arm dereference.",
    [
        "`item_embed_free` returns for a NULL non-primitive value before the CHOICE arm (src/asn1/fre.rs:217-221); the item is `ASN1_ITYPE_CHOICE` with `utype: 0` (selector at offset 0) (src/cms/cms_asn1.rs:1991-1999).",
        "`item_embed_new` allocates or zeroes the CHOICE block, calls `set_choice_selector(pval, -1)`, then NEW_POST (src/asn1/new.rs:214-261). NEW_POST therefore stores `type_ = -1` (`CMS_RECIPINFO_NONE`), not an arm index (src/cms/cms_asn1.rs:658-661; constants at :74-80).",
        "`embed_d2i` CHOICE calls D2I_POST only after `template_ex_d2i` matched an alternative and `set_choice_selector` stored its index (src/asn1/d2i.rs:1822-1854); the arm pointer `d` was installed by that decode.",
        "Every in-crate constructor stores `d` before setting `type_`: `cms_RecipientInfo_ktri_init` (:775 then :781-782), `ossl_cms_RecipientInfo_kari_init` (:832 then :838-839), `CMS_add0_recipient_key` (cms_env.rs:1917-1920), `CMS_add0_recipient_password` (cms_pwri.rs:397 then :411-412), `ossl_cms_RecipientInfo_kemri_init` (cms_kemri.rs:191-194 with the ORI installed first).",
        "`CMS_RecipientInfo` is a private item (`cms_recipientinfo_it` is pub(crate) and not exported); the only re-decode path into an existing CHOICE element is the generic `embed_d2i` existing-value branch, which `SEQUENCE OF`/`SET OF` element decoding never reaches because each element is decoded into a fresh local slot (src/asn1/d2i.rs:2448-2463). No safe CMS API re-decodes into an existing `CMS_RecipientInfo`.",
        "D2I_POST reads `(*ori).ori_type` only when `type_ == CMS_RECIPINFO_OTHER`; that alternative was just decoded, so `d` is the live ORI (src/cms/cms_asn1.rs:646-657).",
    ],
    ["`*pval` is a live `CMS_RecipientInfo` whenever the callback runs; when `type_` is TRANS/KEK/PASS, `d` points at the corresponding live arm."],
    ["courts/phase25/rt_cms_asn1_callbacks.c: d2i of a KARI recipient yields `CMS_RecipientInfo_type == CMS_RECIPINFO_AGREE (1)`, and d2i of a KEM ORI yields `CMS_RECIPINFO_KEM (5)`; a zeroed block would read 0, so the D2I_POST arm provably ran. Freeing TRANS, AGREE and KEM recipients drives FREE_PRE for the three arms plus the `_` arm. Plain PASS; LeakSanitizer PASS."],
)

add(
    "CMS-CB-006", "src/cms/cms_asn1.rs", "cms_cb", 2453, 2480, "CMS_ContentInfo",
    "NDEF_SEQUENCE", "cms_cb", "0x1960e0",
    "C ABI `int (int, ASN1_VALUE **, const ASN1_ITEM *, void *)`. On ASN1_OP_FREE_POST `*pval` is a live `CMS_ContentInfo`. On STREAM_PRE/STREAM_POST/DETACHED_PRE/DETACHED_POST the item machinery is entered from `BIO_new_NDEF`/`asn1_output_data`, whose contract requires the value slot to hold a live `CMS_ContentInfo` and `exarg` to be the live `ASN1_STREAM_ARG`; the body dereferences both. All other operations return 1 without dereferencing `*pval`.",
    "The FREE_POST dereference is guarded by the free walk's non-primitive NULL check (the item is an NDEF_SEQUENCE). The streaming arms are not reached from the generic free path: they are invoked by the stream/detach machinery with a caller-supplied live value and a live argument block. The body's own `pval.is_null()` test guards the slot address, which the machinery always provides; the value itself is non-NULL by the caller contract.",
    [
        "`item_embed_free` returns for a NULL non-primitive value before the callback (src/asn1/fre.rs:217-221); the item is `ASN1_ITYPE_NDEF_SEQUENCE` (src/cms/cms_asn1.rs:2480-2488).",
        "STREAM_PRE/POST are invoked by `BIO_new_NDEF` with `val` from its caller and a local `sarg` (src/asn1/bio_asn1.rs:903-911); STREAM_POST reuses the stored value in the support block (src/asn1/bio_asn1.rs:1114-1127).",
        "DETACHED_PRE/POST are invoked by `asn1_output_data` with its `val` parameter and a local `sarg` (src/asn1/asn_mime.rs:992-1028).",
        "`BIO_new_NDEF` documents `val` as 'a live value of it's type' (src/asn1/bio_asn1.rs:802-805); `asn1_output_data` documents 'val and it as the encoder requires' (src/asn1/asn_mime.rs:961-963). A NULL value is C-invalid for both, exactly as in the authority.",
        "The I2D_PRE/I2D_POST callbacks, which the encoder also issues, return 1 here without touching `*pval`/`exarg`; `item_ex_i2d` additionally returns before them when a non-primitive value is NULL (src/asn1/i2d.rs:228-237).",
        "FREE_POST releases only `ctx.propq`, a member buffer owned by the object; the template walk does not release it.",
    ],
    ["At FREE_POST `*pval` is live. For STREAM/DETACHED, the caller of `BIO_new_NDEF`/`asn1_output_data` passes a live `CMS_ContentInfo` and a live `ASN1_STREAM_ARG`; a NULL value is outside the C ABI contract."],
    ["courts/phase25/rt_cms_asn1_callbacks.c: `i2d_CMS_bio_stream(..., SMIME_STREAM)` on a CMS built with CMS_STREAM drives STREAM_PRE and STREAM_POST to a successful return; the same CMS and a decoded CMS are freed (FREE_POST). The DETACHED arms are NOT_RUN (see not_run). Plain PASS; LeakSanitizer PASS for the non-streaming paths."],
)

add(
    "PK7-CB-001", "src/pkcs7/pk7_asn1.rs", "ri_cb", 646, 898, "PKCS7_RECIP_INFO",
    "SEQUENCE", "ri_cb", "0x1a2480",
    "C ABI `int (int, ASN1_VALUE **, const ASN1_ITEM *, void *)`. On ASN1_OP_FREE_POST `*pval` is a live `PKCS7_RECIP_INFO`; `cert` is NULL or an `X509` reference owned by it and is released exactly once with `X509_free`. Every other operation returns 1 without reading `*pval`.",
    "ri_cb dereferences `*pval` only inside the FREE_POST arm. The item is a SEQUENCE, so `item_embed_free` returns before the callback when the stored value is NULL; FREE_POST therefore receives a live object. `cert` is a runtime member, not a template field, so the callback is its single release.",
    [
        "`item_embed_free` returns for a NULL non-primitive value before the SEQUENCE arm (src/asn1/fre.rs:217-221); the item is `ASN1_ITYPE_SEQUENCE` (src/pkcs7/pk7_asn1.rs:898-906).",
        "The FREE_POST invocation at src/asn1/fre.rs:345-348 is therefore always on a live slot.",
        "The four template fields are version, issuer_and_serial, key_encryption_algorithm and encrypted_key; `cert` is runtime state the generic walk does not release.",
        "The arm test is `operation == ASN1_OP_FREE_POST`, so NEW_PRE's possible NULL slot is never dereferenced.",
    ],
    ["At ASN1_OP_FREE_POST, `*pval` is a live `PKCS7_RECIP_INFO`; `cert` is NULL or an `X509` reference owned by it, released exactly once."],
    ["courts/phase25/rt_cms_asn1_callbacks.c: PKCS7_encrypt(i2d -> d2i) round trip; a live certificate is attached to a decoded recipient with PKCS7_add_recipient, and PKCS7_free drives the FREE_POST release. LeakSanitizer observes the release (an omitted X509_free would be an unsuppressed leak). Plain PASS; LeakSanitizer PASS."],
)

receipt = {
    "receipt": "boundary-sweep-B71",
    "kind": "site-enumerating-boundary-receipt",
    "date": "2026-11-10",
    "campaign": "safe-c33",
    "subphase": "B71",
    "candidate": {
        "source_head": "525408edf2e679ac2cf6042893d862d5f19583ee",
        "branch": "detached HEAD (evidence commit)",
        "tool": "forensics/tools/consumer_closure.py",
        "tool_sha256": "b13ebd6e5fa4afc1acdc4a477b2b9a556e7182d6e34bb744f655809159b04039",
        "source_state": (
            "src/ is not edited by this receipt. src/cms/cms_asn1.rs is sha256 f6d459a64b9f0e3ee81d296a107add8f97addf10aa93eeca058f84c856b627d1 and "
            "src/pkcs7/pk7_asn1.rs is sha256 3e3ad7863d0cbd5773bb5ac075ffbfa4a5eeedaefe73135e27bfa5c8039e54de at HEAD 525408edf; git diff against the inventory/span source "
            "b8bba955503014c8fd86303314c6deebaea093b0 is empty for both. The repository files this subphase adds are the receipt, the CAMPAIGN-STATUS scoped row, "
            "the external C probe courts/phase25/rt_cms_asn1_callbacks.c and the closure evidence evidence/closure-ssh-b71-cmscb.json; no src/ file changes."
        ),
        "files": ["src/cms/cms_asn1.rs", "src/pkcs7/pk7_asn1.rs", "courts/phase25/rt_cms_asn1_callbacks.c"],
        "files_sha256": {
            "src/cms/cms_asn1.rs": "f6d459a64b9f0e3ee81d296a107add8f97addf10aa93eeca058f84c856b627d1",
            "src/pkcs7/pk7_asn1.rs": "3e3ad7863d0cbd5773bb5ac075ffbfa4a5eeedaefe73135e27bfa5c8039e54de",
            "courts/phase25/rt_cms_asn1_callbacks.c": "d58af5cd537338488b696a76778e2eb7b5745ed39e336339df2ef5694623c5a1",
        },
        "admitted_install": {
            "prefix": "artifacts/phase2/install",
            "libcrypto_so_3_sha256": "1c03ec0a8925f43dc891aa8e4121c57420dc4d4c4c65ce399d9a9cece0766ed3",
        },
    },
    "authority": {
        "id": "openssl-3.6.4",
        "source": "forensics/authorities/src/openssl-3.6.4/crypto/cms/cms_asn1.c, crypto/pkcs7/pk7_asn1.c",
        "item_callback_abi": (
            "ASN1_AUX.asn1_cb is an informational callback called by the ASN.1 item machinery around each operation. On NEW_POST/D2I_POST/FREE_PRE/FREE_POST `*pval` is the live value slot for the declared item type; "
            "NEW_PRE and CHOICE D2I_PRE may be called before allocation, so `*pval` may be NULL there. For a non-primitive item the free walk returns before any callback when the stored value is NULL "
            "(tasn_fre.c's item-embed-free guard), so FREE_PRE/FREE_POST only see NULL for primitive items whose value lives in the slot. The streaming operations receive the caller-supplied value and the ASN1_STREAM_ARG."
        ),
        "registrations": (
            "cms_ec_cb : ASN1_SEQUENCE_cb(CMS_EncryptedContentInfo, cms_ec_cb); cms_rek_cb : ASN1_SEQUENCE_cb(CMS_RecipientEncryptedKey, cms_rek_cb); "
            "cms_kari_cb : ASN1_SEQUENCE_cb(CMS_KeyAgreeRecipientInfo, cms_kari_cb); cms_kemri_cb : ASN1_SEQUENCE_cb(CMS_KEMRecipientInfo, cms_kemri_cb); "
            "cms_ri_cb : ASN1_CHOICE_cb(CMS_RecipientInfo, cms_ri_cb); cms_cb : ASN1_SEQUENCE_cb(CMS_ContentInfo, cms_cb); ri_cb : ASN1_SEQUENCE_cb(PKCS7_RECIP_INFO, ri_cb)."
        ),
    },
    "mechanism": {
        "id": "RAND_CMS_STORE_KEYFMT",
        "state_before": "OWNERSHIP_RECONSTRUCTED",
        "state_after": "OWNERSHIP_RECONSTRUCTED",
        "state_source": "state.json#/mechanisms[id=RAND_CMS_STORE_KEYFMT]",
        "discharge": "none mechanism-wide; this receipt discharges only the seven named item-callback boundaries (site-scoped)",
    },
    "obligations": [],
    "boundaries": sites,
    "caller_closure": {
        "callers": [
            aux_reg("src/cms/cms_asn1.rs", 1288, 1322, "CMS_EncryptedContentInfo", "ASN1_ITYPE_NDEF_SEQUENCE", "cms_ec_cb", "0x1961c0"),
            aux_reg("src/cms/cms_asn1.rs", 1485, 1512, "CMS_RecipientEncryptedKey", "ASN1_ITYPE_SEQUENCE", "cms_rek_cb", "0x195b80"),
            aux_reg("src/cms/cms_asn1.rs", 1595, 1643, "CMS_KeyAgreeRecipientInfo", "ASN1_ITYPE_SEQUENCE", "cms_kari_cb", "0x195c40"),
            aux_reg("src/cms/cms_asn1.rs", 1785, 1861, "CMS_KEMRecipientInfo", "ASN1_ITYPE_SEQUENCE", "cms_kemri_cb", "0x195d30"),
            aux_reg("src/cms/cms_asn1.rs", 1943, 1991, "CMS_RecipientInfo", "ASN1_ITYPE_CHOICE", "cms_ri_cb", "0x196280"),
            aux_reg("src/cms/cms_asn1.rs", 2453, 2480, "CMS_ContentInfo", "ASN1_ITYPE_NDEF_SEQUENCE", "cms_cb", "0x1960e0"),
            aux_reg("src/pkcs7/pk7_asn1.rs", 646, 898, "PKCS7_RECIP_INFO", "ASN1_ITYPE_SEQUENCE", "ri_cb", "0x1a2480"),
        ],
        "other_references": (
            "A grep over src/ finds each callback name only at its definition, at the single `asn1_cb: Some(...)` field of its static `Asn1Aux`, and in doc comments "
            "(cms_env.rs refers to cms_ri_cb in prose). There is no direct call, no `#[no_mangle]`, no `#[export_name]`, and no address-of outside the aux initializer. "
            "The aux statics are referenced only through the corresponding `Asn1Item.funcs`."
        ),
        "export_status": "Not exported. `nm` on the admitted libcrypto.so.3 lists all seven as local (`t`) symbols: cms_rek_cb 0x195b80, cms_kari_cb 0x195c40, cms_kemri_cb 0x195d30, cms_cb 0x1960e0, cms_ec_cb 0x1961c0, cms_ri_cb 0x196280, pk7 ri_cb 0x1a2480.",
        "slot_writers": "One writer per slot: the static `Asn1Aux.asn1_cb` initializer. No runtime store, table copy or re-registration exists.",
        "reachability": (
            "Reached only through the ASN.1 item machinery: exported d2i/i2d/CMS_* and PKCS7_* entry points allocate/decode/encode/free values of these item types, and the machinery invokes the registered callbacks. "
            "The callbacks are private and cannot be called directly by a consumer."
        ),
    },
    "negative_control": {
        "id": "B71-C1",
        "name": "CMS/PKCS7 item callbacks tolerate the NULL-slot arm and release their live members",
        "kind": "external C probe against the admitted install (no src change)",
        "source": "courts/phase25/rt_cms_asn1_callbacks.c",
        "source_sha256": "d58af5cd537338488b696a76778e2eb7b5745ed39e336339df2ef5694623c5a1",
        "build_plain": "cc -std=c11 -O1 -Wall -Wextra -I artifacts/phase2/install/include -o court/tmp/closure-b71-cms/rt_cms_asn1_callbacks courts/phase25/rt_cms_asn1_callbacks.c -L artifacts/phase2/install/lib -lcrypto -Wl,-rpath,/work/artifacts/phase2/install/lib",
        "binary_plain": "court/tmp/closure-b71-cms/rt_cms_asn1_callbacks",
        "binary_plain_sha256": "5a9744390c05bf187a40006aa45e45f06a92904441761fa007c2c25e4fa9af6d",
        "run_plain": "court/tmp/closure-b71-cms/rt_cms_asn1_callbacks",
        "observed_plain": "NOT_RUN cms_cb DETACHED_PRE/POST (SMIME write refused); PASS cms asn1 callbacks: ktri=1 kari=1 kari_ctx=1 kem=1 pkcs7=1 stream=1 malformed=clean",
        "exit_plain": 0,
        "build_lsan": "cc -std=c11 -O1 -g -Wall -Wextra -fsanitize=leak -fno-omit-frame-pointer -I artifacts/phase2/install/include -o court/tmp/closure-b71-cms/rt_cms_asn1_callbacks_lsan courts/phase25/rt_cms_asn1_callbacks.c -L artifacts/phase2/install/lib -lcrypto -Wl,-rpath,/work/artifacts/phase2/install/lib",
        "binary_lsan": "court/tmp/closure-b71-cms/rt_cms_asn1_callbacks_lsan",
        "binary_lsan_sha256": "1d05b925ffa207277164e0ddfd36888155d218145bda10b278c8cffa9d1a6beb",
        "run_lsan": "RT_B71_SKIP_STREAM=1 LSAN_OPTIONS=suppressions=court/tmp/closure-b71-cms/lsan.supp:exitcode=23 court/tmp/closure-b71-cms/rt_cms_asn1_callbacks_lsan",
        "observed_lsan": "PASS cms asn1 callbacks: ktri=1 kari=1 kari_ctx=1 kem=1 pkcs7=1 stream=SKIPPED malformed=clean; 4688 BN_value_one baseline allocations suppressed (93760 bytes)",
        "exit_lsan": 0,
        "result": "PASS (plain all arms; LeakSanitizer on the callback d2i/free/PKCS7 paths)",
        "mutation_sensitive": (
            "The probe exits non-zero if a KARI recipient does not decode as CMS_RECIPINFO_AGREE, if a KEM ORI does not map to CMS_RECIPINFO_KEM, if the KARI/KEM context allocated by NEW_POST is NULL, "
            "if i2d_CMS_bio_stream(SMIME_STREAM) fails, if a malformed/truncated CMS/PKCS7 decode succeeds or crashes, or if PKCS7_encrypt/d2i/add_recipient/free fails. LeakSanitizer observes the live-member releases."
        ),
        "neutral_control": {
            "id": "B71-N1",
            "assertion": "The decode observables are produced by the callbacks, not by default storage: a zeroed CHOICE reads type 0 (TRANS), so a KARI decode reading type 1 and a KEM decode reading type 5 can only come from cms_ri_cb; the context pointers are installed only by cms_kari_cb/cms_kemri_cb NEW_POST.",
            "observed": "KARI type=1 with non-NULL kari ctx; KEM type=5 with non-NULL kemri ctx; both round-trip and free cleanly.",
        },
    },
    "adjudicated": False,
    "review": {
        "state": "PENDING",
        "verdict": "PENDING",
        "adjudicated": False,
        "date": "2026-11-10",
        "reviewer": None,
        "review_history": [
            {"verdict": "PENDING", "date": "2026-11-10", "note": "authoring state: receipt and ledger row added with adjudicated=false; the ssh closure is provisional and not committed"}
        ],
    },
    "supersedes": [],
    "related_receipts": ["boundary-sweep-B70", "boundary-sweep-B69"],
    "instrument_gaps": [
        {"id": "B71-G1", "detail": "consumer_closure.py accepts a scoped discharge on (file, kind, operation) identity plus the recorded span hash and the `^SAFETY_DISCHARGED\\b` disposition prefix. It does not re-audit the callback bodies, the per-site contracts or the probe; those are reviewer-established."},
        {"id": "B71-G2", "detail": "The admitted install leaks in `BN_generate_prime_ex` under LeakSanitizer: a minimal RSA-keygen program leaks 71080 bytes / 3554 allocations attributed to `BN_value_one`, scaling with the number of prime candidates. This is pre-existing candidate/library behaviour outside the seven callback boundaries (no keygen code is in any B71 span). The probe run suppresses only `leak:BN_value_one`; any release omitted by a callback would still surface as an unsuppressed CRYPTO_* leak."},
        {"id": "B71-G3", "detail": "The STREAM arm exposes a separate 387-byte leak in `bio_asn1::ndef_prefix` (its DER buffer is overwritten by `ndef_suffix`'s buffer assignment). This is in the ASN.1 BIO machinery, not in any B71 callback, and is not repaired here (src/ is out of scope). It is why the LSan run sets RT_B71_SKIP_STREAM=1; the plain run still exercises STREAM_PRE/STREAM_POST."},
    ],
    "residuals": [
        {"id": "B71-R1", "class": "private_callback_reachability", "detail": "The seven callbacks are private local symbols; the probe cannot name them and observes them through the machinery's effects (recipient type, allocated ctx) and LeakSanitizer. Direct per-callback counters are not expressible without editing src/ or instrumenting the DSO.", "disposition": "open", "owner": "atlas-maintainer"},
        {"id": "B71-R2", "class": "cms_ri_type_arm_invariant", "detail": "cms_ri_cb FREE_PRE relies on `type_` being an arm index only when `d` is live. This is established for decoded values (D2I_POST copies the matched selector) and fresh values (NEW_POST copies the -1 selector), and every constructor stores `d` before `type_`. A hypothetical caller that re-decoded into an existing CMS_RecipientInfo could leave a stale `type_`; no such caller exists in the crate (the item is private and `SEQUENCE OF` elements decode into fresh slots).", "disposition": "open", "owner": "atlas-maintainer"},
        {"id": "B71-R3", "class": "stream_caller_contract", "detail": "cms_cb STREAM/DETACHED dereferences the caller-supplied value. `BIO_new_NDEF`/`asn1_output_data` require a live value; a C-invalid NULL value faults there, authority-identical. This is a caller precondition of the C ABI, not a hidden obligation of the callback.", "disposition": "open", "owner": "atlas-maintainer"},
        {"id": "B71-R4", "class": "detached_arms_not_run", "detail": "The cms_cb DETACHED_PRE/DETACHED_POST arms were not executed: SMIME_write_CMS(SMIME_DETACHED) refused both an EnvelopedData and a partial SignedData built for the probe. The arms share CMS_dataInit/CMS_dataFinal with the exercised STREAM arms and are discharged at contract level; runtime coverage is NOT_RUN.", "disposition": "open", "owner": "atlas-maintainer"},
        {"id": "B71-R5", "class": "lsan_baseline", "detail": "A clean LeakSanitizer verdict is reported only after suppressing the candidate's pre-existing `BN_value_one` prime-generation leak (B71-G2) and excluding the unrelated `bio_asn1::ndef_prefix` leak (B71-G3). The suppressed population is recorded; no cleanup performed by any B71 callback is suppressed.", "disposition": "open", "owner": "atlas-maintainer"},
    ],
    "not_run": [
        {"gate": "cms_cb ASN1_OP_DETACHED_PRE/ASN1_OP_DETACHED_POST", "blocker": "NOT_RUN: SMIME_write_CMS(SMIME_DETACHED) returned 0 for both an EnvelopedData (CMS_PARTIAL) and a partial SignedData; the arms were not entered. STREAM_PRE/STREAM_POST were entered and returned success."},
        {"gate": "AddressSanitizer", "blocker": "NOT_RUN: the court enforces RLIMIT_DATA=4 GiB and ASan cannot reserve its shadow region; LeakSanitizer ran and passed under the recorded baseline suppression."},
        {"gate": "Miri (Stacked/Tree Borrows)", "blocker": "not invoked; the callback bodies are FFI-only and construct no Rust references, but no Miri run is claimed."},
        {"gate": "authority differential execution", "blocker": "the pinned 3.6.4 source was read; no differential binary was executed."},
        {"gate": "independent BOUNDARY adjudication", "blocker": "PENDING by design; the author does not self-approve (adjudicated=false)."},
    ],
    "non_claims": [
        "Site-scoped to the seven named item callbacks only. RAND_CMS_STORE_KEYFMT remains OWNERSHIP_RECONSTRUCTED mechanism-wide; no mechanism-wide discharge is claimed.",
        "No claim about cms_si_cb, pk7_cb or any other ASN.1 callback, nor about the surrounding CMS/PKCS7 encode/decode/free code beyond the callbacks' own spans.",
        "No claim that the DETACHED arms executed; they are NOT_RUN.",
        "No AddressSanitizer result; LeakSanitizer passed only with the recorded baseline suppression and stream exclusion.",
        "No SAFE_COMPATIBLE consumer graduation.",
    ],
}

order = [
    ("src/cms/cms_asn1.rs", 523, "cms_ec_cb", "CMS-CB-001"),
    ("src/cms/cms_asn1.rs", 539, "cms_rek_cb", "CMS-CB-002"),
    ("src/cms/cms_asn1.rs", 556, "cms_kari_cb", "CMS-CB-003"),
    ("src/cms/cms_asn1.rs", 585, "cms_kemri_cb", "CMS-CB-004"),
    ("src/cms/cms_asn1.rs", 617, "cms_ri_cb", "CMS-CB-005"),
    ("src/cms/cms_asn1.rs", 668, "cms_cb", "CMS-CB-006"),
    ("src/pkcs7/pk7_asn1.rs", 607, "ri_cb", "PK7-CB-001"),
]
for f, ln, it, bid in order:
    receipt["obligations"].append({
        "id": "V1:" + f + ":" + str(ln) + ":UNSAFE_FN_DEF",
        "stable_id": f + "::UNSAFE_FN_DEF::" + it,
        "file": f,
        "line": ln,
        "kind": "UNSAFE_FN_DEF",
        "item": it,
        "mechanism": "RAND_CMS_STORE_KEYFMT",
        "v1_reason": "block-level SAFETY present but no # Safety fn contract",
        "status_before": "BLOCKED",
        "status_after": "DISCHARGED (boundary " + bid + ")",
    })

out = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh/boundary-sweep-B71.json"
out.write_text(json.dumps(receipt, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
print("wrote", out, len(receipt["boundaries"]), "boundaries", len(receipt["obligations"]), "obligations")
for b in receipt["boundaries"]:
    print(b["id"], b["operation"], b["span_start_line"], b["span_end_line"], b["span_sha256"])
