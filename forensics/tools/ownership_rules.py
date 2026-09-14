#!/usr/bin/env python3
"""openssl-rs — the ownership rules: which stratum owns which authority export.

Why this exists, and why it is one file
--------------------------------------
Each phase ledger used to decide its own universe. Phase 3 and Phase 4 did it with
an explicit `(module, prefixes)` list; Phase 5 tried to do it with the stronger
rule "a symbol belongs to the stratum that owns the header declaring it", but kept
a **prefix test** to choose its candidates. That is the D49/D51 defect class, and
it recurred a third time: `a2d_ASN1_OBJECT` is declared in `asn1.h`, matches none
of `^(BN_|ASN1_|d2i_|i2d_|PEM_)`, and was therefore invisible to every ledger at
once — because discovery was prefix-derived even though assignment was
header-derived.

The fix is not another prefix. It is one generated artifact,
`forensics/atlas/symbol-ownership.json`, whose universe is **every authority
export** (6,499 across `libcrypto.so.3` and `libssl.so.3`), with each export
assigned to exactly one stratum by a rule that is stated here once and applied
everywhere. Each phase ledger then becomes a *projection* of that atlas rather
than an opinion about it.

What a rule is
--------------
`owner_phase()` answers `(phase, rule)` for a symbol. The rules, in the order they
are tried:

1. `abi-only` — the DSO exports it and **no installed header declares it**. The
   authority has 26 of these. They are part of the binary contract (a precompiled
   binary resolves them) but not the source contract, so they need a disposition
   rather than a header. Each is named in `ABI_ONLY_OWNER` with the stratum that
   will implement it and why.
2. `declaring-header` — the header that declares the symbol, mapped through
   `HEADER_PHASE`.
3. `pem-typed-object` — `pem.h` declares both the generic PEM machinery and the
   typed readers and writers for types owned elsewhere, so `pem.h` alone says
   nothing. The trailing type in the name is resolved through the Phase 1 atlas's
   type→header evidence (`structs.json`, `typedefs.json`, the `d2i_T`/`i2d_T`
   names) and the *type's* header decides. `PEM_read_bio_X509` is Phase 11's,
   `PEM_read_bio_PKCS8_PRIV_KEY_INFO` is Phase 10's, and the generic
   `PEM_read_bio` is Phase 5's.

Failure is loud. An export whose symbol or type resolves to a header with no
entry in `HEADER_PHASE` stops the atlas rather than defaulting to "probably this
phase" — an unassigned export must never look like an assigned one.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Which stratum owns a header.
#
# Every entry is a decision, and the value is the phase that will *implement* the
# subsystem the header declares -- not the phase that first needs it. The entries
# for headers whose symbols Phases 3, 4 and 5 already implement are not decisions
# at all: they are read off those ledgers, and `symbol_ownership.py` checks that
# each one agrees. An entry here that disagreed with an existing ledger would show
# up as a `ledger_disagreement` row rather than being resolved silently.
# ---------------------------------------------------------------------------

HEADER_PHASE: dict[str, int] = {
    # -- Phase 3, core runtime ---------------------------------------------
    "crypto.h": 3,              # allocation, refcounts, the atomics, init
    "cryptoerr_legacy.h": 3,    # the legacy per-library ERR_load_T_strings family
    "err.h": 3,                 # the thread-local error queue
    "lhash.h": 3,               # the open hash table
    "objects.h": 3,             # the OID/NID database
    "stack.h": 3,               # OPENSSL_STACK
    "thread.h": 3,              # CRYPTO_THREAD_* locks and thread-locals
    "trace.h": 3,               # OSSL_TRACE_*, a core diagnostic facility
    "async.h": 3,               # the async job framework the core runtime owns
    # -- Phase 4, BIO, CONF and the object database's BIO-facing surface ----
    "bio.h": 4,
    "buffer.h": 4,              # BUF_MEM, the memory BIO's storage
    "comp.h": 4,                # the compression BIOs' method layer
    "conf.h": 4,
    # -- Phase 5, BN, ASN.1 and PEM -----------------------------------------
    "bn.h": 5,
    "asn1.h": 5,
    "asn1t.h": 5,
    "pem.h": 5,                 # the generic machinery; typed names resolve below
    # -- Phase 6, OSSL_LIB_CTX and the provider core ------------------------
    "core_names.h": 6,
    "core_object.h": 6,
    "provider.h": 6,
    "params.h": 6,
    "param_build.h": 6,
    "self_test.h": 6,
    "indicator.h": 6,
    # -- Phase 7, the EVP execution model -----------------------------------
    "evp.h": 7,
    "kdf.h": 7,
    "hpke.h": 7,                # HPKE is an EVP-level KEM API
    "hmac.h": 7,                # the one-shot digest-MAC helpers
    "cmac.h": 7,
    # -- Phase 8, the native primitives and the key types they define -------
    "aes.h": 8,
    "aria.h": 8,
    "blowfish.h": 8,
    "camellia.h": 8,
    "cast.h": 8,
    "des.h": 8,
    "dh.h": 8,
    "dsa.h": 8,
    "ec.h": 8,
    "idea.h": 8,
    "md4.h": 8,
    "md5.h": 8,
    "mdc2.h": 8,
    "modes.h": 8,
    "rc2.h": 8,
    "rc4.h": 8,
    "ripemd.h": 8,
    "rsa.h": 8,
    "seed.h": 8,
    "sha.h": 8,
    "sm2.h": 8,
    "sm3.h": 8,
    "sm4.h": 8,
    "whrlpool.h": 8,
    # -- Phase 9, RAND, DRBG and entropy ------------------------------------
    "rand.h": 9,
    # -- Phase 10, key formats, PKCS and STORE ------------------------------
    "decoder.h": 10,
    "encoder.h": 10,
    "pkcs12.h": 10,
    "store.h": 10,
    # -- Phase 11, X.509 and path validation --------------------------------
    "x509.h": 11,
    "x509_acert.h": 11,
    "x509_vfy.h": 11,
    "x509v3.h": 11,
    # -- Phase 12, the remaining libcrypto protocol families ----------------
    "cmp.h": 12,
    "cmp_util.h": 12,
    "cms.h": 12,
    "crmf.h": 12,
    "ct.h": 12,
    "ess.h": 12,
    "http.h": 12,               # the HTTP/1.1 client OCSP and CT fetch through
    "ocsp.h": 12,
    "pkcs7.h": 12,
    "srp.h": 12,
    "ts.h": 12,
    # -- Phase 13, legacy and deprecated compatibility ----------------------
    #
    # Phase 13 owns the *deprecated API surface*, not any header of its own: the
    # METHOD-era entry points (`DH_meth_new`, `RSA_set_default_method`, the whole
    # `ENGINE_*` family) are declared in `dh.h`, `rsa.h`, `ec.h` and `engine.h`,
    # which belong to the strata that implement the underlying algorithm. A header
    # is not split between two phases by this table.
    "engine.h": 13,
    "ui.h": 13,                 # the UI framework, whose users are the legacy APIs
    "txt_db.h": 13,             # TXT_DB, the text database the `ca` app reads
    # -- Phase 14, TLS and DTLS ---------------------------------------------
    "ssl.h": 14,
    "sslerr_legacy.h": 14,
    "tls1.h": 14,
    "srtp.h": 14,               # the DTLS-SRTP profile identifiers
    # -- Phase 15, QUIC and ECH ---------------------------------------------
    "quic.h": 15,
}

# No header appears twice above; `symbol_ownership.py` asserts that, because a
# duplicate silently keeps the last value and a silently-overridden decision is
# exactly the class of defect this table exists to remove.

# ---------------------------------------------------------------------------
# The 26 exports the DSO exports and no installed header declares.
#
# The Phase 1 completeness work classified these `ABI_ONLY_EXPORTED`:
# `source_public = false`, `binary_public = true`, `must_export = true`. They are
# part of the binary contract -- a precompiled binary resolves them -- but not the
# source contract, so a header cannot decide their owner and this table does.
# ---------------------------------------------------------------------------

ABI_ONLY_OWNER: dict[str, tuple[int, str]] = {
    # The dynamic-loader abstraction. It is the runtime half of what Phase 2's
    # distribution shell describes but does not implement, and it has no header
    # because nothing is meant to call it from a header: the exports exist for
    # `DSO_load`'s users inside the library.
    "DSO_bind_func": (2, "crypto/dso; the loader Phase 2's distribution contract describes"),
    "DSO_convert_filename": (2, "crypto/dso"),
    "DSO_ctrl": (2, "crypto/dso"),
    "DSO_dsobyaddr": (2, "crypto/dso"),
    "DSO_flags": (2, "crypto/dso"),
    "DSO_free": (2, "crypto/dso"),
    "DSO_get_filename": (2, "crypto/dso"),
    "DSO_global_lookup": (2, "crypto/dso"),
    "DSO_load": (2, "crypto/dso"),
    "DSO_merge": (2, "crypto/dso"),
    "DSO_new": (2, "crypto/dso"),
    "DSO_pathbyaddr": (2, "crypto/dso"),
    "DSO_set_filename": (2, "crypto/dso"),
    "DSO_up_ref": (2, "crypto/dso"),
    "DSO_METHOD_openssl": (2, "crypto/dso/dso_dlfcn.c"),
    # The directory reader Phase 3 implements; declared in `crypto/o_dir.h`,
    # which is not installed.
    "OPENSSL_DIR_read": (3, "crypto/o_dir.c; installed headers declare no o_dir.h"),
    "OPENSSL_DIR_end": (3, "crypto/o_dir.c; installed headers declare no o_dir.h"),
    # The ERR string table teardown, declared in `crypto/err/err_local.h`.
    "err_free_strings_int": (3, "crypto/err/err_local.h is not installed"),
    # The CONF helpers the `ca` application uses, declared in
    # `crypto/conf/conf_local.h`.
    "conf_ssl_get": (4, "crypto/conf/conf_ssl.c; conf_local.h is not installed"),
    "conf_ssl_get_cmd": (4, "crypto/conf/conf_ssl.c"),
    "conf_ssl_name_find": (4, "crypto/conf/conf_ssl.c"),
    # The DER reader behind `d2i_*_bio`, declared in `crypto/asn1/asn1_local.h`.
    "asn1_d2i_read_bio": (5, "crypto/asn1/a_d2i_fp.c; asn1_local.h is not installed"),
    # The four typed CMS readers and writers, declared in `cms.h` inside an
    # `#ifndef OPENSSL_NO_CMS` block the atlas's header pass does not see.
    "PEM_read_CMS": (12, "the typed reader for CMS; cms.h is Phase 12's"),
    "PEM_read_bio_CMS": (12, "the typed reader for CMS; cms.h is Phase 12's"),
    "PEM_write_CMS": (12, "the typed writer for CMS; cms.h is Phase 12's"),
    "PEM_write_bio_CMS": (12, "the typed writer for CMS; cms.h is Phase 12's"),
}

# ---------------------------------------------------------------------------
# `pem.h`'s typed names. The trailing type group after the call-shape suffix
# names the object, and the object's header decides.
# ---------------------------------------------------------------------------

PEM_TYPE_RE = re.compile(r"^PEM_[a-z0-9]+(?:_bio|_fp|_asn1)?_(.+)$")

# Headers that say nothing about who owns a type. `types.h` forward-declares every
# type, and `pem.h` declares the typed readers for every type it can serialise, so
# a type resolved to either has told us nothing.
WEAK_TYPE_HEADERS = frozenset({"types.h", "pem.h"})


def weak_type_header(header: str | None) -> bool:
    """True when a type's resolved header says nothing about who owns it."""
    return header is None or header in WEAK_TYPE_HEADERS


def owner_phase(
    symbol: str,
    header: str | None,
    types: dict[str, str],
) -> tuple[int | None, str, str | None]:
    """The owning phase of one export.

    Answers `(phase, rule, resolved_header)`. `phase` is `None` only when the rules
    cannot decide, which the caller must treat as a hard failure rather than as
    "unowned".

    `types` maps a type name to the best header the Phase 1 atlas can offer for it
    (see `type_headers` in `phase5_obligations.py`, whose logic this module now
    shares).
    """
    if header is None:
        found = ABI_ONLY_OWNER.get(symbol)
        if found is None:
            return None, "abi-only", None
        return found[0], "abi-only", None
    if header == "pem.h":
        m = PEM_TYPE_RE.match(symbol)
        if m is None:
            # A generic PEM entry point with no type in its name.
            return HEADER_PHASE["pem.h"], "declaring-header", "pem.h"
        type_header = types.get(m.group(1))
        if weak_type_header(type_header):
            return HEADER_PHASE["pem.h"], "declaring-header", "pem.h"
        return HEADER_PHASE.get(type_header), "pem-typed-object", type_header
    phase = HEADER_PHASE.get(header)
    return phase, "declaring-header", header
