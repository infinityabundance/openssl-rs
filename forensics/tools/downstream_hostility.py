#!/usr/bin/env python3
"""openssl-rs — Phase-24.10 hostility augmentation: the **separate** hostility-augmentation corpus.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). The counted population exercises a bounded
union of OpenSSL surfaces: the imported symbols, the headers and the API families the committed 24.3
usage fingerprints, 24.6 build/link atlas, 24.7 runtime/functional atlas and 24.9 high-value tier
record. This module owns the stratum's **hostility augmentation** (the brief's section 12): a
**separate** corpus of standalone, deterministic probes that exercise the *rare* OpenSSL surfaces a
real consumer relies on but the counted population rarely touches -- legacy ENGINE loading, provider
configuration, custom BIO methods, the error queue, callback/ownership, `fork`/reinit, threading,
PKCS#12, CMS, OCSP-adjacent and public-layout surfaces, `dlopen`, and static linking -- chosen by
**maximum marginal contract novelty** over that covered union using the Phase-22 public-entity
inventory.

The corpus is separate by design
------------------------------
The corpus is **not** part of the counted P1000 population and its results are **never mixed into the
population's rates** (`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` section 3.7). Every member carries
`role: "hostility"` and a `hostility:` id; no member is a `family`, no member carries a frozen
`family_id`, and the frozen P1000 count is a read of `forensics/downstream/family-freeze.json` rather
than a number this artefact can move. The corpus is the stratum's augmentation, and a passing corpus
is an instrument, not a rate.

The frozen selection rule (reads no candidate result)
-----------------------------------------------------
`covered_surface` is a **pure function of committed evidence**: the union of the imported OpenSSL
symbols and the OpenSSL headers the committed atlases record (plus the API families derived from the
symbols). From the Phase-22 public-entity inventory (`forensics/atlas/implemented-surface.json` and the
`forensics/atlas/openssl-3.6.4-production/` entity atlases) the corpus is then selected by **maximum
marginal novelty**: the candidate probe targets are the authored surfaces below, each declaring the
public OpenSSL entities it exercises; a target's novelty is the count of its entities **not in the
covered surface**, and the corpus is chosen greedily -- at each step the target whose entities add the
most *uncovered* — i.e. *not already contributed* — entities, tie-broken by (rarer/more-legacy
entities first, then `surface_id` ascending). The selection reads no candidate row, so a surface
cannot enter the corpus by what the candidate happens to pass.

Proving the OpenSSL path is enabled (section 61)
-----------------------------------------------
Every probe is a real C program compiled against each subject's OpenSSL install prefix and run
locally, and the load proof is **three readings**, not a banner: the program's `ldd` resolution of
every OpenSSL soname (under the subject prefix, never the authority's, for a candidate row), the
dynamic loader's `LD_DEBUG=libs` initialisation of the subject library, and the program's own runtime
`dladdr` of an OpenSSL symbol (the `openssl_lib=` line). A `dlopen` probe links **no** OpenSSL and
proves the subject through the runtime loader; a `static` probe links the subject's `libcrypto.a` with
no OpenSSL `DT_NEEDED` and proves the subject through the archive it was built from. A probe whose
loaded library is not the subject's is a finding, not a pass.

Local-only, bounded, normalised
-------------------------------
Every network member runs against the admitted authority's own local PKI over loopback only (the
brief's sections 46 and 63): the candidate and the authority each act as TLS client and server, in
both directions, so a cross-implementation pair is measured. No run touches the public internet. Every
fetch, compile and run is bounded by this tool's wall-clock limits and runs inside the admitted court
container. Each measured row carries a `transcript_sha256` over its normalised transcript, and the
**same** normaliser 24.7 uses is applied to both subjects (paths, ports, PIDs, timestamps, addresses);
a return code, an error class, a certificate decision or a protocol/algorithm choice is never
normalised.

Measurement, not a pure function -- so not in `evidence_determinism.py`
----------------------------------------------------------------------
This tool compiles and runs real probes inside the court container, so the level a run reaches and its
normalised transcript are a function of the court's toolchain, not of committed inputs -- the same
precedent as 24.6's build/link atlas, 24.7's runtime/functional atlas, 24.9's high-value tier and the
Phase-17 measured corpus under `courts/phase17/downstream/*/result.json`. It is therefore **not** in
`forensics/tools/evidence_determinism.py`'s `GENERATORS` or `COMPARED`, and the court
`RT-HOSTILITY-AUGMENTATION` re-runs only this module's **pure** functions over the committed artefact
and never rebuilds.

The Docker-only guard is called first
-------------------------------------
This tool compiles and runs, so it is an **execution** entry point: `phase24_guard.require_admitted()`
is the first statement of `main`, and a host invocation is refused (`docs/REPRODUCIBILITY.md`
section 1).

Outputs
-------
  forensics/downstream/hostility-corpus.json   the separate hostility corpus and its runs, both subjects

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_bytes,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool compiles and
# runs, so it is an execution entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schemas the rows are validated against, imported rather than restated so the vocabulary
# cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

# The 24.3 census primitives (bounded subprocess, ELF inspection, resource limits) are reused.
import downstream_census as census  # noqa: E402

# The 24.6 build/link atlas: its candidate-identity helper is reused so the corpus names the exact
# candidate it measured.
import downstream_build_link as bl  # noqa: E402

# The 24.7 runtime/functional atlas: the local PKI fixture, the authority CLI helpers, the load proof,
# the normaliser and the transcript construction are **imported and reused**, so a hostility run is
# the exact local workload machinery 24.7 measured with (one code path, not two that can drift).
import downstream_runtime as rt  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the corpus and the freeze cannot drift.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
USAGE_FINGERPRINTS = REPO_ROOT / "forensics" / "downstream" / "usage-fingerprints.json"
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
RUNTIME_FUNCTIONAL_ATLAS = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"
HIGH_VALUE_TIER = REPO_ROOT / "forensics" / "downstream" / "high-value-tier.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "hostility-corpus.json"

# The Phase-22 public-entity inventory: the implemented surface and the per-entity atlases of the
# production authority. The hostility corpus is selected against this inventory and the covered union.
IMPLEMENTED_SURFACE = REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json"
PHASE22_AUTHORITY = REPO_ROOT / "forensics" / "atlas" / "openssl-3.6.4-production"

# The committed probe sources (a C program and/or a shared header) under the hostility directory.
HOSTILITY_DIR = REPO_ROOT / "forensics" / "downstream" / "hostility"
COMMON_HEADER = "hostility_common.h"

CANDIDATE_PREFIX = bl.CANDIDATE_PREFIX

# Scratch is kept under `/work/court` (never `/tmp` or the container's `/`) and removed after the
# measurement; only the small committed artefact persists in the tree.
SCRATCH = REPO_ROOT / "court" / "phase24-hostility"

GENERATOR = "forensics/tools/downstream_hostility.py"
CC = "cc"

L0 = "L0-catalogued"
L3 = "L3-built"
L4 = "L4-linked"
L5 = "L5-loaded"
L6 = "L6-runtime"
L7 = "L7-functional"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

STEP_TIMEOUT = census.STEP_TIMEOUT
LAUNCH_TIMEOUT = census.LAUNCH_TIMEOUT
BUILD_TIMEOUT = 300
NET_TIMEOUT = 60

SUBJECTS = ("authority", "candidate")

NORMALISATION_TAG = rt.NORMALISATION_TAG
NORMALISATION_ALLOWED = rt.NORMALISATION_ALLOWED
NORMALISATION_NEVER = rt.NORMALISATION_NEVER

# The bounded corpus size. The selection is a greedy maximum-marginal-novelty pick over the candidate
# targets below, capped here so the corpus stays bounded; a target beyond the cap is recorded
# `not_selected` with the reason rather than silently dropped.
CORPUS_BOUND = 12

# The subject versions treated as legacy/rare for the tie-break: an entity that exists only in an
# OpenSSL before 3.1 (or is deprecated, or has no EXIST ordinal in the production authority).
OLD_VERSIONS = frozenset({
    "OPENSSL_0.9.8", "OPENSSL_1.0.0", "OPENSSL_1.0.1", "OPENSSL_1.0.2", "OPENSSL_1.1.0",
    "OPENSSL_1.1.1",
})

# TLS protocol-version constants for the section-62 tls1.2/tls1.3 variants.
TLS1_2_VERSION = 0x0303

# The stratum's four non-claims (imported from 24.4 so the two cannot drift) plus the one this
# subphase's measurement adds: the hostility corpus is not part of the counted P1000 population and
# its results are not mixed into the population's rates.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "the hostility corpus is not part of the counted P1000 population and its results are not mixed "
    "into the population's rates: the corpus augments the stratum with a separate set of rare-surface "
    "probes, it carries no frozen family_id, and a pass or a failure here moves no drop-in rate",
]


# ===================================================================================================
# the committed candidate probe targets: each authored surface and the public entities it exercises
# ===================================================================================================
#
# Every surface is a standalone, deterministic probe (a C program and/or a shared header) compiled
# against each subject and run locally. `entities` names the public OpenSSL entities the probe
# exercises (each must appear in the committed source and in the Phase-22 public-entity inventory);
# `foreign_symbols` names the non-OpenSSL symbols a probe may use (a `dlopen` probe uses `dlopen`).
# The `variant` names the brief's section-62 configuration the member exercises.

SURFACES: tuple[dict, ...] = (
    {
        "surface_id": "hostility:custom-bio",
        "title": "custom BIO method (callback + ownership)",
        "variant": "callback",
        "probe_kind": "shared-c",
        "sources": ["custom_bio.c"],
        "entities": ["BIO_meth_new", "BIO_meth_set_write", "BIO_meth_set_read",
                     "BIO_meth_set_ctrl", "BIO_meth_set_create", "BIO_meth_set_destroy",
                     "BIO_meth_get_write", "BIO_meth_get_read", "BIO_meth_get_ctrl",
                     "BIO_meth_get_create", "BIO_meth_get_destroy", "BIO_get_new_index",
                     "BIO_set_callback_ex", "BIO_meth_free", "BIO_new", "BIO_set_data",
                     "BIO_get_data", "BIO_set_init", "BIO_up_ref", "BIO_free", "BIO_read",
                     "BIO_write", "BIO_ctrl"],
        "foreign_symbols": [],
        "network": False,
    },
    {
        "surface_id": "hostility:engine-legacy",
        "title": "legacy ENGINE registry and dynamic binding",
        "variant": "legacy-provider",
        "probe_kind": "shared-c",
        "sources": ["engine_legacy.c"],
        "entities": ["ENGINE_load_builtin_engines", "ENGINE_register_all_complete",
                     "ENGINE_get_first", "ENGINE_get_next", "ENGINE_get_id", "ENGINE_by_id",
                     "ENGINE_ctrl_cmd_string", "ENGINE_free"],
        "foreign_symbols": [],
        "network": False,
    },
    {
        "surface_id": "hostility:provider-config",
        "title": "provider loading / availability / algorithm fetch",
        "variant": "provider-configuration",
        "probe_kind": "shared-c",
        "sources": ["provider_config.c"],
        "entities": ["OSSL_PROVIDER_load", "OSSL_PROVIDER_get0_name", "OSSL_PROVIDER_available",
                     "OSSL_PROVIDER_try_load", "OSSL_PROVIDER_unload", "EVP_MD_fetch",
                     "EVP_MD_get0_name", "EVP_MD_free"],
        "foreign_symbols": [],
        "network": False,
    },
    {
        "surface_id": "hostility:error-queue",
        "title": "error-queue mark/pop lifetime and ERR_get_error_all",
        "variant": "callback",
        "probe_kind": "shared-c",
        "sources": ["error_queue.c"],
        "entities": ["ERR_set_mark", "ERR_pop_to_mark", "ERR_peek_last_error", "ERR_clear_error",
                     "ERR_get_error_all", "ERR_error_string_n", "ERR_lib_error_string",
                     "ERR_reason_error_string"],
        "foreign_symbols": [],
        "network": False,
    },
    {
        "surface_id": "hostility:layout",
        "title": "public-layout assumptions (version macros + accessors + OSSL_PARAM)",
        "variant": "public-layout",
        "probe_kind": "shared-c",
        "sources": ["layout.c"],
        "entities": ["OPENSSL_VERSION_MAJOR", "OPENSSL_VERSION_MINOR", "OPENSSL_VERSION_PATCH",
                     "OPENSSL_VERSION_NUMBER", "X509_new", "X509_set_version", "X509_get_version",
                     "X509_get0_notBefore", "X509_free", "OSSL_PARAM_construct_utf8_string"],
        "foreign_symbols": [],
        "network": False,
    },
    {
        "surface_id": "hostility:fork-reinit",
        "title": "fork and re-initialisation of an initialised library",
        "variant": "forking",
        "probe_kind": "shared-c",
        "sources": ["fork_reinit.c"],
        "entities": ["OPENSSL_init_crypto", "OPENSSL_INIT_ATFORK", "RAND_bytes",
                     "RAND_priv_bytes", "EVP_MD_CTX_new", "EVP_MD_CTX_copy", "EVP_DigestInit_ex",
                     "EVP_DigestUpdate", "EVP_DigestFinal_ex", "EVP_MD_CTX_free"],
        "foreign_symbols": ["fork", "waitpid"],
        "network": False,
    },
    {
        "surface_id": "hostility:threading",
        "title": "threading contract (CRYPTO_ONCE + CRYPTO_RWLOCK under concurrency)",
        "variant": "threaded",
        "probe_kind": "shared-c",
        "sources": ["threading.c"],
        "entities": ["CRYPTO_THREAD_run_once", "CRYPTO_THREAD_get_current_id",
                     "CRYPTO_THREAD_lock_new", "CRYPTO_THREAD_write_lock", "CRYPTO_THREAD_unlock",
                     "CRYPTO_THREAD_lock_free", "EVP_sha256", "EVP_MD_CTX_new"],
        "foreign_symbols": ["pthread_create", "pthread_join"],
        "network": False,
    },
    {
        "surface_id": "hostility:dlopen",
        "title": "runtime dynamic loading of the subject library",
        "variant": "dlopen",
        "probe_kind": "dlopen",
        "sources": ["dlopen.c"],
        "entities": ["OpenSSL_version", "EVP_MD_fetch", "EVP_MD_get0_name", "EVP_MD_free",
                     "OSSL_PROVIDER_load_ex"],
        "foreign_symbols": ["dlopen", "dlsym", "dladdr", "dlclose"],
        "network": False,
    },
    {
        "surface_id": "hostility:pkcs12",
        "title": "PKCS#12 create/parse (PKCS + PBE)",
        "variant": "pkcs",
        "probe_kind": "shared-c",
        "sources": ["pkcs12.c", COMMON_HEADER],
        "entities": ["PKCS12_PBE_add", "PKCS12_create", "PKCS12_parse", "PKCS12_free", "i2d_PKCS12",
                     "d2i_PKCS12", "EVP_PKEY_Q_keygen", "X509_sign"],
        "foreign_symbols": [],
        "network": False,
    },
    {
        "surface_id": "hostility:cms",
        "title": "CMS signed-data create/verify (CMS / S-MIME)",
        "variant": "cms",
        "probe_kind": "shared-c",
        "sources": ["cms.c", COMMON_HEADER],
        "entities": ["CMS_sign", "CMS_verify", "CMS_ContentInfo_free", "i2d_CMS_ContentInfo",
                     "d2i_CMS_ContentInfo", "X509_STORE_new", "X509_STORE_add_cert",
                     "X509_STORE_free"],
        "foreign_symbols": [],
        "network": False,
    },
    {
        "surface_id": "hostility:tls",
        "title": "cross-implementation TLS client/server (tls1.2 and tls1.3)",
        "variant": "tls1.3",
        "probe_kind": "network",
        "sources": ["tls_server.c", "tls_client.c", COMMON_HEADER],
        "entities": ["TLS_server_method", "TLS_client_method", "SSL_CTX_new",
                     "SSL_CTX_set_min_proto_version", "SSL_CTX_set_max_proto_version",
                     "SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file",
                     "SSL_CTX_check_private_key", "SSL_CTX_load_verify_locations",
                     "SSL_CTX_set_verify", "SSL_new", "SSL_set_fd", "SSL_accept", "SSL_connect",
                     "SSL_read", "SSL_write", "SSL_get_version", "SSL_get_current_cipher",
                     "SSL_CIPHER_get_name", "SSL_set_tlsext_host_name", "SSL_get_verify_result"],
        "foreign_symbols": [],
        "network": True,
    },
    {
        "surface_id": "hostility:static",
        "title": "static linkage against the subject libcrypto.a",
        "variant": "static",
        "probe_kind": "static",
        "sources": ["static_crypto.c", COMMON_HEADER],
        "entities": ["EVP_DigestInit_ex", "EVP_DigestUpdate", "EVP_DigestFinal_ex",
                     "EVP_MD_CTX_new", "BN_new", "BN_set_word", "BN_bn2hex",
                     "OPENSSL_buf2hexstr"],
        "foreign_symbols": [],
        "network": False,
    },
)

# The frozen rule, recorded verbatim in the artefact and re-derived by the court.
RULE: dict = {
    "id": "downstream-hostility-augmentation/1",
    "name": "the separate hostility-augmentation corpus",
    "selection_rule": (
        "candidate probe targets are ranked by **maximum marginal novelty**: at each step the target "
        "whose declared public OpenSSL entities add the most entities not already in the covered "
        "surface (the P1000 union) and not already contributed by an earlier pick, tie-broken by "
        "(more rare/legacy entities first, then surface_id ascending); the corpus is the greedy pick "
        "capped at the corpus bound. The selection reads no candidate row"
    ),
    "covered_surface": (
        "a pure function of committed evidence: the union of the imported OpenSSL symbols and the "
        "OpenSSL headers the committed 24.3 usage fingerprints (and any specimens/variants/runs of "
        "the 24.6/24.7/24.9 atlases) record, plus the API families derived from those symbols"
    ),
    "inventory": (
        "the Phase-22 public-entity inventory: forensics/atlas/implemented-surface.json and the "
        "forensics/atlas/openssl-3.6.4-production/ entity atlases (functions, symbols, macros, "
        "typedefs, structs, enums, cli-commands). Rarity/legacy-ness is derived from each entity's "
        "deprecated flag, its ordinal status, and its subject version"
    ),
    "separation_rule": (
        "the corpus is separate by design: every member carries role `hostility` and a `hostility:` "
        "id, no member is a family, no member carries a frozen family_id, and the corpus is never "
        "mixed into the counted P1000 population's rates"
    ),
    "enabled_path_rule": (
        "the OpenSSL path must be proven enabled for the subject (section 61): each shared-C and "
        "network probe is proven by its ldd resolution of every OpenSSL soname under the subject "
        "prefix (never the authority's), by the LD_DEBUG=libs initialisation of the subject library, "
        "and by the program's own runtime dladdr of an OpenSSL symbol; a dlopen probe links no OpenSSL "
        "and is proven by the runtime loader's resolution of the subject shared object; a static "
        "probe is proven by the no-OpenSSL-DT_NEEDED binary built from the subject's libcrypto.a"
    ),
    "network_rule": (
        "every network member runs against the admitted authority's own local PKI over loopback only "
        "(sections 46 and 63): the candidate and the authority each act as TLS client and server, in "
        "both directions, so a cross-implementation pair is measured; no run touches the public "
        "internet"
    ),
    "levels": [L5, L6, L7],
    "subjects": list(SUBJECTS),
    "corpus_bound": CORPUS_BOUND,
    "normalisation": {
        "tag": NORMALISATION_TAG,
        "normalises": list(NORMALISATION_ALLOWED),
        "never": list(NORMALISATION_NEVER),
        "policy": (
            "the same normaliser is applied to both subjects; it replaces only absolute paths, ports, "
            "PIDs, timestamps and addresses, and never a return code, an error class, a certificate "
            "decision, or a protocol/algorithm choice"
        ),
    },
    "confinement": (
        "each compile and run runs inside the admitted court container under its cgroup caps and this "
        "tool's own wall-clock bounds; scratch is under /work/court and removed afterwards"
    ),
    "constants": {"corpus_bound": CORPUS_BOUND, "step_timeout_seconds": STEP_TIMEOUT,
                  "build_timeout_seconds": BUILD_TIMEOUT, "launch_timeout_seconds": LAUNCH_TIMEOUT},
}


# ===================================================================================================
# the committed inputs: the covered surface, the public-entity inventory, the frozen P1000
# ===================================================================================================

def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def load_inventory() -> dict:
    """The Phase-22 public-entity inventory and the rarity/legacy metadata of each entity.

    A pure read of the committed Phase-22 atlases: the implemented surface gives the exported
    symbols, `functions.json` the declared-function records with the `deprecated` flag, the
    `symbols-*.json` atlases the ordinal `status`/`version`, and the macro/typedef/struct/enum/CLI
    atlases the remaining public names. Returns `{names, meta, count}`.
    """
    names: set[str] = set()
    meta: dict[str, dict] = {}
    surface = _load_json(IMPLEMENTED_SURFACE)
    for _lib, val in (surface.get("libraries") or {}).items():
        for sym in val.get("implemented_symbols") or []:
            names.add(str(sym))
            meta.setdefault(str(sym), {})
    functions = _load_json(PHASE22_AUTHORITY / "functions.json")
    for rec in functions.get("records") or []:
        name = str(rec.get("name"))
        names.add(name)
        m = meta.setdefault(name, {})
        m["deprecated"] = bool(rec.get("deprecated"))
        if rec.get("header"):
            m["header"] = str(rec["header"])
    for atlas in ("symbols-libcrypto", "symbols-libssl"):
        body = _load_json(PHASE22_AUTHORITY / f"{atlas}.json")
        for rec in body.get("records") or []:
            name = str(rec.get("symbol"))
            names.add(name)
            m = meta.setdefault(name, {})
            num = rec.get("num") or {}
            dso = rec.get("dso") or {}
            if num:
                if num.get("deprecated"):
                    m["deprecated"] = True
                if num.get("status"):
                    m["status"] = str(num["status"])
            if dso.get("version"):
                m["version"] = str(dso["version"])
    for atlas in ("macros", "typedefs", "structs", "enums"):
        body = _load_json(PHASE22_AUTHORITY / f"{atlas}.json")
        for rec in body.get("records") or []:
            names.add(str(rec.get("name")))
    cli = _load_json(PHASE22_AUTHORITY / "cli-commands.json")
    for cmd in cli.get("commands") or []:
        names.add(str(cmd.get("name")))
    names.discard("None")
    return {"names": names, "meta": meta, "count": len(names)}


def load_plane() -> dict:
    """The committed atlases the covered surface is a union of, plus the frozen P1000."""
    return {
        "usage_fingerprints": _load_json(USAGE_FINGERPRINTS),
        "build_link": _load_json(BUILD_LINK_ATLAS),
        "runtime": _load_json(RUNTIME_FUNCTIONAL_ATLAS),
        "high_value": _load_json(HIGH_VALUE_TIER),
        "family_freeze": _load_json(FAMILY_FREEZE),
    }


def load_inputs() -> dict:
    """Every committed input the derivation and the court re-read (inventory loaded once)."""
    inputs = load_plane()
    inputs["inventory"] = load_inventory()
    return inputs


def covered_surface(inputs: dict) -> dict:
    """The P1000-covered surface: the union of the committed atlases' imported symbols and headers.

    A pure function of committed evidence. It reads the 24.3 usage fingerprints and any
    specimens/variants/runs of the 24.6/24.7/24.9 atlases that carry the imported-symbol/header
    lists, and derives the API families from the symbols.
    """
    symbols: set[str] = set()
    headers: set[str] = set()

    def absorb(row: dict) -> None:
        for field in ("imported_openssl_symbols", "openssl_symbols"):
            val = row.get(field)
            if isinstance(val, list):
                symbols.update(str(s) for s in val)
        val = row.get("openssl_headers")
        if isinstance(val, list):
            headers.update(str(h) for h in val)

    for fp in inputs["usage_fingerprints"].get("fingerprints") or []:
        absorb(fp)
    for key in ("build_link", "runtime", "high_value"):
        body = inputs[key]
        for coll in ("specimens", "variants", "runs"):
            for row in body.get(coll) or []:
                if isinstance(row, dict):
                    absorb(row)
    symbols.discard("")
    headers.discard("")
    api_families = {s.split("_", 1)[0] for s in symbols if s}
    return {
        "symbols": sorted(symbols),
        "headers": sorted(headers),
        "api_families": sorted(api_families),
        "symbol_count": len(symbols),
        "header_count": len(headers),
        "api_family_count": len(api_families),
        "hash": content_hash([sorted(symbols), sorted(headers), sorted(api_families)]),
    }


def _is_legacy(name: str, inv: dict) -> bool:
    m = inv["meta"].get(name) or {}
    if m.get("deprecated"):
        return True
    if m.get("status") and m["status"] != "EXIST":
        return True
    if m.get("version") in OLD_VERSIONS:
        return True
    return False


def _candidate_target(surface: dict, inv: dict, covered_symbols: set[str]) -> dict:
    entities = [str(e) for e in surface["entities"]]
    missing = sorted(e for e in entities if e not in inv["names"])
    novel = [e for e in entities if e not in covered_symbols]
    legacy = sum(1 for e in entities if _is_legacy(e, inv))
    return {
        "surface_id": str(surface["surface_id"]),
        "role": "hostility",
        "title": str(surface["title"]),
        "variant": str(surface["variant"]),
        "probe_kind": str(surface["probe_kind"]),
        "sources": [f"forensics/downstream/hostility/{s}" for s in surface["sources"]],
        "entities": entities,
        "foreign_symbols": [str(s) for s in surface.get("foreign_symbols") or []],
        "network": bool(surface.get("network")),
        "legacy_entities": legacy,
        "novelty_vs_covered": len(novel),
        "missing_from_inventory": missing,
        "_novel": novel,
    }


def derive_corpus(inputs: dict) -> dict:
    """The frozen selection rule applied to committed evidence: the corpus and the ranked targets.

    Greedy maximum-marginal-novelty over the covered surface, capped at `CORPUS_BOUND` and
    tie-broken deterministically. Reads no candidate row.
    """
    inv = inputs["inventory"]
    covered = covered_surface(inputs)
    covered_symbols = set(covered["symbols"])
    candidates = [_candidate_target(s, inv, covered_symbols) for s in SURFACES]

    selected: list[dict] = []
    not_selected: list[dict] = []
    contributed: set[str] = set()
    remaining = list(candidates)
    while remaining and len(selected) < CORPUS_BOUND:
        best = None
        best_key = None
        best_marg: list[str] = []
        for c in remaining:
            marg = [e for e in c["_novel"] if e not in contributed]
            key = (-len(marg), -c["legacy_entities"], c["surface_id"])
            if best_key is None or key < best_key:
                best_key, best, best_marg = key, c, marg
        if best is None or not best_marg:
            break
        contributed.update(best_marg)
        member = {k: v for k, v in best.items() if not k.startswith("_")}
        member["selection_rank"] = len(selected) + 1
        member["marginal_new_entities"] = list(best_marg)
        member["marginal_novelty"] = len(best_marg)
        member["reason"] = (
            f"selected by maximum marginal novelty: at selection it added {len(best_marg)} public "
            f"entit(y/ies) not in the covered surface and not already contributed "
            f"({len(best['_novel'])} novel vs the covered surface, {best['legacy_entities']} "
            f"rare/legacy)")
        selected.append(member)
        remaining = [c for c in remaining if c["surface_id"] != best["surface_id"]]

    for c in remaining:
        marg = [e for e in c["_novel"] if e not in contributed]
        entry = {k: v for k, v in c.items() if not k.startswith("_")}
        entry["marginal_novelty"] = len(marg)
        entry["reason"] = (
            "not admitted: the corpus bound was reached by higher-marginal targets"
            if len(selected) >= CORPUS_BOUND else
            "not admitted: it contributes no public entity not already covered or contributed")
        not_selected.append(entry)

    return {
        "covered_surface": covered,
        "candidate_targets": sorted(
            ({k: v for k, v in c.items() if not k.startswith("_")} for c in candidates),
            key=lambda c: c["surface_id"]),
        "corpus": selected,
        "not_selected": not_selected,
    }


# ===================================================================================================
# measurement: compile and run each corpus member against both subjects
# ===================================================================================================

def _src_path(relpath: str) -> Path:
    return REPO_ROOT / relpath


def _compile(src: Path, prefix: Path, out: Path, kind: str) -> dict:
    """Compile one probe against one subject prefix; never raises on a non-zero exit."""
    base = [CC, "-D_GNU_SOURCE", "-O2", "-Wno-deprecated-declarations",
            f"-I{prefix / 'include'}"]
    if kind == "static":
        argv = base + [str(src), str(prefix / "lib" / "libcrypto.a"), "-ldl", "-lpthread",
                       "-o", str(out)]
    elif kind == "dlopen":
        argv = base + [str(src), "-ldl", "-o", str(out)]
    else:
        argv = base + [str(src), f"-L{prefix / 'lib'}", "-lssl", "-lcrypto", "-ldl", "-lpthread",
                       f"-Wl,-rpath,{prefix / 'lib'}", "-o", str(out)]
    return census._run(argv, timeout=BUILD_TIMEOUT)


def _load_proof(binary: Path, prefix: Path, authority_prefix: Path, out_text: str, kind: str,
                env: dict, archive: Path | None) -> dict:
    """The section-61 enabled-path proof for one probe binary, by its kind."""
    if kind in ("shared-c",):
        return rt.load_proof(binary, prefix, authority_prefix, [], env)
    if kind == "dlopen":
        m = re.search(r"^dlopen_lib=(.+)$", out_text, re.MULTILINE)
        path = m.group(1).strip() if m else ""
        under = bool(path) and census._under(path, prefix)
        under_auth = bool(path) and census._under(path, authority_prefix)
        return {
            "kind": "dlopen", "proven": under, "all_under_prefix": under,
            "resolved_under_authority": under_auth,
            "sonames": {"libcrypto.so.3": {
                "resolved": f"prefix:libcrypto.so.3" if under else (path or "unresolved"),
                "under_prefix": under, "under_authority": under_auth}},
            "dynamic_load_trace": [], "ldd_exit": None, "trace_exit": None,
        }
    # static
    needed = [s for s in census.dt_needed(binary) if census._is_openssl_soname(s)]
    archive_under = bool(archive) and archive.is_file() and census._under(str(archive), prefix)
    under_auth = bool(archive) and archive.is_file() and census._under(str(archive),
                                                                       authority_prefix)
    proven = (not needed) and archive_under
    return {
        "kind": "static", "proven": proven, "all_under_prefix": archive_under,
        "resolved_under_authority": under_auth and not archive_under,
        "sonames": {}, "dynamic_load_trace": [], "ldd_exit": None, "trace_exit": None,
        "static_archive": rel(archive) if archive else None,
        "static_archive_sha256": sha256_file(archive) if archive and archive.is_file() else None,
        "openssl_dt_needed": needed,
    }


def _failure_from_compile(step: dict) -> tuple[str, str]:
    blob = (step.get("stderr") or "") + "\n" + (step.get("stdout") or "")
    if "undefined reference" in blob or "cannot find -l" in blob or "cannot find" in blob:
        return "link-failure", "unlinked"
    if "error:" in blob or "No such file" in blob:
        return "configure-failure", "unbuildable"
    return "harness-failure", "unknown"


def _row(surface: dict, subject: str, *, level: str, outcome: str, residual: str,
         failure_class: str | None, reason: str | None, evidence: list[str], compile_step: dict,
         load_proof: dict | None, transcript: str, prefix: Path, extra: dict | None = None) -> dict:
    """One hostility run row: a schema-valid `run` record plus the hostility extension."""
    proof = load_proof or {}
    suffix = ("-" + str(extra.get("run_id_suffix"))) if extra and extra.get("run_id_suffix") else \
        ("-" + str(extra.get("direction")) if extra and extra.get("direction") else "")
    row = {
        "run_id": f"run:hostility:{surface['surface_id'].split(':', 1)[1]}:{subject}{suffix}",
        "specimen_id": None,
        "variant_id": None,
        "subject": subject,
        "level": level,
        "outcome": outcome,
        "residual_class": residual,
        "evidence": list(evidence),
        "probe_id": surface["surface_id"],
        "role": "hostility",
        "family_id": None,
        "variant": surface["variant"],
        "probe_kind": surface["probe_kind"],
        "probe_sources": list(surface["sources"]),
        "probe_sha256": content_hash([sha256_file(_src_path(s)) for s in surface["sources"]
                                      if _src_path(s).is_file()]),
        "failure_class": failure_class,
        "reason": reason,
        "linkage_proven": bool(proof.get("proven")),
        "resolved_under_authority": bool(proof.get("resolved_under_authority")),
        "load_proof": proof,
        "local_only": True,
        "candidate_specific_patch_count": 0,
        "container_image": None,
        "resource_limits": {},
        "compile": {
            "ok": bool(compile_step.get("ok")),
            "exit_code": compile_step.get("exit_code"),
            "argv": list(compile_step.get("argv") or []),
            "elapsed_seconds": compile_step.get("elapsed_seconds"),
        },
        "transcript_sha256": sha256_bytes(transcript.encode("utf-8")) if transcript else "",
        "transcript_excerpt": transcript.splitlines()[-40:],
        "normalisation": {
            "tag": NORMALISATION_TAG,
            "normalises": list(NORMALISATION_ALLOWED),
            "never": list(NORMALISATION_NEVER),
        },
        "divergence": None,
        "divergence_fields": [],
    }
    if extra:
        row.update(extra)
    return row


def _printed_lib(out_text: str) -> str:
    m = re.search(r"^openssl_lib=(.+)$", out_text, re.MULTILINE)
    if m:
        return m.group(1).strip()
    m = re.search(r"^dlopen_lib=(.+)$", out_text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def _measure_c_surface(member: dict, subject: str, prefix: Path, auth_prefix: Path,
                       limits: dict, pki: dict | None) -> list[dict]:
    sid = member["surface_id"]
    name = sid.split(":", 1)[1]
    work = SCRATCH / "work" / name / subject
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    csrc = [_src_path(s) for s in member["sources"] if s.endswith(".c")]
    src = csrc[0]
    out = work / f"{name}-{subject}"
    comp = _compile(src, prefix, out, member["probe_kind"])
    evidence = [f"surface:{sid}", f"probe:{rel(src)}", "local_only:loopback"]

    if not comp["ok"] or not out.is_file():
        fclass, residual = _failure_from_compile(comp)
        return [_row(member, subject, level=L3, outcome="failed", residual=residual,
                     failure_class=(fclass if subject != "authority" or fclass == "link-failure"
                                    else "authority-build-failure"),
                     reason=f"compiling the probe failed: {census._error_line(comp)}",
                     evidence=evidence, compile_step=comp, load_proof=None,
                     transcript=rt._transcript(("compile", comp)), prefix=prefix,
                     extra={"resource_limits": _confine(limits), "container_image":
                            limits.get("image")})]

    env = dict(os.environ, LD_LIBRARY_PATH=str(prefix / "lib"))
    archive = (prefix / "lib" / "libcrypto.a") if member["probe_kind"] == "static" else None
    if member["probe_kind"] == "dlopen":
        argv = [str(out), str(prefix / "lib" / "libcrypto.so.3")]
    else:
        argv = [str(out)]
    run = rt._run_captured(argv, cwd=work, env=env, timeout=LAUNCH_TIMEOUT)
    proof = _load_proof(out, prefix, auth_prefix, run["stdout"] or "", member["probe_kind"], env,
                        archive)
    printed = _printed_lib(run["stdout"] or "")
    printed_ok = (member["probe_kind"] == "static") or (
        bool(printed) and census._under(printed, prefix))
    runtime_ok = bool(run["ok"]) and "result=ok" in (run["stdout"] or "")
    raw = rt._transcript(("compile", comp), ("run", run))
    normalised = rt.normalise_transcript(raw, prefix, auth_prefix, work, None)

    payload = {}
    for line in (run.get("stdout") or "").splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            payload[key] = val
    if not proof.get("proven"):
        level, outcome, residual, fclass = L4, "failed", "runtime-failure", "load-failure"
        reason = "the subject's OpenSSL library was not the one the probe loaded"
    elif not printed_ok:
        level, outcome, residual, fclass = L4, "failed", "runtime-failure", "load-failure"
        reason = "the probe's runtime dladdr did not resolve under the subject prefix"
    elif not runtime_ok:
        level, outcome, residual = L6, "failed", "functional-divergence"
        fclass = "functional-failure" if run["ok"] else "runtime-failure"
        reason = f"the probe reported {payload.get('result', 'a failure')}: " \
                 f"{payload.get('reason', 'the OpenSSL path did not complete')}"
    else:
        level, outcome, residual, fclass, reason = L7, "reached", "none", None, None

    return [_row(member, subject, level=level, outcome=outcome, residual=residual,
                 failure_class=fclass, reason=reason, evidence=evidence + [f"subject_lib:{printed}"],
                 compile_step=comp, load_proof=proof, transcript=normalised, prefix=prefix,
                 extra={"printed_lib_under_prefix": printed_ok,
                        "printed_lib": printed,
                        "resource_limits": _confine(limits),
                        "container_image": limits.get("image"),
                        "workload_result": {"name": f"{name}", "runtime_ok": runtime_ok}})]


def _measure_network_surface(member: dict, auth_prefix: Path, limits: dict,
                             pki: dict | None) -> list[dict]:
    """The section-63 cross-implementation network matrix: candidate<->authority, both directions."""
    sid = member["surface_id"]
    name = sid.split(":", 1)[1]
    rows: list[dict] = []
    binaries: dict[tuple[str, str], tuple[dict, Path]] = {}
    for subject, prefix in (("authority", auth_prefix), ("candidate", CANDIDATE_PREFIX)):
        for role, srcname in (("server", "tls_server.c"), ("client", "tls_client.c")):
            work = SCRATCH / "work" / f"{name}-{role}" / subject
            work.mkdir(parents=True, exist_ok=True)
            out = work / f"{name}-{role}-{subject}"
            comp = _compile(_src_path(f"forensics/downstream/hostility/{srcname}"), prefix, out,
                            "shared-c")
            binaries[(subject, role)] = (comp, out)
    if pki is None:
        # no PKI: both subjects are honestly not_attempted for the network member.
        return [_row(member, s, level=L0, outcome="not_attempted", residual="unavailable",
                     failure_class="harness-failure",
                     reason="no local PKI fixture was generated for the network member",
                     evidence=[f"surface:{sid}", "local_only:loopback"], compile_step={},
                     load_proof=None, transcript="", prefix=auth_prefix,
                     extra={"direction": f"{s}->{s}", "resource_limits": _confine(limits)})
                for s in SUBJECTS]

    directions = [("authority", "authority"), ("candidate", "candidate"),
                  ("candidate", "authority"), ("authority", "candidate")]
    variants = [("tls1.3", 0, 0), ("tls1.2", TLS1_2_VERSION, TLS1_2_VERSION)]
    for client_subj, server_subj in directions:
        for vname, vmin, vmax in variants:
            # the tls1.2 variant is measured only on the cross-implementation pairs (section 62/63)
            if vname == "tls1.2" and client_subj == server_subj:
                continue
            direction = f"{client_subj}->{server_subj}"
            rows.append(_run_direction(member, client_subj, server_subj, direction, vname, vmin,
                                       vmax, binaries, auth_prefix, limits, pki))
    return rows


def _wait_file_line(path: Path, needle: str, timeout: float = 25.0) -> bool:
    """Wait until `path` contains `needle`. A listener prints a line rather than being probed by a
    throwaway TCP connection, which a single-accept TLS server would otherwise consume."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if needle in path.read_text(encoding="utf-8", errors="ignore"):
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def _run_direction(member: dict, client_subj: str, server_subj: str, direction: str, vname: str,
                   vmin: int, vmax: int, binaries: dict, auth_prefix: Path, limits: dict,
                   pki: dict) -> dict:
    sid = member["surface_id"]
    name = sid.split(":", 1)[1]
    ccomp, cbin = binaries[(client_subj, "client")]
    scomp, sbin = binaries[(server_subj, "server")]
    client_prefix = auth_prefix if client_subj == "authority" else CANDIDATE_PREFIX
    server_prefix = auth_prefix if server_subj == "authority" else CANDIDATE_PREFIX
    extra = {"direction": direction, "client_subject": client_subj,
             "counterpart_subject": server_subj, "tls_variant": vname,
             "resource_limits": _confine(limits), "container_image": limits.get("image")}
    evidence = [f"surface:{sid}", f"direction:{direction}", f"tls_variant:{vname}",
                "local_only:loopback", "cross_implementation:true"]

    if not (ccomp["ok"] and cbin.is_file() and scomp["ok"] and sbin.is_file()):
        bad = ccomp if not ccomp["ok"] else scomp
        fclass, residual = _failure_from_compile(bad)
        return _row(member, client_subj, level=L3, outcome="failed", residual=residual,
                    failure_class=(fclass if client_subj != "authority" else
                                   "authority-build-failure"),
                    reason=f"compiling the probe failed: {census._error_line(bad)}",
                    evidence=evidence, compile_step=bad, load_proof=None,
                    transcript=rt._transcript(("compile", bad)), prefix=client_prefix, extra=extra)

    port = rt._free_port()
    workdir = SCRATCH / "run" / name / f"{direction}-{vname}"
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    srv_env = dict(os.environ, LD_LIBRARY_PATH=str(server_prefix / "lib"))
    cli_env = dict(os.environ, LD_LIBRARY_PATH=str(client_prefix / "lib"))
    srv, of, ef = rt._spawn([str(sbin), str(port), str(pki["srv_crt"]), str(pki["srv_key"]),
                             str(vmin), str(vmax)], workdir, srv_env, workdir / "srv.out",
                            workdir / "srv.err")
    try:
        if not _wait_file_line(workdir / "srv.out", "listening=1"):
            return _row(member, client_subj, level=L5, outcome="failed", residual="runtime-failure",
                        failure_class="load-failure",
                        reason=f"the {server_subj} TLS server did not listen",
                        evidence=evidence, compile_step=scomp, load_proof=None, transcript="",
                        prefix=client_prefix, extra=extra)
        cli = rt._run_captured([str(cbin), str(port), str(pki["ca_crt"]), str(vmin), str(vmax)],
                               cwd=workdir, env=cli_env, timeout=NET_TIMEOUT)
    finally:
        rt._stop(srv)
        of.close()
        ef.close()
    srv_out = {"exit_code": 0, "stdout": rt._read(workdir / "srv.out"),
               "stderr": rt._read(workdir / "srv.err")}
    proof = rt.load_proof(cbin, client_prefix, auth_prefix, [], cli_env)
    printed = _printed_lib(cli["stdout"] or "")
    printed_ok = bool(printed) and census._under(printed, client_prefix)
    runtime_ok = bool(cli["ok"]) and "result=ok" in (cli["stdout"] or "")
    raw = rt._transcript(("server", srv_out), ("client", cli))
    normalised = rt.normalise_transcript(raw, client_prefix, auth_prefix, workdir, port)
    extra = dict(extra, printed_lib=printed, printed_lib_under_prefix=printed_ok,
                 run_id_suffix=f"{direction}-{vname}",
                 client_tls_version=re.search(r"^tls_version=(.+)$", cli["stdout"] or "",
                                              re.MULTILINE).group(1).strip()
                 if re.search(r"^tls_version=(.+)$", cli["stdout"] or "", re.MULTILINE) else None,
                 )
    if not proof.get("proven") or not printed_ok:
        level, outcome, residual, fclass = L4, "failed", "runtime-failure", "load-failure"
        reason = "the client's OpenSSL library was not the subject's"
    elif not runtime_ok:
        level, outcome, residual, fclass = L6, "failed", "functional-divergence", \
            ("functional-failure" if cli["ok"] else "runtime-failure")
        reason = f"the {direction} handshake/workload did not complete"
    else:
        level, outcome, residual, fclass, reason = L7, "reached", "none", None, None
    return _row(member, client_subj, level=level, outcome=outcome, residual=residual,
                failure_class=fclass, reason=reason, evidence=evidence, compile_step=ccomp,
                load_proof=proof, transcript=normalised, prefix=client_prefix, extra=extra)


def _measure_surface(member: dict, subject: str, prefix: Path, auth_prefix: Path, limits: dict,
                     pki: dict | None) -> list[dict]:
    if member["network"]:
        return []  # handled once per surface, not per subject
    return _measure_c_surface(member, subject, prefix, auth_prefix, limits, pki)


def _confine(limits: dict) -> dict:
    return {k: limits.get(k) for k in ("memory_max", "memory_swap_max", "pids_max", "cpu_max",
                                       "image", "platform")}


def _annotate_divergence(rows: list[dict], corpus: list[dict], auth_prefix: Path) -> None:
    """Record, per non-network member, whether the two subjects' transcripts differ."""
    def neutral(text: str) -> str:
        for p in (str(auth_prefix), str(CANDIDATE_PREFIX), str(SCRATCH), str(REPO_ROOT)):
            if p and p != "/":
                text = text.replace(p, "{prefix}")
        return text

    banners = ("surface=", "openssl_lib=", "openssl_runtime_version=", "openssl_version_text=",
               "== ", "exit=")
    for member in corpus:
        if member["network"]:
            continue
        sid = member["surface_id"]
        by_subject = {r["subject"]: r for r in rows if r["probe_id"] == sid}
        a = by_subject.get("authority")
        c = by_subject.get("candidate")
        if a is None or c is None:
            continue
        pa = [ln for ln in neutral("\n".join(a.get("transcript_excerpt") or [])).splitlines()
              if ln and not ln.startswith(banners)]
        pc = [ln for ln in neutral("\n".join(c.get("transcript_excerpt") or [])).splitlines()
              if ln and not ln.startswith(banners)]
        if pa != pc:
            diff = [f"{x} != {y}" for x, y in zip(pa, pc) if x != y][:6]
            a["divergence"] = True
            c["divergence"] = True
            a["divergence_fields"] = diff
            c["divergence_fields"] = diff


def derive_body(inputs: dict, authority_id: str) -> dict:
    """Select the corpus and measure it against both subjects."""
    auth = resolve_authority(authority_id)
    auth_prefix = auth.prefix
    if not (CANDIDATE_PREFIX / "lib" / "libssl.so.3").is_file():
        raise SystemExit(f"[downstream-hostility] the candidate install prefix "
                         f"{rel(CANDIDATE_PREFIX)} holds no lib/libssl.so.3")
    limits = census.resource_limits()
    corpus = derive_corpus(inputs)["corpus"]

    rows: list[dict] = []
    SCRATCH.mkdir(parents=True, exist_ok=True)
    try:
        pki = None
        if any(m["network"] for m in corpus):
            pki = rt._gen_pki(auth_prefix, SCRATCH / "pki")
        for member in corpus:
            if member["network"]:
                new = _measure_network_surface(member, auth_prefix, limits, pki)
            else:
                new = []
                for subject, prefix in (("authority", auth_prefix),
                                        ("candidate", CANDIDATE_PREFIX)):
                    new += _measure_surface(member, subject, prefix, auth_prefix, limits, pki)
            for r in new:
                print(f"  [hostility] {member['surface_id'].split(':', 1)[1]:<14} "
                      f"{r['subject']:<9} {r.get('direction') or '':<22} {r['level']:<16} "
                      f"{str(r.get('reason') or '')[:50]}", flush=True)
            rows += new
    finally:
        census._cleanup(SCRATCH)

    _annotate_divergence(rows, corpus, auth_prefix)
    rows.sort(key=lambda r: (r["probe_id"], r["subject"], r.get("direction") or ""))
    counts = _counts(corpus, rows, inputs)
    body = {
        "rule": RULE,
        "authority": authority_id,
        "authority_prefix": rel(auth_prefix),
        "candidate_identity": bl.candidate_identity(),
        "covered_surface": covered_surface(inputs),
        "corpus": corpus,
        "not_selected": derive_corpus(inputs)["not_selected"],
        "candidate_targets": derive_corpus(inputs)["candidate_targets"],
        "runs": rows,
        "counts": counts,
        "resource_limits": limits,
        "non_claims": NON_CLAIMS,
    }
    return body


def _counts(corpus: list[dict], rows: list[dict], inputs: dict) -> dict:
    """Every count, computed from the corpus, the rows and the frozen P1000 -- never typed."""
    def levels(subject: str, rung: str) -> int:
        return sum(1 for r in rows if r["subject"] == subject
                   and RANK.get(str(r.get("level")), -1) >= RANK[rung])

    def outcomes(subject: str, outcome: str) -> int:
        return sum(1 for r in rows if r["subject"] == subject and r.get("outcome") == outcome)

    failure_histogram: dict[str, int] = {}
    for r in rows:
        if r["subject"] == "candidate" and r.get("outcome") in ("failed", "not_attempted",
                                                                "unavailable"):
            fc = r.get("failure_class")
            if fc:
                failure_histogram[fc] = failure_histogram.get(fc, 0) + 1

    p1000 = list(inputs["family_freeze"].get("p1000") or [])
    p1000_ids = {str(e.get("family_id")) for e in p1000}
    member_ids = {m["surface_id"] for m in corpus}
    overlap = [r for r in rows if str(r.get("family_id")) in p1000_ids]

    distinct_new = {e for m in corpus for e in m.get("marginal_new_entities") or []}
    return {
        "corpus_size": len(corpus),
        "corpus_network": sum(1 for m in corpus if m["network"]),
        "corpus_c": sum(1 for m in corpus if not m["network"]),
        "corpus_bound": CORPUS_BOUND,
        "new_public_entities": sum(len(m.get("marginal_new_entities") or []) for m in corpus),
        "distinct_new_public_entities": len(distinct_new),
        "new_entity_names": sorted(distinct_new),
        "covered_surface_symbols": len(covered_surface(inputs)["symbols"]),
        "rows": len(rows),
        "by_subject": {
            subject: {
                "loaded": levels(subject, L5),
                "runtime": levels(subject, L6),
                "functional": levels(subject, L7),
                "failed": outcomes(subject, "failed"),
                "not_attempted": outcomes(subject, "not_attempted") + outcomes(subject,
                                                                               "unavailable"),
            }
            for subject in SUBJECTS
        },
        "candidate_failures": failure_histogram,
        "divergences": sum(1 for r in rows if r.get("divergence")),
        "linkage_proven": sum(1 for r in rows if r.get("linkage_proven")),
        "p1000": len(p1000),
        "p1000_hostility_overlap": len(overlap),
        "separated_by_design": True,
        "candidate_specific_patch_count": sum(
            int(r.get("candidate_specific_patch_count") or 0) for r in rows),
    }


# ===================================================================================================
# the artefact
# ===================================================================================================

def write_outputs(body: dict, authority_id: str) -> None:
    inputs = [
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="usage-fingerprints", path=USAGE_FINGERPRINTS),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="runtime-functional-atlas", path=RUNTIME_FUNCTIONAL_ATLAS),
        InputRef(name="high-value-tier", path=HIGH_VALUE_TIER),
        InputRef(name="implemented-surface", path=IMPLEMENTED_SURFACE),
        InputRef(name="phase22-functions", path=PHASE22_AUTHORITY / "functions.json"),
        InputRef(name="phase22-symbols-libcrypto", path=PHASE22_AUTHORITY / "symbols-libcrypto.json"),
        InputRef(name="phase22-symbols-libssl", path=PHASE22_AUTHORITY / "symbols-libssl.json"),
        InputRef(name="phase22-macros", path=PHASE22_AUTHORITY / "macros.json"),
        InputRef(name="phase22-typedefs", path=PHASE22_AUTHORITY / "typedefs.json"),
        InputRef(name="phase22-structs", path=PHASE22_AUTHORITY / "structs.json"),
        InputRef(name="phase22-enums", path=PHASE22_AUTHORITY / "enums.json"),
        InputRef(name="phase22-cli-commands", path=PHASE22_AUTHORITY / "cli-commands.json"),
        InputRef(name="downstream-hostility",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_hostility.py"),
        InputRef(name="downstream-runtime",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_runtime.py"),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-census",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_census.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard", path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]
    for s in sorted(HOSTILITY_DIR.glob("*")):
        if s.is_file():
            inputs.append(InputRef(name=f"probe/{s.name}", path=s))
    doc = envelope(kind="downstream-hostility-corpus", authority=authority_id,
                   inputs=inputs, body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


# ===================================================================================================
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# ===================================================================================================

def _p1000_context(freeze_body: dict) -> tuple[list[dict], set[str]]:
    p1000 = list(freeze_body.get("p1000") or [])
    return p1000, {str(e.get("family_id")) for e in p1000}


def hostility_findings(inputs: dict, body: dict) -> list[str]:
    """Every way the recorded corpus fails its own subject.

    Pure over the committed covered-surface inputs, the Phase-22 public-entity inventory and the
    frozen P1000, so the court re-runs it without rebuilding and the sensitivity control can mutate
    an in-memory copy. Every check is a re-derivation: the corpus reproduces from the frozen novelty
    rule; no member is a P1000 counted family and the P1000 count is unchanged; every member has
    both-subject runs; each member's linkage is subject-correct with a real load proof on an `L5+`
    row; the transcript normalisation is applied identically to both subjects; the counts are derived
    rather than typed; and `candidate_specific_patch_count` is 0.
    """
    findings: list[str] = []
    inv = inputs["inventory"]
    covered = covered_surface(inputs)
    covered_symbols = set(covered["symbols"])
    p1000, p1000_ids = _p1000_context(inputs["family_freeze"])

    # 1. The corpus reproduces from the frozen novelty rule.
    derived = derive_corpus(inputs)
    derived_corpus = derived["corpus"]
    recorded = body.get("corpus") or []
    derived_key = [(m["surface_id"], m["selection_rank"], tuple(m["marginal_new_entities"]))
                   for m in derived_corpus]
    recorded_key = [(str(m.get("surface_id")), m.get("selection_rank"),
                     tuple(m.get("marginal_new_entities") or [])) for m in recorded]
    if recorded_key != derived_key:
        findings.append("the recorded corpus does not reproduce from the frozen novelty rule: the "
                        f"derived members are {[m['surface_id'] for m in derived_corpus]} but the "
                        f"artefact records {[m.get('surface_id') for m in recorded]}")
    if len(recorded) > CORPUS_BOUND:
        findings.append(f"the corpus carries {len(recorded)} member(s), above the bound "
                        f"{CORPUS_BOUND}")
    if body.get("covered_surface") != covered:
        findings.append("the recorded covered_surface is not the committed P1000 union")

    corpus_ids = {str(m.get("surface_id")) for m in recorded}

    # 2. The corpus is separate: no member is a P1000 counted family, and the P1000 is unchanged.
    if len(p1000) != 1000:
        findings.append(f"the frozen P1000 carries {len(p1000)} family(ies), not 1000")
    for m in recorded:
        if m.get("family_id") is not None:
            findings.append(f"{m.get('surface_id')}: a hostility member carries family_id "
                            f"{m.get('family_id')!r}, so it is not separate from the population")
        if str(m.get("family_id")) in p1000_ids:
            findings.append(f"{m.get('surface_id')}: a hostility member is a P1000 counted family")
        if m.get("role") != "hostility":
            findings.append(f"{m.get('surface_id')}: a corpus member does not carry role `hostility`")
        if not str(m.get("surface_id", "")).startswith("hostility:"):
            findings.append(f"{m.get('surface_id')}: a corpus member does not carry a hostility id")
        # 2b. Each member declares at least one new entity, and every declared entity is public.
        missing = [e for e in m.get("entities") or [] if e not in inv["names"]]
        if missing:
            findings.append(f"{m.get('surface_id')}: declares entities outside the Phase-22 "
                            f"inventory ({sorted(missing)[:3]})")
        marg = list(m.get("marginal_new_entities") or [])
        if not marg:
            findings.append(f"{m.get('surface_id')}: a corpus member contributes no new public "
                            f"entity")
        for e in marg:
            if e in covered_symbols:
                findings.append(f"{m.get('surface_id')}: its new entity {e!r} is already in the "
                                f"covered surface")
        # 2c. Every declared entity/source maps to a real committed probe.
        text = ""
        for s in m.get("sources") or []:
            p = REPO_ROOT / str(s)
            if not p.is_file():
                findings.append(f"{m.get('surface_id')}: probe source {s!r} is absent")
            else:
                text += p.read_text(encoding="utf-8", errors="ignore")
        for e in (m.get("entities") or []) + (m.get("foreign_symbols") or []):
            if e not in text:
                findings.append(f"{m.get('surface_id')}: declared entity {e!r} does not appear in "
                                f"the committed probe source")

    runs = body.get("runs") or []
    if not runs:
        return findings + ["the corpus records no run"]

    by_member: dict[str, dict[str, list]] = {}
    seen_ids: set[str] = set()
    for row in runs:
        sid = str(row.get("probe_id"))
        subject = str(row.get("subject"))
        findings += [f"{sid}/{subject}: {p}" for p in downstream_schemas.validate_run(row)]
        rid = str(row.get("run_id"))
        if rid in seen_ids:
            findings.append(f"two hostility rows share run_id {rid!r}")
        seen_ids.add(rid)
        if sid not in corpus_ids:
            findings.append(f"{sid}: a run row is not a corpus member -- a surface cannot enter by a "
                            f"result rather than the novelty rule")
        if str(row.get("family_id")) in p1000_ids:
            findings.append(f"{sid}/{subject}: a hostility run is a P1000 counted family")
        if int(row.get("candidate_specific_patch_count") or 0) != 0:
            findings.append(f"{sid}/{subject}: candidate_specific_patch_count is "
                            f"{row.get('candidate_specific_patch_count')!r}, not 0")
        if not row.get("local_only"):
            findings.append(f"{sid}/{subject}: a hostility row is not marked local-only")
        by_member.setdefault(sid, {}).setdefault(subject, []).append(row)

        level_rank = RANK.get(str(row.get("level")), -1)
        if level_rank >= RANK[L5]:
            if not row.get("linkage_proven"):
                findings.append(f"{sid}/{subject}: claims {row.get('level')} but its load/linkage "
                                f"is not proven")
            proof = row.get("load_proof") or {}
            if proof.get("proven") is not True:
                findings.append(f"{sid}/{subject}: a {row.get('level')} row carries no proven load "
                                f"proof")
            if row.get("printed_lib_under_prefix") is False:
                findings.append(f"{sid}/{subject}: the probe's runtime library is not under the "
                                f"subject prefix")
            if subject == "candidate" and (row.get("resolved_under_authority")
                                           or proof.get("resolved_under_authority")):
                findings.append(f"{sid}/{subject}: a candidate {row.get('level')} row resolves the "
                                f"authority prefix")
        if level_rank >= RANK[L6]:
            ts = str(row.get("transcript_sha256") or "")
            if len(ts) != 64:
                findings.append(f"{sid}/{subject}: a {row.get('level')} row has no non-empty "
                                f"transcript hash")
            norm = row.get("normalisation") or {}
            if norm.get("tag") != NORMALISATION_TAG:
                findings.append(f"{sid}/{subject}: a {row.get('level')} row carries a normalisation "
                                f"tag that is not the committed policy")
            if list(norm.get("normalises") or []) != list(NORMALISATION_ALLOWED):
                findings.append(f"{sid}/{subject}: the normalisation allow-list is not the committed "
                                f"policy")
            bad = [c for c in (norm.get("normalises") or []) if c not in NORMALISATION_ALLOWED]
            if bad:
                findings.append(f"{sid}/{subject}: the normalisation erases evidence "
                                f"({sorted(bad)})")
        outcome = row.get("outcome")
        if outcome in ("failed", "not_attempted", "unavailable"):
            if not row.get("reason"):
                findings.append(f"{sid}/{subject}: a {outcome} row carries no reason")
            if not row.get("failure_class"):
                findings.append(f"{sid}/{subject}: a {outcome} row carries no failure class")
            elif row["failure_class"] not in downstream_schemas.FAILURE_CLASSES:
                findings.append(f"{sid}/{subject}: failure class {row['failure_class']!r} is outside "
                                f"the taxonomy")

    # 3. Every member has both-subject runs.
    for m in recorded:
        sid = str(m.get("surface_id"))
        subjects = set(by_member.get(sid, {}).keys())
        for subject in SUBJECTS:
            if subject not in subjects:
                findings.append(f"{sid}: no {subject} run")

    # 4. The counts are derived, not typed.
    derived_counts = _counts(derived_corpus, runs, inputs)
    recorded_counts = body.get("counts") or {}
    for key in ("corpus_size", "corpus_network", "corpus_c", "corpus_bound",
                "new_public_entities", "distinct_new_public_entities", "rows", "divergences",
                "linkage_proven", "p1000", "p1000_hostility_overlap", "separated_by_design",
                "candidate_specific_patch_count", "covered_surface_symbols"):
        if recorded_counts.get(key) != derived_counts[key]:
            findings.append(f"counts.{key} {recorded_counts.get(key)!r} disagrees with the derived "
                            f"{derived_counts[key]!r}")
    if (recorded_counts.get("new_entity_names") or []) != derived_counts["new_entity_names"]:
        findings.append("counts.new_entity_names disagrees with the derived novelty set")
    if (recorded_counts.get("candidate_failures") or {}) != derived_counts["candidate_failures"]:
        findings.append("counts.candidate_failures disagrees with the derived histogram")
    for subject in SUBJECTS:
        for rung in ("loaded", "runtime", "functional", "failed", "not_attempted"):
            got = (recorded_counts.get("by_subject") or {}).get(subject, {}).get(rung)
            want = derived_counts["by_subject"][subject][rung]
            if got != want:
                findings.append(f"counts.by_subject.{subject}.{rung} {got!r} disagrees with the "
                                f"derived {want!r}")

    # 5. The recorded rule and non-claims are the frozen ones.
    if body.get("rule") != RULE:
        findings.append("the recorded rule is not the frozen hostility rule")
    if body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the "
                        "separation non-claim")
    return findings


def _mutations(body: dict, inputs: dict) -> list[tuple[str, str, dict]]:
    """`(name, needle, mutated_body)` for each seeded mutation."""
    out: list[tuple[str, str, dict]] = []
    corpus = body.get("corpus") or []
    runs = body.get("runs") or []

    # a hostility member injected into the P1000 counts: a member given a frozen family_id.
    p1000, p1000_ids = _p1000_context(inputs["family_freeze"])
    m1 = copy.deepcopy(body)
    if m1["corpus"] and p1000_ids:
        m1["corpus"][0]["family_id"] = sorted(p1000_ids)[0]
    out.append(("hostility_member_injected_into_p1000", "is a P1000 counted family", m1))

    # a corpus member with no new public entity.
    m2 = copy.deepcopy(body)
    if m2["corpus"]:
        m2["corpus"][0]["marginal_new_entities"] = []
        m2["corpus"][0]["marginal_novelty"] = 0
    out.append(("corpus_member_without_new_entity", "contributes no new public entity", m2))

    # a candidate row resolving the authority/system instead of the candidate.
    m3 = copy.deepcopy(body)
    cand = next((r for r in m3["runs"] if r.get("subject") == "candidate"
                 and RANK.get(str(r.get("level")), -1) >= RANK[L5]), None)
    if cand is not None:
        cand["load_proof"] = dict(cand.get("load_proof") or {}, resolved_under_authority=True,
                                  proven=True)
        cand["resolved_under_authority"] = True
    out.append(("candidate_row_resolves_authority", "resolves the authority prefix", m3))

    # a missing authority run for a member.
    m4 = copy.deepcopy(body)
    victim = next((r for r in m4["runs"] if r.get("subject") == "authority"
                   and not r.get("direction")), None)
    if victim is not None:
        pid = victim["probe_id"]
        m4["runs"] = [r for r in m4["runs"]
                      if not (r["probe_id"] == pid and r["subject"] == "authority"
                              and not r.get("direction"))]
    out.append(("missing_authority_run", "no authority run", m4))

    # an unnormalised transcript (an empty tag at L6+).
    m5 = copy.deepcopy(body)
    rt_row = next((r for r in m5["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L6]), None)
    if rt_row is not None:
        rt_row["normalisation"] = {"tag": "", "normalises": [], "never": []}
    out.append(("unnormalised_transcript", "normalisation tag that is not the committed policy", m5))

    # a corpus member beyond the bound (a 13th member appended).
    m6 = copy.deepcopy(body)
    if m6["corpus"]:
        extra = copy.deepcopy(m6["corpus"][0])
        extra["surface_id"] = "hostility:injected-extra"
        extra["selection_rank"] = len(m6["corpus"]) + 1
        m6["corpus"] = list(m6["corpus"]) + [extra]
    out.append(("corpus_member_beyond_bound", "does not reproduce from the frozen novelty rule", m6))
    return out


def hostility_sensitivity_control(inputs: dict, body: dict) -> dict:
    """Prove the court can fail: seed six mutations and require each caught with specificity.

    The honest corpus must yield **zero** findings (specificity), and each seeded mutation -- a
    hostility member injected into the P1000 counts, a corpus member with no new entity, a candidate
    row resolving the authority/system, a missing authority run, an unnormalised transcript, and a
    corpus member beyond the bound -- must be caught with a finding naming it.
    """
    base = hostility_findings(inputs, body)
    control: dict = {"baseline_findings": len(base), "specificity_holds": not base}
    honest = not base
    for name, needle, mutated in _mutations(body, inputs):
        caught = any(needle in f for f in hostility_findings(inputs, mutated))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# ===================================================================================================
# entry point
# ===================================================================================================

def _load_all_inputs() -> dict:
    for path, what, sub in ((USAGE_FINGERPRINTS, "usage fingerprints", "24.3"),
                            (FAMILY_FREEZE, "frozen P1000", "24.4"),
                            (BUILD_LINK_ATLAS, "build/link atlas", "24.6"),
                            (RUNTIME_FUNCTIONAL_ATLAS, "runtime/functional atlas", "24.7"),
                            (HIGH_VALUE_TIER, "high-value tier", "24.9")):
        if not path.is_file():
            raise SystemExit(f"[downstream-hostility] {rel(path)} is absent; run {sub} first")
    if not IMPLEMENTED_SURFACE.is_file():
        raise SystemExit(f"[downstream-hostility] {rel(IMPLEMENTED_SURFACE)} is absent")
    return load_inputs()


def cmd_measure(authority_id: str) -> int:
    inputs = _load_all_inputs()
    if len(inputs["family_freeze"].get("p1000") or []) != 1000:
        print("[downstream-hostility] the frozen P1000 does not carry 1000 family(ies)")
        return 1
    print(f"[downstream-hostility] measuring the separate hostility corpus against both subjects "
          f"(authority {authority_id} + candidate {rel(CANDIDATE_PREFIX)})")
    started = time.monotonic()
    body = derive_body(inputs, authority_id)
    findings = hostility_findings(inputs, body)
    control = hostility_sensitivity_control(inputs, body)
    if findings or not control["honest"]:
        print("[downstream-hostility] the measured corpus fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body, authority_id)
    c = body["counts"]
    print(f"[downstream-hostility] elapsed={time.monotonic() - started:.0f}s "
          f"corpus={c['corpus_size']} (c={c['corpus_c']} network={c['corpus_network']}) "
          f"new_entities={c['distinct_new_public_entities']} divergences={c['divergences']}")
    for subject in SUBJECTS:
        s = c["by_subject"][subject]
        print(f"  {subject:<9} loaded={s['loaded']} runtime={s['runtime']} "
              f"functional={s['functional']} failed={s['failed']} "
              f"not_attempted={s['not_attempted']}")
    print(f"  candidate_failures={c['candidate_failures']} "
          f"p1000={c['p1000']} overlap={c['p1000_hostility_overlap']} "
          f"separated_by_design={c['separated_by_design']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    if not OUT.is_file():
        print(f"[downstream-hostility] {rel(OUT)} is absent")
        return 1
    inputs = _load_all_inputs()
    body = _load_json(OUT)
    findings = hostility_findings(inputs, body)
    control = hostility_sensitivity_control(inputs, body)
    if findings:
        print(f"[downstream-hostility] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = body.get("counts") or {}
    by = c.get("by_subject") or {}
    print(f"[downstream-hostility] corpus={c.get('corpus_size')} "
          f"new_entities={c.get('distinct_new_public_entities')} "
          f"cand_functional={(by.get('candidate') or {}).get('functional')} "
          f"findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_hostility.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_hostility.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. Every declared probe source is committed, and every declared entity appears in it.
    for s in SURFACES:
        for src in s["sources"]:
            if not (HOSTILITY_DIR / src).is_file():
                failures.append(f"the probe source {src} of {s['surface_id']} is absent")

    # 3. The pure functions behave over the committed evidence.
    if not (USAGE_FINGERPRINTS.is_file() and FAMILY_FREEZE.is_file()
            and BUILD_LINK_ATLAS.is_file() and RUNTIME_FUNCTIONAL_ATLAS.is_file()
            and HIGH_VALUE_TIER.is_file() and IMPLEMENTED_SURFACE.is_file()):
        failures.append("a committed hostility input is absent")
    else:
        inputs = _load_all_inputs()
        inv = inputs["inventory"]
        if inv["count"] < 1000:
            failures.append(f"the Phase-22 public-entity inventory is implausibly small "
                            f"({inv['count']})")
        covered = covered_surface(inputs)
        if not covered["symbols"]:
            failures.append("the covered surface carries no imported symbol")
        # every declared entity must be a real public entity, and appear in its probe source.
        for s in SURFACES:
            text = "".join((HOSTILITY_DIR / src).read_text(encoding="utf-8", errors="ignore")
                           for src in s["sources"] if (HOSTILITY_DIR / src).is_file())
            for e in s["entities"]:
                if e not in inv["names"]:
                    failures.append(f"{s['surface_id']}: entity {e!r} is not in the Phase-22 "
                                    f"inventory")
                if e not in text:
                    failures.append(f"{s['surface_id']}: entity {e!r} does not appear in the probe "
                                    f"source")
        derived = derive_corpus(inputs)
        if not derived["corpus"]:
            failures.append("the frozen novelty rule selected no corpus member")
        if len(derived["corpus"]) > CORPUS_BOUND:
            failures.append("the frozen novelty rule selected more members than the bound")
        for m in derived["corpus"]:
            if not m["marginal_new_entities"]:
                failures.append(f"{m['surface_id']}: the frozen novelty rule selected a member with "
                                f"no new entity")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            body = _load_json(OUT)
            findings = hostility_findings(inputs, body)
            if findings:
                failures.append(f"the committed corpus has findings: {findings[:3]}")
            control = hostility_sensitivity_control(inputs, body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")
            # the corpus is separate from the counted population
            if body.get("counts", {}).get("separated_by_design") is not True:
                failures.append("the corpus is not marked separated_by_design")

    if failures:
        print("[downstream-hostility] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-hostility] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), every declared entity is a real Phase-22 public entity that "
          "appears in its committed probe source, the covered surface is non-empty, the frozen "
          "novelty rule selects a bounded corpus, the committed corpus reproduces with zero findings, "
          "and every seeded mutation (a hostility member injected into the P1000 counts, a corpus "
          "member with no new entity, a candidate row resolving the authority, a missing authority "
          "run, an unnormalised transcript and a corpus member beyond the bound) is caught with "
          "specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="compile and run the corpus against both subjects and write it (in-container)")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed corpus without rebuilding (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool compiles and runs, so it is an
    # execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    return cmd_measure(args.authority)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
