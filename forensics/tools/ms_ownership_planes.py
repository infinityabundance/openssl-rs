#!/usr/bin/env python3
"""openssl-rs — the ownership, allocation and callback planes (Phase 25.4).

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). 25.1 enumerates the compiler-derived unsafe
operations, 25.2 records the non-Rust trusted computing base, and 25.3 gives every site an
obligation along the closed dimensions. This subphase is 25.4: it models the **FFI lifetime
machinery** the later reachability and dynamic planes depend on — the allocation/deallocation
associations, the ownership edges across the Rust/C boundary, the callback lifetimes, the unsafe
`Send`/`Sync` impls, the global/static state and the panic/unwind boundaries.

What is derived, and from what
------------------------------
Every record is a deterministic function of three committed inputs and the committed source text:

  * the **25.1 census** supplies the compiler-derived unsafe sites (the `site_id`, its file, its
    enclosing context span and function) — the primary unit is the compiler's operation, never a
    regex;
  * the **25.2 non-Rust TCB** supplies the FFI boundary records (one per exported symbol / imported
    extern), each of which carries `unwind: UNKNOWN` with a note that 25.4 owns the panic boundary;
  * the **committed source** (`src/**/*.rs`) supplies the secondary classifications: which
    allocation API family a context's own text names, which `set0`/`set1`/`get0`/`get1`/`up_ref`
    convention it uses, which registration function installs a callback, which `unsafe impl
    Send`/`Sync` exists, which `static`/`thread_local!` global exists, and which body an exported
    function has.

The source classifications are **secondary labels on compiler-established units** (25.1's sites),
recorded in `rule` so the court reproduces them rather than trusting them, exactly as 25.3's
keyword index is. The operation kind and the site identity come from the compiler; this plane says
nothing the compiler did not establish about what operations exist.

The ownership-edge kinds are the closed vocabulary
---------------------------------------------------
`ALLOCATES`, `RETURNS_OWNERSHIP`, `BORROWS`, `TRANSFERS_OWNERSHIP`, `INCREMENTS_REFCOUNT`,
`DECREMENTS_REFCOUNT` and `FREES` (the brief's section 4). The OpenSSL calling conventions map
onto them: `X_new`/`CRYPTO_malloc` **allocates**, `X_set0` **transfers** ownership, `X_set1`
transfers and **increments** the refcount, `X_get0` **borrows**, `X_get1` returns ownership and
increments, `X_up_ref` increments and `X_free` decrements, and a deallocator **frees**. A
structural possibility of a double free, a use-after-free, a lost ownership, an incorrect clone, a
missing refcount, a premature free or a leak is recorded as a **finding**, never asserted as a
defect without evidence: the plane records what is structurally possible, not what is true.

A pure derivation, so it executes nothing
-----------------------------------------
It reads the committed census, the committed TCB and the committed source tree and writes a
derived plane; it runs no compiler, no tool and no probe, so `forensics/memory-safety/container.json`
lists it `metadata_only` and the Docker-only guard admits it on any host (it still calls the guard
first, so the rule is never optional).

Outputs
-------
  artifacts/phase25/ownership-planes.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
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
)

# The Docker-only execution guard, called first. This tool executes nothing -- it derives a plane
# from committed artefacts and committed source text -- so the manifest lists it `metadata_only`
# and the guard admits it on any host exactly as `ms_obligations.py` is.
import phase25_guard  # noqa: E402

# The record kinds and their closed vocabularies. Imported, never restated, so the planes cannot
# drift from the schema the court validates them against.
import memory_safety_schemas as schemas  # noqa: E402

# The lexical scanner the census already uses to define "code": comments and string literals are
# removed from a context's own text before this plane classifies it, so a family named only in a
# comment or a string is not read as an operation. Reused rather than re-implemented, so the two
# cannot disagree.
import unsafe_footprint as lexical  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "ownership-planes.json"
GENERATOR = "forensics/tools/ms_ownership_planes.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_ownership_planes.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
TCB = REPO_ROOT / "artifacts" / "phase25" / "non-rust-tcb.json"
OBLIGATIONS = REPO_ROOT / "artifacts" / "phase25" / "safety-obligations.json"
SRC = REPO_ROOT / "src"

OWNERSHIP_KINDS = list(schemas.OWNERSHIP_KINDS)

# The non-claims every Phase-25 artefact carries, plus this plane's own.
NON_CLAIMS = (
    "safe Rust does not prove protocol correctness: memory safety is not behavioural correctness",
    "unsafe Rust is not inherently vulnerable: an unsafe operation with a discharged contract is "
    "sound, so an unsafe site is not a defect",
    "unsafe LOC is not a vulnerability count: lines of unsafe code are a secondary projection of "
    "the compiler-derived census, and a count is not a risk",
    "the source classifications (the allocation family, the set/get convention, the callback "
    "registration, the Send/Sync justification, the global's mutability, the export's body) are "
    "deterministic projections over the committed source, recorded in `rule`; they are labels on "
    "compiler-established units, not compiler facts",
    "a structural possibility of a double free, a use-after-free, a lost ownership, an incorrect "
    "clone, a missing refcount, a premature free or a leak is recorded as a finding and never "
    "asserted as a defect: this plane records what the structure admits, not what is true",
    "an UNKNOWN panic/unwind class records that the unwind behaviour was not measured here; the "
    "panic-injection measurement belongs to a later subphase, so UNKNOWN blocks the seal rather "
    "than passing it (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 3.6)",
)


# --------------------------------------------------------------------------------------------
# the allocation/deallocation families: the closed table the plane records and the court reproduces
# --------------------------------------------------------------------------------------------
# Each family names the API, the role it plays in the allocation lifecycle (`ALLOC`, `REALLOC`,
# `FREE`, `CLEAR_FREE`, `SECURE_ALLOC`, `SECURE_FREE`, or a Rust ownership transfer), the deallocator
# that releases a block the family allocates, and its provenance. The patterns are anchored on the
# bare identifier so a path-qualified call (`crate::runtime::mem::CRYPTO_malloc`) matches.
ALLOCATION_FAMILIES: tuple[dict, ...] = (
    {"family": "CRYPTO_malloc", "pattern": r"\bCRYPTO_malloc\b", "role": "ALLOC",
     "freed_by": "CRYPTO_free",
     "provenance": "the crate's C allocator shim (src/runtime/mem.rs), backed by the Rust global "
                   "allocator"},
    {"family": "CRYPTO_zalloc", "pattern": r"\bCRYPTO_zalloc\b", "role": "ALLOC",
     "freed_by": "CRYPTO_free",
     "provenance": "the crate's C allocator shim (src/runtime/mem.rs); zero-initialised"},
    {"family": "CRYPTO_calloc", "pattern": r"\bCRYPTO_calloc\b", "role": "ALLOC",
     "freed_by": "CRYPTO_free",
     "provenance": "the crate's C allocator shim (src/runtime/mem.rs); count*size"},
    {"family": "CRYPTO_realloc", "pattern": r"\bCRYPTO_realloc\b", "role": "REALLOC",
     "freed_by": "CRYPTO_free",
     "provenance": "the crate's C allocator shim (src/runtime/mem.rs); reallocation"},
    {"family": "CRYPTO_memdup", "pattern": r"\bCRYPTO_memdup\b", "role": "ALLOC",
     "freed_by": "CRYPTO_free",
     "provenance": "the crate's C allocator shim (src/runtime/mem.rs); duplicated block"},
    {"family": "CRYPTO_strdup", "pattern": r"\bCRYPTO_strdup\b", "role": "ALLOC",
     "freed_by": "CRYPTO_free",
     "provenance": "the crate's C allocator shim (src/runtime/mem.rs); NUL-terminated copy"},
    {"family": "CRYPTO_free", "pattern": r"\bCRYPTO_free\b", "role": "FREE",
     "freed_by": "CRYPTO_malloc",
     "provenance": "the crate's C deallocator shim (src/runtime/mem.rs)"},
    {"family": "CRYPTO_clear_free", "pattern": r"\bCRYPTO_clear_free\b", "role": "CLEAR_FREE",
     "freed_by": "CRYPTO_malloc",
     "provenance": "the crate's C deallocator shim (src/runtime/mem.rs); clears before freeing"},
    {"family": "OPENSSL_malloc", "pattern": r"\bOPENSSL_malloc\b", "role": "ALLOC",
     "freed_by": "OPENSSL_free",
     "provenance": "the public OPENSSL_* alias of the crate's C allocator shim (src/runtime/mem.rs)"},
    {"family": "OPENSSL_zalloc", "pattern": r"\bOPENSSL_zalloc\b", "role": "ALLOC",
     "freed_by": "OPENSSL_free",
     "provenance": "the public OPENSSL_* alias; zero-initialised"},
    {"family": "OPENSSL_calloc", "pattern": r"\bOPENSSL_calloc\b", "role": "ALLOC",
     "freed_by": "OPENSSL_free",
     "provenance": "the public OPENSSL_* alias; count*size"},
    {"family": "OPENSSL_realloc", "pattern": r"\bOPENSSL_realloc\b", "role": "REALLOC",
     "freed_by": "OPENSSL_free",
     "provenance": "the public OPENSSL_* alias; reallocation"},
    {"family": "OPENSSL_strdup", "pattern": r"\bOPENSSL_strdup\b", "role": "ALLOC",
     "freed_by": "OPENSSL_free",
     "provenance": "the public OPENSSL_* alias; NUL-terminated copy"},
    {"family": "OPENSSL_free", "pattern": r"\bOPENSSL_free\b", "role": "FREE",
     "freed_by": "OPENSSL_malloc",
     "provenance": "the public OPENSSL_* deallocator alias"},
    {"family": "OPENSSL_clear_free", "pattern": r"\bOPENSSL_clear_free\b", "role": "CLEAR_FREE",
     "freed_by": "OPENSSL_malloc",
     "provenance": "the public OPENSSL_* deallocator alias; clears before freeing"},
    {"family": "secure_alloc", "pattern": r"\b(?:CRYPTO|OPENSSL)_secure_(?:malloc|zalloc|realloc)"
                                          r"(?:alloc)?\b",
     "role": "SECURE_ALLOC", "freed_by": "secure_free",
     "provenance": "the secure heap (src/runtime/secure.rs), a distinct allocator"},
    {"family": "secure_free", "pattern": r"\b(?:CRYPTO|OPENSSL)_secure_free\b", "role":
     "SECURE_FREE", "freed_by": "secure_alloc",
     "provenance": "the secure heap deallocator (src/runtime/secure.rs)"},
    {"family": "Box::into_raw", "pattern": r"\bBox::into_raw\b", "role": "RUST_RETURN_OWNERSHIP",
     "freed_by": "Box::from_raw",
     "provenance": "the Rust allocator via Box; ownership moves to the raw pointer"},
    {"family": "Box::from_raw", "pattern": r"\bBox::from_raw\b", "role": "RUST_TAKE_OWNERSHIP",
     "freed_by": "",
     "provenance": "the Rust allocator via Box; ownership returns from the raw pointer"},
    {"family": "CString::into_raw", "pattern": r"\bCString::into_raw\b", "role":
     "RUST_RETURN_OWNERSHIP", "freed_by": "CString::from_raw",
     "provenance": "the Rust allocator via CString; the NUL-terminated buffer moves to C"},
    {"family": "CString::from_raw", "pattern": r"\bCString::from_raw\b", "role":
     "RUST_TAKE_OWNERSHIP", "freed_by": "",
     "provenance": "the Rust allocator via CString; ownership returns from the raw pointer"},
    {"family": "Vec::from_raw_parts", "pattern": r"\bVec::from_raw_parts\b", "role":
     "RUST_TAKE_OWNERSHIP", "freed_by": "",
     "provenance": "the Rust allocator via Vec; a (ptr, len, cap) triple becomes a Vec"},
    {"family": "Vec::into_raw_parts", "pattern": r"\bVec::into_raw_parts\b", "role":
     "RUST_RETURN_OWNERSHIP", "freed_by": "Vec::from_raw_parts",
     "provenance": "the Rust allocator via Vec; a Vec becomes a (ptr, len, cap) triple"},
    {"family": "String::from_raw_parts", "pattern": r"\bString::from_raw_parts\b", "role":
     "RUST_TAKE_OWNERSHIP", "freed_by": "",
     "provenance": "the Rust allocator via String; a (ptr, len, cap) triple becomes a String"},
    {"family": "Rc::into_raw", "pattern": r"\bRc::into_raw\b", "role": "RUST_RETURN_OWNERSHIP",
     "freed_by": "Rc::from_raw",
     "provenance": "the Rust refcounted allocation via Rc; ownership moves to the raw pointer"},
    {"family": "Rc::from_raw", "pattern": r"\bRc::from_raw\b", "role": "RUST_TAKE_OWNERSHIP",
     "freed_by": "", "provenance": "the Rust refcounted allocation via Rc"},
    {"family": "Arc::into_raw", "pattern": r"\bArc::into_raw\b", "role": "RUST_RETURN_OWNERSHIP",
     "freed_by": "Arc::from_raw",
     "provenance": "the Rust refcounted allocation via Arc; ownership moves to the raw pointer"},
    {"family": "Arc::from_raw", "pattern": r"\bArc::from_raw\b", "role": "RUST_TAKE_OWNERSHIP",
     "freed_by": "", "provenance": "the Rust refcounted allocation via Arc"},
    {"family": "ManuallyDrop", "pattern": r"\bManuallyDrop::(?:new|into_inner)\b", "role":
     "RUST_TRANSFER", "freed_by": "",
     "provenance": "the Rust ownership discipline: a value whose drop is deferred"},
    {"family": "mem::forget", "pattern": r"\b(?:core|std)::mem::forget\b", "role": "RUST_TRANSFER",
     "freed_by": "",
     "provenance": "the Rust ownership discipline: a value intentionally leaked"},
)

_FAMILY_BY_NAME = {f["family"]: f for f in ALLOCATION_FAMILIES}
_FAMILY_PATTERNS = [(f["family"], re.compile(f["pattern"])) for f in ALLOCATION_FAMILIES]

# role -> the ownership-edge kind it emits.
ROLE_EDGE_KIND = {
    "ALLOC": "ALLOCATES",
    "REALLOC": "ALLOCATES",
    "SECURE_ALLOC": "ALLOCATES",
    "FREE": "FREES",
    "CLEAR_FREE": "FREES",
    "SECURE_FREE": "FREES",
    "RUST_RETURN_OWNERSHIP": "RETURNS_OWNERSHIP",
    "RUST_TAKE_OWNERSHIP": "TRANSFERS_OWNERSHIP",
    "RUST_TRANSFER": "TRANSFERS_OWNERSHIP",
}

# The reference-counting / ownership convention tokens the OpenSSL API families carry. Each names
# the object family (the identifier before the suffix) via capture group 1, the edge kind it emits,
# and whether it also emits an INCREMENTS_REFCOUNT edge (the `set1`/`get1` variants both take or
# return a reference *and* bump the count).
CONVENTION_PATTERNS: tuple[tuple[str, str, bool], ...] = (
    (r"\b([A-Za-z_][A-Za-z0-9_]*)_up_ref\b", "INCREMENTS_REFCOUNT", False),
    (r"\b([A-Za-z_][A-Za-z0-9_]*)_set0\b", "TRANSFERS_OWNERSHIP", False),
    (r"\b([A-Za-z_][A-Za-z0-9_]*)_set1\b", "TRANSFERS_OWNERSHIP", True),
    (r"\b([A-Za-z_][A-Za-z0-9_]*)_get0\b", "BORROWS", False),
    (r"\b([A-Za-z_][A-Za-z0-9_]*)_get1\b", "RETURNS_OWNERSHIP", True),
    # A generic `X_free` is a reference-count decrement (and a release at zero), unless it is one of
    # the bare deallocator families already modelled above.
    (r"\b([A-Za-z_][A-Za-z0-9_]*)_free\b", "DECREMENTS_REFCOUNT", False),
)
_CONVENTION_RX = [(re.compile(p), kind, also) for p, kind, also in CONVENTION_PATTERNS]
_BARE_DEALLOCATORS = frozenset({
    "CRYPTO_free", "CRYPTO_clear_free", "OPENSSL_free", "OPENSSL_clear_free",
    "CRYPTO_secure_free", "OPENSSL_secure_free",
})


# --------------------------------------------------------------------------------------------
# the callback-registration families
# --------------------------------------------------------------------------------------------
# `_callback_kind` maps a registration API name to a family; each family names who invokes the
# callback, how long it is stored, the thread context it runs in and how it is destroyed. A family
# not named falls back to `other`, whose fields say "not classified here" rather than guessing.
def _callback_kind(name: str) -> str:
    if re.search(r"_set_verify$|_set_cert_verify_callback$", name):
        return "verify"
    if re.search(r"_set_info_callback$|_set_msg_callback$|_set_keylog_callback$"
                 r"|_set_record_padding_cb$|_set_(?:client_hello|new_pending_conn)_cb$", name):
        return "tls_event"
    if re.search(r"_sess_set_[a-z_]*cb$|_set_session_ticket_cb$|_set_(?:session_secret|"
                 r"session_ticket_ext)_cb$", name):
        return "session"
    if re.search(r"_set_cookie_[a-z_]*cb$|_set_stateless_cookie_[a-z_]*cb$", name):
        return "cookie"
    if re.search(r"_set_psk_[a-z_]*callback$|_set_psk_", name):
        return "psk"
    if re.search(r"_set_alpn_select_cb$|_set_next_proto", name):
        return "alpn_npn"
    if re.search(r"_set_client_cert_cb$|_set_cert_cb$|_set_verify_callback$", name):
        return "cert"
    if re.search(r"_set_default_passwd_cb|_set_passphrase_cb|_set_pem_password_cb"
                 r"|_set_srp_cb|_set_passwd_cb|PEM_def_callback", name):
        return "password"
    if re.search(r"set_mem_functions$|_set_mem_debug$", name):
        return "allocation"
    if re.search(r"ASYNC_set_|_set_async_", name):
        return "async"
    if re.search(r"_set_security_callback$|_set_security_ex_data$", name):
        return "security"
    if re.search(r"^BIO_meth_set_", name):
        return "bio_method"
    if re.search(r"^ENGINE_set_", name):
        return "engine"
    if re.search(r"_set_[a-z0-9_]*cb$|_set_[a-z0-9_]*callback$|_set_cb$", name):
        return "tls_generic"
    return ""


CALLBACK_KINDS: dict[str, dict] = {
    "verify": {
        "invoked_by": "the authority's certificate-verification path (X509_verify_cert / "
                      "SSL_verify_cert_chain)",
        "lifetime": "stored on the SSL_CTX/SSL until replaced or the owning object is freed",
        "thread_context": "the thread driving the handshake the callback is registered on",
        "destruction": "replaced by a later registration, or dropped when the containing object "
                       "is freed",
        "may_outlive": False},
    "tls_event": {
        "invoked_by": "the authority's handshake state machine and record layer",
        "lifetime": "stored on the SSL/SSL_CTX until replaced or the owning object is freed",
        "thread_context": "the thread driving the connection",
        "destruction": "replaced by a later registration, or dropped when the containing object "
                       "is freed",
        "may_outlive": False},
    "session": {
        "invoked_by": "the authority's session-cache path",
        "lifetime": "stored on the SSL_CTX until replaced or the context is freed",
        "thread_context": "the thread that performs the session lookup/insert",
        "destruction": "replaced by a later registration, or dropped with the context",
        "may_outlive": False},
    "cookie": {
        "invoked_by": "the authority's DTLS cookie exchange",
        "lifetime": "stored on the SSL_CTX/SSL until replaced or freed",
        "thread_context": "the thread handling the datagram",
        "destruction": "replaced by a later registration, or dropped with the context",
        "may_outlive": False},
    "psk": {
        "invoked_by": "the authority's PSK handshake path",
        "lifetime": "stored on the SSL/SSL_CTX until replaced or freed",
        "thread_context": "the thread driving the handshake",
        "destruction": "replaced by a later registration, or dropped with the object",
        "may_outlive": False},
    "alpn_npn": {
        "invoked_by": "the authority's ALPN/NPN extension path",
        "lifetime": "stored on the SSL/SSL_CTX until replaced or freed",
        "thread_context": "the thread driving the handshake",
        "destruction": "replaced by a later registration, or dropped with the object",
        "may_outlive": False},
    "cert": {
        "invoked_by": "the authority's certificate-selection path",
        "lifetime": "stored on the SSL/SSL_CTX until replaced or freed",
        "thread_context": "the thread driving the handshake",
        "destruction": "replaced by a later registration, or dropped with the object",
        "may_outlive": False},
    "password": {
        "invoked_by": "the authority's PEM/key decryption path",
        "lifetime": "stored on the context/passphrase structure until replaced or freed",
        "thread_context": "the thread performing the decryption",
        "destruction": "replaced by a later registration, or dropped with the object",
        "may_outlive": False},
    "allocation": {
        "invoked_by": "the authority's allocator dispatch on every allocation/free",
        "lifetime": "process-global, latched at first allocation: the installed functions run for "
                    "the life of the process",
        "thread_context": "every thread that allocates",
        "destruction": "not unregistered; the latch makes the first install permanent",
        "may_outlive": True},
    "async": {
        "invoked_by": "the authority's ASYNC job/stack machinery",
        "lifetime": "process-global, latched at first use",
        "thread_context": "every thread that starts an async job",
        "destruction": "not unregistered",
        "may_outlive": True},
    "security": {
        "invoked_by": "the authority's security-level checks",
        "lifetime": "stored on the SSL/SSL_CTX until replaced or freed",
        "thread_context": "the thread performing the security check",
        "destruction": "replaced by a later registration, or dropped with the object",
        "may_outlive": False},
    "bio_method": {
        "invoked_by": "the authority's BIO dispatch, one function pointer per BIO operation",
        "lifetime": "stored in the BioMethod table for the life of the process (a static method "
                    "table) or until the method is freed",
        "thread_context": "any thread using a BIO of that method",
        "destruction": "a static method table is never dropped; a heap method drops with its table",
        "may_outlive": True},
    "engine": {
        "invoked_by": "the authority's ENGINE dispatch",
        "lifetime": "stored on the ENGINE until replaced or the ENGINE is freed",
        "thread_context": "any thread using the ENGINE",
        "destruction": "replaced by a later registration, or dropped with the ENGINE",
        "may_outlive": False},
    "provider_dispatch": {
        "invoked_by": "the authority's provider dispatch (OSSL_DISPATCH function pointers)",
        "lifetime": "stored in a static dispatch table for the life of the process",
        "thread_context": "any thread that fetches the algorithm",
        "destruction": "a static dispatch table is never dropped",
        "may_outlive": True},
    "tls_generic": {
        "invoked_by": "the authority's TLS dispatch for the named callback",
        "lifetime": "stored on the SSL/SSL_CTX until replaced or freed",
        "thread_context": "the thread driving the connection",
        "destruction": "replaced by a later registration, or dropped with the object",
        "may_outlive": False},
    "other": {
        "invoked_by": "not classified by this plane",
        "lifetime": "not classified by this plane",
        "thread_context": "not classified by this plane",
        "destruction": "not classified by this plane",
        "may_outlive": False},
}

# A `static ... : BioMethod = BioMethod { .. }` or a `static ... : [OsslDispatch; N]` table is a
# callback table rather than a single registration function.
_BIO_METHOD_TABLE = re.compile(r"\bstatic\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*BioMethod\s*=")
_DISPATCH_TABLE = re.compile(r"\bstatic\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\[\s*OsslDispatch\b")
_EXPORTED_FN = re.compile(
    r"pub(?:\([^)]*\))?\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+([A-Za-z0-9_]+)\s*\(")


# --------------------------------------------------------------------------------------------
# source scanning helpers
# --------------------------------------------------------------------------------------------

def build_context() -> dict:
    """The committed first-party source text, keyed by repository-relative path.

    Deterministic: the files are walked in sorted order and nothing but their bytes enters.
    """
    src: dict[str, dict] = {}
    for path in sorted(SRC.rglob("*.rs")):
        relpath = path.relative_to(REPO_ROOT).as_posix()
        raw = path.read_bytes()
        src[relpath] = {"text": raw.decode("utf-8", "replace"), "bytes": raw}
    return {"src": src}


def _own_text(raw: bytes, ctx: dict, group: list[dict]) -> str:
    """A context's own source text: its span minus every nested context's span.

    Exactly the census's rule (the context's *own* body, not a copy of a child's), so a family
    classified here is one the context itself performs.
    """
    bs, be = ctx["span"][0], ctx["span"][1]
    bs_c, be_c = min(bs, len(raw)), min(be, len(raw))
    buf = bytearray(raw[bs_c:be_c])
    for other in group:
        if other is ctx:
            continue
        obs, obe = other["span"][0], other["span"][1]
        if bs <= obs and obe <= be:
            lo = max(obs, bs_c) - bs_c
            hi = min(obe, be_c) - bs_c
            for k in range(lo, max(lo, hi)):
                buf[k] = 0x20
    return bytes(buf).decode("utf-8", "replace")


def _first_call_arg(text: str, at: int) -> str:
    """The first top-level argument of the call whose `(` begins at/after `at`, or `unknown`.

    A best-effort, secondary projection of the size expression: the plan asks for the size/alignment,
    and this records the call's first argument verbatim when it is simple, else `unknown`.
    """
    i = text.find("(", at)
    if i < 0:
        return "unknown"
    depth = 0
    j = i
    while j < len(text):
        ch = text[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        elif ch == "," and depth == 1:
            break
        j += 1
    arg = text[i + 1:j].strip()
    if not arg or len(arg) > 120 or "\n" in arg:
        return "unknown"
    return arg


def _fn_body(text: str, name: str) -> str | None:
    """The brace-matched body text of the function named `name`, or None.

    Used only for an exported symbol's body, to classify its unwind boundary. The first `fn NAME`
    in the file is the one the export is bound to (the census binds one site per exported symbol).
    """
    m = re.search(r"\bfn\s+" + re.escape(name) + r"\s*[(<]", text)
    if not m:
        return None
    i = m.end()
    depth_p = 0
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth_p += 1
        elif ch == ")":
            if depth_p > 0:
                depth_p -= 1
            elif depth_p == 0:
                break
        i += 1
    j = i
    while j < len(text) and text[j] != "{":
        j += 1
    if j >= len(text):
        return None
    depth = 0
    k = j
    while k < len(text):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():k + 1]
        k += 1
    return None


def _preceding_comment(lines: list[str], index: int, limit: int = 24) -> str:
    """The contiguous comment block ending at `lines[index-1]`, joined, or ''.

    A blank line or a non-comment line ends the block; doc comments and `//`/`/* */` comments are
    kept. This is how a Send/Sync justification or a global's safety contract is located.
    """
    out: list[str] = []
    i = index - 1
    steps = 0
    while i >= 0 and steps < limit:
        stripped = lines[i].strip()
        if stripped == "":
            if out:
                break
            i -= 1
            steps += 1
            continue
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            out.append(stripped)
            i -= 1
            steps += 1
            continue
        break
    out.reverse()
    return " ".join(out).strip()


# --------------------------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------------------------

def _client_name(token: str) -> str:
    """A short, stable suffix for an id."""
    return sha256_bytes(token.encode("utf-8"))[:16]


# The derivation reads the whole source tree, so it is memoised by the identity of its three
# arguments: the sensitivity control mutates the plane, not the census/TCB/context, so all its
# checks share one derivation rather than re-scanning the source for each mutation.
_DERIVE_CACHE: dict = {}


def derive_cached(census_body: dict, tcb_body: dict, ctx: dict) -> dict:
    """`derive` memoised by the identity of its three arguments (pure and deterministic)."""
    key = (id(census_body), id(tcb_body), id(ctx))
    if key not in _DERIVE_CACHE:
        _DERIVE_CACHE[key] = derive(census_body, tcb_body, ctx)
    return _DERIVE_CACHE[key]


def derive(census_body: dict, tcb_body: dict, ctx: dict) -> dict:
    """Every plane, re-derived from the census, the TCB and the committed source text.

    Pure over its three arguments: no compiler, no disk except through `ctx`. `build_body` and
    `ownership_findings` share it, so the artefact's content and the court's re-derivation cannot
    be two different rules.
    """
    src = ctx["src"]
    contexts = census_body.get("unsafe_contexts") or []
    sites = census_body.get("sites") or []
    ctx_by_id = {c.get("context_id"): c for c in contexts}
    site_by_id = {s.get("site_id"): s for s in sites}

    by_file: dict[str, list[dict]] = defaultdict(list)
    for c in contexts:
        by_file[c.get("file")].append(c)

    allocation_sites: list[dict] = []
    ownership_edges: list[dict] = []
    double_free_contexts: list[dict] = []
    function_of_site: dict[str, str] = {}
    file_of_site: dict[str, str] = {}

    # Pre-filter: only a file whose text names an allocation family or a convention token is
    # scanned per context. This is a performance bound, not a semantic one: a context's own text is
    # inside its file's text.
    family_hot = re.compile("|".join(
        [f["pattern"] for f in ALLOCATION_FAMILIES]
        + [p for p, _k, _g in CONVENTION_PATTERNS]))

    for relpath in sorted(by_file):
        entry = src.get(relpath)
        if entry is None:
            continue
        text = entry["text"]
        if not family_hot.search(text):
            continue
        raw = entry["bytes"]
        group = sorted(by_file[relpath], key=lambda c: (c["span"][0], c["span"][1]))
        for c in group:
            site_ids = c.get("site_ids") or []
            if not site_ids:
                continue
            own = _own_text(raw, c, group)
            code = lexical.code_only(own, keep_strings=False)
            if not family_hot.search(code):
                continue
            site_id = site_ids[0]
            site = site_by_id.get(site_id) or {}
            function = str(site.get("function") or "")
            function_of_site[site_id] = function
            file_of_site[site_id] = relpath
            free_hits = 0
            alloc_hits: list[tuple[str, str]] = []
            for family, pattern in _FAMILY_PATTERNS:
                m = pattern.search(code)
                if m is None:
                    continue
                fam = _FAMILY_BY_NAME[family]
                size = ("(deallocator: no size argument)"
                        if fam["role"] in ("FREE", "CLEAR_FREE", "SECURE_FREE")
                        else _first_call_arg(code, m.end()))
                paired = bool(fam["freed_by"]) and fam["role"].startswith(
                    ("ALLOC", "REALLOC", "SECURE", "RUST_RETURN"))
                allocation_sites.append({
                    "allocation_id": "as:" + site_id + ":" + _client_name(family),
                    "site_id": site_id,
                    "allocator": family,
                    "role": fam["role"],
                    "size_expr": size,
                    "freed_by": fam["freed_by"] if paired else "",
                    "paired": paired,
                    "provenance": fam["provenance"],
                    "evidence": [
                        f"the site's own compiler-derived context at {relpath}:{site.get('line')} "
                        f"names {family}",
                        f"allocator provenance: {fam['provenance']}",
                    ],
                })
                kind = ROLE_EDGE_KIND.get(fam["role"])
                if kind:
                    ownership_edges.append({
                        "edge_id": "oe:" + _client_name(f"{site_id}\0{kind}\0{family}"),
                        "from_site": site_id,
                        "to_site": "authority:" + family,
                        "kind": kind,
                        "site_id": site_id,
                        "symbol": family,
                        "object": family,
                        "file": relpath,
                        "matched_by": [],
                        "evidence": [
                            f"{family} ({fam['role']}) at {relpath}:{site.get('line')}",
                            f"allocator provenance: {fam['provenance']}",
                        ],
                    })
                if fam["role"] in ("ALLOC", "REALLOC", "SECURE_ALLOC", "RUST_RETURN_OWNERSHIP"):
                    alloc_hits.append((site_id, family))
                if fam["role"] in ("FREE", "CLEAR_FREE", "SECURE_FREE"):
                    free_hits += 1
            # The convention tokens.
            for pattern, kind, also_increments in _CONVENTION_RX:
                for m in pattern.finditer(code):
                    obj = m.group(1)
                    if kind == "DECREMENTS_REFCOUNT" and obj + "_free" in _BARE_DEALLOCATORS:
                        continue
                    if kind == "DECREMENTS_REFCOUNT" and obj in ("CRYPTO", "OPENSSL"):
                        continue
                    ownership_edges.append({
                        "edge_id": "oe:" + _client_name(f"{site_id}\0{kind}\0{obj}_{kind.lower()}"),
                        "from_site": site_id,
                        "to_site": "authority:" + obj,
                        "kind": kind,
                        "site_id": site_id,
                        "symbol": obj,
                        "object": obj,
                        "file": relpath,
                        "matched_by": [],
                        "evidence": [
                            f"the {kind.lower()} convention on {obj} at "
                            f"{relpath}:{site.get('line')}",
                        ],
                    })
                    if also_increments:
                        ownership_edges.append({
                            "edge_id": "oe:" + _client_name(
                                f"{site_id}\0INCREMENTS_REFCOUNT\0{obj}_inc"),
                            "from_site": site_id,
                            "to_site": "authority:" + obj,
                            "kind": "INCREMENTS_REFCOUNT",
                            "site_id": site_id,
                            "symbol": obj,
                            "object": obj,
                            "file": relpath,
                            "matched_by": [],
                            "evidence": [
                                f"the set1/get1 variant on {obj} bumps the refcount at "
                                f"{relpath}:{site.get('line')}",
                            ],
                        })
            if free_hits >= 2:
                double_free_contexts.append({
                    "site_id": site_id, "file": relpath, "frees": free_hits,
                    "function": function,
                })

    # De-duplicate edges by id (a context can name the same convention token twice).
    edge_by_id: dict[str, dict] = {}
    for e in ownership_edges:
        edge_by_id.setdefault(e["edge_id"], e)
    ownership_edges = sorted(edge_by_id.values(), key=lambda e: e["edge_id"])
    allocation_sites.sort(key=lambda a: a["allocation_id"])

    # --- matching --------------------------------------------------------------------------------
    alloc_by_file: dict[str, list[str]] = defaultdict(list)
    increments_by_object: dict[str, list[str]] = defaultdict(list)
    for e in ownership_edges:
        if e["kind"] in ("ALLOCATES", "RETURNS_OWNERSHIP"):
            alloc_by_file[e["file"]].append(e["edge_id"])
        if e["kind"] == "INCREMENTS_REFCOUNT":
            increments_by_object[e["object"]].append(e["edge_id"])
    unmatched_frees: list[str] = []
    unmatched_refcount: list[str] = []
    for e in ownership_edges:
        if e["kind"] == "FREES":
            e["matched_by"] = sorted(alloc_by_file.get(e["file"], []))[:8]
            if not e["matched_by"]:
                e["finding_id"] = "find-free-" + _client_name(e["edge_id"])
                unmatched_frees.append(e["finding_id"])
        elif e["kind"] == "DECREMENTS_REFCOUNT":
            e["matched_by"] = sorted(increments_by_object.get(e["object"], []))[:8]
            if not e["matched_by"]:
                e["finding_id"] = "find-rc-" + _client_name(e["object"])
                unmatched_refcount.append(e["object"])

    # --- callbacks -------------------------------------------------------------------------------
    callback_lifetimes: list[dict] = []
    for relpath in sorted(src):
        text = src[relpath]["text"]
        lines = text.split("\n")
        for m in _EXPORTED_FN.finditer(text):
            name = m.group(1)
            kind = _callback_kind(name)
            if not kind:
                continue
            line = text.count("\n", 0, m.start()) + 1
            callback_lifetimes.append(_callback_record(
                relpath, line, name, kind,
                _param_types(text, m.end())))
        for rx, kind in ((_BIO_METHOD_TABLE, "bio_method"), (_DISPATCH_TABLE, "provider_dispatch")):
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                callback_lifetimes.append(_callback_record(
                    relpath, line, m.group(1), kind, "(a static table of function pointers)"))
    callback_lifetimes.sort(key=lambda c: c["callback_id"])

    # --- unsafe Send/Sync impls ------------------------------------------------------------------
    send_sync: list[dict] = []
    ss_rx = re.compile(
        r"unsafe\s+impl(?P<gen>[^;{]*?)\b(?P<trait>Send|Sync)\b\s+for\s+"
        r"(?P<type>[A-Za-z_][A-Za-z0-9_:<>,\s]*?)\s*\{")
    for relpath in sorted(src):
        text = src[relpath]["text"]
        lines = text.split("\n")
        for m in ss_rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            justification = _preceding_comment(lines, line - 1)
            send_sync.append({
                "impl_id": "ss:" + _client_name(f"{m.group('trait')}\0{m.group('type')}\0"
                                                f"{relpath}\0{line}"),
                "type": m.group("type").strip(),
                "trait": m.group("trait").upper(),
                "justification": justification or "(no source-stated justification found; recorded "
                                                 "as a finding)",
                "has_source_justification": bool(justification),
                "mutability_fields": _impl_fields(text, m.group("type").strip()),
                "file": relpath,
                "line": line,
                "evidence": [
                    f"unsafe impl {m.group('trait')} for {m.group('type').strip()} at "
                    f"{relpath}:{line}",
                    "justification: the contiguous comment block above the impl"
                    if justification else "no comment block above the impl states a justification",
                ],
            })
    send_sync.sort(key=lambda s: s["impl_id"])

    # --- globals ---------------------------------------------------------------------------------
    globals_: list[dict] = []
    static_rx = re.compile(
        r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?static\s+(?P<mut>mut\s+)?"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<type>[^=;{]+?)\s*(?:=|;)",
        re.MULTILINE)
    sync_markers = ("Atomic", "OnceLock", "Once", "Mutex", "RwLock")
    for relpath in sorted(src):
        text = src[relpath]["text"]
        lines = text.split("\n")
        for m in static_rx.finditer(text):
            name = m.group("name")
            ty = m.group("type").strip()
            if m.group("mut"):
                mutability = "MUTABLE_UNSYNCHRONIZED"
            elif any(k in ty for k in sync_markers):
                mutability = "MUTABLE_SYNCHRONIZED"
            else:
                continue  # an immutable static carries no mutable state
            line = text.count("\n", 0, m.start()) + 1
            contract = (_preceding_comment(lines, line - 1)
                        if mutability == "MUTABLE_UNSYNCHRONIZED" else "")
            globals_.append({
                "global_id": "gs:" + _client_name(f"{relpath}\0{name}\0{line}"),
                "name": name,
                "mutability": mutability,
                "type": ty,
                "initialization": m.group(0).strip()[:160],
                "safety_contract": contract or (
                    "(no source-stated contract found; recorded as a finding)"
                    if mutability == "MUTABLE_UNSYNCHRONIZED" else ""),
                "has_source_contract": bool(contract),
                "file": relpath,
                "line": line,
                "evidence": [f"static {name}: {ty} at {relpath}:{line}",
                             "mutability classified from the static's own declaration"],
            })
        # thread-local storage
        for m in re.finditer(r"\bthread_local\s*(?:!|:)?\s*\{?", text):
            line = text.count("\n", 0, m.start()) + 1
            globals_.append({
                "global_id": "gs:" + _client_name(f"{relpath}\0tls\0{line}"),
                "name": f"thread_local@{relpath.split('/')[-1]}:{line}",
                "mutability": "THREAD_LOCAL",
                "type": "thread_local! { .. }",
                "initialization": "lazy thread-local initialisation",
                "safety_contract": "",
                "has_source_contract": True,
                "file": relpath,
                "line": line,
                "evidence": [f"thread_local! at {relpath}:{line}",
                             "Rust thread-local storage: one instance per thread"],
            })
    globals_.sort(key=lambda g: g["global_id"])

    # --- panic/unwind boundaries -----------------------------------------------------------------
    panic_boundaries: list[dict] = []
    body_cache: dict[tuple[str, str], str | None] = {}
    for b in tcb_body.get("ffi_boundaries") or []:
        boundary_id = str(b.get("boundary_id"))
        direction = b.get("direction")
        exporter = b.get("exporter")
        symbol = str(b.get("symbol") or "")
        site_id = str(b.get("census_site") or boundary_id)
        if direction == "INBOUND" and exporter == "rust":
            if symbol.startswith("<macro"):
                klass, caught, reason = (
                    "UNKNOWN", "",
                    "the export is macro-expanded, so no single source function body states its "
                    "unwind boundary; recorded as a finding")
            else:
                site = site_by_id.get(b.get("census_site"))
                relpath = site.get("file") if site else None
                body = None
                if relpath is not None:
                    key = (relpath, symbol)
                    if key not in body_cache:
                        entry = src.get(relpath)
                        body_cache[key] = (_fn_body(entry["text"], symbol)
                                           if entry else None)
                    body = body_cache[key]
                if body is None:
                    klass, caught, reason = (
                        "UNKNOWN", "",
                        "no source body was located for the exported symbol; recorded as a finding")
                elif "C-unwind" in body or "unwind(allowed)" in body:
                    klass, caught, reason = (
                        "C_UNWIND_EXPLICIT", "",
                        "the export declares an explicit unwind edge (C-unwind / unwind(allowed))")
                elif "guard_ffi" in body or "catch_unwind" in body:
                    klass, caught, reason = (
                        "CATCHES_PANIC", "src/ffi/mod.rs guard_ffi (catch_unwind, never resumes)",
                        "the export's body establishes the unwind boundary with guard_ffi")
                else:
                    klass, caught, reason = (
                        "UNKNOWN", "",
                        "the export's body contains no guard_ffi/catch_unwind and no explicit "
                        "unwind token; whether it can panic is not measured here (panic injection "
                        "belongs to a later subphase), so it is recorded as a finding")
            panic_boundaries.append({
                "panic_id": "pb:" + _client_name(f"{boundary_id}\0{symbol}"),
                "site_id": site_id,
                "class": klass,
                "caught_at": caught,
                "symbol": symbol,
                "boundary_id": boundary_id,
                "reason": reason,
                "evidence": [f"FFI boundary {boundary_id} ({symbol})",
                             reason],
            })
        else:
            panic_boundaries.append({
                "panic_id": "pb:" + _client_name(f"{boundary_id}\0{symbol}"),
                "site_id": site_id,
                "class": "CANNOT_PANIC_BY_CONSTRUCTION",
                "caught_at": "",
                "symbol": symbol,
                "boundary_id": boundary_id,
                "reason": ("the boundary is not Rust code (a foreign/C symbol), so no Rust panic "
                           "originates in it"),
                "evidence": [f"FFI boundary {boundary_id} ({symbol})",
                             "the boundary is not Rust code (a foreign/C symbol), so no Rust panic "
                             "originates in it"],
            })
    panic_boundaries.sort(key=lambda p: p["panic_id"])

    return {
        "allocation_sites": allocation_sites,
        "ownership_edges": ownership_edges,
        "callback_lifetimes": callback_lifetimes,
        "send_sync": send_sync,
        "globals": globals_,
        "panic_boundaries": panic_boundaries,
        "double_free_contexts": double_free_contexts,
        "unmatched_frees": sorted(unmatched_frees),
        "unmatched_refcount": sorted(set(unmatched_refcount)),
    }


def _param_types(text: str, open_paren_end: int) -> str:
    """The callback parameter type(s) of a registration function, from its signature.

    The last `Option<Xxx>`/`*mut Xxx`/`*const Xxx` parameter before the closing paren is the
    callback argument; its text is recorded verbatim.
    """
    i = open_paren_end - 1
    depth = 0
    j = i
    while j < len(text):
        ch = text[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        j += 1
    params = text[i + 1:j]
    found = re.findall(r"(?:Option<[^,>]+>|\*mut\s+[A-Za-z_][A-Za-z0-9_]*|"
                       r"\*const\s+[A-Za-z_][A-Za-z0-9_]*)", params)
    return found[-1].strip() if found else "(no callback-typed parameter located)"


def _impl_fields(text: str, type_name: str) -> list[str]:
    """The raw-pointer/interior-mutable fields of a struct, for the Send/Sync record."""
    base = type_name.split("<")[0].strip()
    m = re.search(r"\bstruct\s+" + re.escape(base) + r"[^{]*\{", text)
    if not m:
        return []
    depth = 0
    j = m.end() - 1
    k = j
    while k < len(text):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    body = text[j + 1:k]
    out = []
    for line in body.split("\n"):
        s = line.strip()
        if any(t in s for t in ("*mut ", "*const ", "UnsafeCell", "Cell<", "Atomic", "Mutex",
                                "RwLock", "OnceLock")):
            name = s.split(":")[0].strip().rstrip(",")
            if name and not name.startswith("//"):
                out.append(name)
    return out[:12]


def _callback_record(relpath: str, line: int, name: str, kind: str,
                     cb_type: str) -> dict:
    info = CALLBACK_KINDS.get(kind, CALLBACK_KINDS["other"])
    return {
        "callback_id": "cb:" + _client_name(f"{relpath}\0{line}\0{name}\0{kind}"),
        "registered_at": f"{relpath}:{line} {name}",
        "invoked_by": info["invoked_by"],
        "lifetime": info["lifetime"],
        "may_outlive": bool(info["may_outlive"]),
        "callback_type": cb_type,
        "family": kind,
        "thread_context": info["thread_context"],
        "destruction": info["destruction"],
        "file": relpath,
        "line": line,
        "evidence": [f"registration API {name} at {relpath}:{line}",
                     f"family {kind}: {info['lifetime']}"],
    }


# --------------------------------------------------------------------------------------------
# counts and findings
# --------------------------------------------------------------------------------------------

def _counts(d: dict) -> dict:
    """The counts, derived from the derived records -- never typed."""
    edges = d["ownership_edges"]
    by_kind = Counter(e["kind"] for e in edges)
    panic = Counter(p["class"] for p in d["panic_boundaries"])
    send_sync_missing = sum(1 for s in d["send_sync"] if not s["has_source_justification"])
    globals_missing = sum(1 for g in d["globals"]
                          if g["mutability"] == "MUTABLE_UNSYNCHRONIZED"
                          and not g["has_source_contract"])
    alloc_roles = Counter(a["role"] for a in d["allocation_sites"])
    alloc_unpaired = sum(1 for a in d["allocation_sites"]
                         if a["role"].startswith(("ALLOC", "REALLOC", "SECURE", "RUST_RETURN"))
                         and not a["paired"])
    return {
        "allocation_sites": len(d["allocation_sites"]),
        "allocation_sites_by_role": {k: alloc_roles[k] for k in sorted(alloc_roles)},
        "unpaired_allocations": alloc_unpaired,
        "ownership_edges": len(edges),
        "ownership_edges_by_kind": {k: by_kind[k] for k in sorted(by_kind)},
        "unmatched_frees": len(d["unmatched_frees"]),
        "unmatched_refcount_decrements": len(d["unmatched_refcount"]),
        "double_free_contexts": len(d["double_free_contexts"]),
        "callback_lifetimes": len(d["callback_lifetimes"]),
        "callback_families": len({c["family"] for c in d["callback_lifetimes"]}),
        "callbacks_that_may_outlive": sum(1 for c in d["callback_lifetimes"] if c["may_outlive"]),
        "send_sync": len(d["send_sync"]),
        "send_sync_by_trait": dict(sorted(Counter(s["trait"] for s in d["send_sync"]).items())),
        "send_sync_without_source_justification": send_sync_missing,
        "globals": len(d["globals"]),
        "globals_by_mutability": dict(sorted(Counter(g["mutability"]
                                                     for g in d["globals"]).items())),
        "globals_without_source_contract": globals_missing,
        "panic_boundaries": len(d["panic_boundaries"]),
        "panic_by_class": {k: panic[k] for k in sorted(panic)},
        "panic_unknown": panic["UNKNOWN"],
        "ffi_boundaries": len(d["panic_boundaries"]),
    }


def _property_findings(d: dict, counts: dict) -> list[str]:
    """The findings the artefact records: the gaps the instrument passes while naming."""
    findings = [
        f"{counts['unmatched_frees']} FREES edge(s) are in a file with no ALLOCATES/"
        f"RETURNS_OWNERSHIP edge: the release cannot be paired to a creation in the same "
        f"translation unit, so a free of a caller-owned pointer, of a value created elsewhere, or "
        f"a double free is structurally possible; recorded, never asserted as a defect",
        f"{counts['unmatched_refcount_decrements']} object family/-ies carry a DECREMENTS_REFCOUNT "
        f"edge with no INCREMENTS_REFCOUNT edge in the plane: a release below the object's initial "
        f"refcount of one, or an over-release, is structurally possible; recorded",
        f"{counts['double_free_contexts']} context(s) name two or more deallocating families: a "
        f"double free of the same block, or a free of two aliases of it, is structurally possible; "
        f"recorded",
        f"{counts['unpaired_allocations']} allocation edge(s) name an allocator with no known "
        f"deallocator: a leak is structurally possible; recorded",
        f"{counts['send_sync_without_source_justification']} manual unsafe Send/Sync impl(s) carry "
        f"no source-stated justification: an unexplained unsafe impl is an unexplained reachable "
        f"unsoundness; recorded",
        f"{counts['globals_without_source_contract']} MUTABLE_UNSYNCHRONIZED global(s) carry no "
        f"source-stated safety contract: an unsynchronized mutable global with no contract is an "
        f"unexplained reachable data race; recorded",
        f"{counts['panic_unknown']} exported C-ABI function(s) are UNKNOWN: the body contains no "
        f"guard_ffi/catch_unwind and no explicit unwind token, so whether it can unwind across the "
        f"C ABI is not measured here; an UNKNOWN class blocks the seal rather than passing it "
        f"(the panic-injection measurement belongs to a later subphase)",
        f"{counts['callbacks_that_may_outlive']} callback(s) are recorded as possibly outliving "
        f"their registrar (process-global allocation/async/bio-method/provider-dispatch hooks); "
        f"the lifetime is a structural classification, not an observed one",
    ]
    return findings


def build_body(census_body: dict, tcb_body: dict, ctx: dict) -> dict:
    """The ownership-planes body: the rule, the six planes, the counts and the findings."""
    d = derive_cached(census_body, tcb_body, ctx)
    counts = _counts(d)

    # One finding per unmatched FREES edge / object family, so a reader can map an edge to it.
    findings_extra = []
    for fid in d["unmatched_frees"]:
        findings_extra.append({"finding_id": fid, "class": "frees_without_visible_allocation",
                              "detail": "a FREES edge whose file has no ALLOCATES/"
                                        "RETURNS_OWNERSHIP edge"})
    for obj in d["unmatched_refcount"]:
        findings_extra.append({"finding_id": "find-rc-" + _client_name(obj),
                              "class": "refcount_decrement_without_increment",
                              "detail": f"object family {obj!r} has a DECREMENTS_REFCOUNT edge "
                                        f"with no INCREMENTS_REFCOUNT edge"})
    for c in d["double_free_contexts"]:
        findings_extra.append({"finding_id": "find-df-" + _client_name(c["site_id"]),
                              "class": "double_free_risk",
                              "detail": f"{c['frees']} deallocating families at "
                                        f"{c['file']} ({c['function']})"})

    body = {
        "rule": {
            "authority": (
                "the compiler is the authority for unsafe operations and 25.1's census is the "
                "authority for the sites: this plane classifies the memory-lifetime machinery around "
                "the compiler-derived sites and types no site and no operation"
            ),
            "source_classification": (
                "each site's own context text (its span minus nested contexts), comment- and "
                "string-stripped by the same scanner the census uses, is matched against the closed "
                "tables below; the plain `extern \"C\"` boundary and the panic class come from the "
                "committed source, and the boundary inventory comes from 25.2's non-Rust TCB"
            ),
            "allocation_families": [
                {"family": f["family"], "pattern": f["pattern"], "role": f["role"],
                 "freed_by": f["freed_by"], "provenance": f["provenance"]}
                for f in ALLOCATION_FAMILIES
            ],
            "role_edge_kind": dict(ROLE_EDGE_KIND),
            "convention_patterns": [
                {"pattern": p, "kind": k, "also_increments": also}
                for p, k, also in CONVENTION_PATTERNS
            ],
            "bare_deallocators": sorted(_BARE_DEALLOCATORS),
            "callback_kinds": {k: dict(v) for k, v in sorted(CALLBACK_KINDS.items())},
            "send_sync_justification": (
                "the contiguous comment block above an `unsafe impl Send`/`Sync` is its "
                "justification; a claim with no such block is recorded with a finding rather than "
                "an invented justification"
            ),
            "global_mutability": (
                "`static mut` is MUTABLE_UNSYNCHRONIZED, a static whose type names an atomic/"
                "OnceLock/Mutex/RwLock is MUTABLE_SYNCHRONIZED, a `thread_local!` is THREAD_LOCAL, "
                "and an immutable static carries no mutable state so it is not recorded"
            ),
            "panic_classification": (
                "an INBOUND Rust export whose body contains guard_ffi/catch_unwind is "
                "CATCHES_PANIC; `C-unwind`/`unwind(allowed)` is C_UNWIND_EXPLICIT; a non-Rust "
                "(foreign/C) boundary is CANNOT_PANIC_BY_CONSTRUCTION; a Rust export with no such "
                "body evidence is UNKNOWN and blocks the seal (panic injection is a later "
                "subphase). No UNKNOWN is hidden: each carries a reason and a finding"
            ),
            "edge_id_scheme": "oe:<sha16(site_id|kind|symbol)>",
            "matching": (
                "a FREES edge is matched to the ALLOCATES/RETURNS_OWNERSHIP edges of its file; a "
                "DECREMENTS_REFCOUNT edge is matched to the INCREMENTS_REFCOUNT edges of its "
                "object family; an unmatched edge names its finding"
            ),
        },
        "allocation_sites": d["allocation_sites"],
        "ownership_edges": d["ownership_edges"],
        "callback_lifetimes": d["callback_lifetimes"],
        "send_sync": d["send_sync"],
        "globals": d["globals"],
        "panic_boundaries": d["panic_boundaries"],
        "counts": counts,
        "findings": _property_findings(d, counts),
        "finding_records": findings_extra,
        "residuals": [],
        "non_claims": list(NON_CLAIMS),
    }
    body["residuals"] = _residuals(d, counts)
    return body


def _residuals(d: dict, counts: dict) -> list[dict]:
    out: list[dict] = []
    if counts["panic_unknown"]:
        out.append({
            "source": "ownership-planes", "class": "evidence_missing",
            "detail": (f"{counts['panic_unknown']} exported Rust C-ABI function(s) carry an "
                       f"UNKNOWN unwind class: the boundary is not observable in the source text "
                       f"and panic injection is a later subphase's measurement"),
        })
    if counts["unmatched_frees"]:
        out.append({
            "source": "ownership-planes", "class": "unexplained_reachable_unsafe",
            "detail": (f"{counts['unmatched_frees']} FREES edge(s) are not paired to a creation in "
                       f"their translation unit; reachability is 25.5's measurement"),
        })
    return out


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def ownership_findings(body: dict, census_body: dict, tcb_body: dict, ctx: dict) -> list[str]:
    """Every way the committed ownership plane contradicts the census, the TCB or the rule.

    Pure over `body`, the census, the TCB and the source context: it is what the
    `MS-OWNERSHIP-PLANES` court runs. It checks that every plane equals the derivation; that every
    record validates against its schema; that every allocation site has an allocator provenance;
    that every FREES edge has a matching ALLOCATES/RETURNS_OWNERSHIP or a finding; that every
    callback has a stored-lifetime classification; that every manual Send/Sync has a justification;
    that every export has a panic/unwind class and none is UNKNOWN without a finding; and that
    every count is derived, not typed.
    """
    problems: list[str] = []
    d = derive_cached(census_body, tcb_body, ctx)
    counts = _counts(d)

    # 1. Every plane equals the derivation, record for record.
    for plane in ("allocation_sites", "ownership_edges", "callback_lifetimes", "send_sync",
                  "globals", "panic_boundaries"):
        want = {r[_id_field(plane)]: r for r in d[plane]}
        got = {r.get(_id_field(plane)): r for r in (body.get(plane) or [])}
        for key in sorted(set(want) - set(got)):
            problems.append(f"{plane}: the derived record {key} is not recorded")
        for key in sorted(set(got) - set(want)):
            problems.append(f"{plane}: the plane records {key}, which is not derived")
        for key in sorted(set(want) & set(got)):
            if want[key] != got[key]:
                problems.append(f"{plane}[{key}]: the recorded record is not the derived record")

    # 2. Every record validates against its schema.
    for plane, kind in (("allocation_sites", "allocation_site"),
                        ("ownership_edges", "ownership_edge"),
                        ("callback_lifetimes", "callback_lifetime"),
                        ("send_sync", "send_sync_impl"),
                        ("globals", "global_state"),
                        ("panic_boundaries", "panic_boundary")):
        for r in body.get(plane) or []:
            problems += [f"{plane}[{r.get(_id_field(plane))}]: {p}"
                         for p in schemas.validate(kind, r)]

    # 3. Every allocation site has an allocator provenance.
    for a in body.get("allocation_sites") or []:
        if not a.get("provenance"):
            problems.append(f"allocation {a.get('allocation_id')} has no allocator provenance")

    # 4. Every FREES edge has a matching ALLOCATES/RETURNS_OWNERSHIP or a finding.
    finding_ids = {f.get("finding_id") for f in (body.get("finding_records") or [])}
    for e in body.get("ownership_edges") or []:
        if e.get("kind") == "FREES" and not e.get("matched_by"):
            if e.get("finding_id") not in finding_ids:
                problems.append(f"the FREES edge {e.get('edge_id')} has no matching "
                                f"ALLOCATES/RETURNS_OWNERSHIP edge and no recorded finding")

    # 5. Every callback has a stored-lifetime classification.
    for c in body.get("callback_lifetimes") or []:
        if not c.get("lifetime") or c.get("lifetime") == "not classified by this plane":
            problems.append(f"callback {c.get('callback_id')} has no stored-lifetime "
                            f"classification")

    # 6. Every manual Send/Sync has a justification.
    for s in body.get("send_sync") or []:
        if not s.get("justification"):
            problems.append(f"the unsafe impl {s.get('impl_id')} ({s.get('trait')} for "
                            f"{s.get('type')}) has no justification")

    # 7. Every export has a panic/unwind class; none is UNKNOWN without a finding.
    unknown = [p for p in body.get("panic_boundaries") or [] if p.get("class") == "UNKNOWN"]
    if unknown and not any("UNKNOWN" in f for f in body.get("findings") or []):
        problems.append(f"{len(unknown)} panic boundary/-ies are UNKNOWN and the artefact records "
                        f"no finding about them, which hides the gap")
    for p in unknown:
        if not p.get("reason"):
            problems.append(f"the UNKNOWN panic boundary {p.get('panic_id')} names no reason")

    # 8. The counts are derived, not typed.
    for key, val in counts.items():
        if (body.get("counts") or {}).get(key) != val:
            problems.append(f"counts.{key}={(body.get('counts') or {}).get(key)!r} is not the "
                            f"derived {val!r}")

    # 9. The property findings are recorded.
    if not any("FREES" in f for f in body.get("findings") or []):
        problems.append("the artefact records no finding about its unmatched FREES edges, which "
                        "hides the gap rather than recording it")
    return problems


def _id_field(plane: str) -> str:
    return {
        "allocation_sites": "allocation_id",
        "ownership_edges": "edge_id",
        "callback_lifetimes": "callback_id",
        "send_sync": "impl_id",
        "globals": "global_id",
        "panic_boundaries": "panic_id",
    }[plane]


def ownership_sensitivity_control(body: dict, census_body: dict, tcb_body: dict,
                                  ctx: dict) -> dict:
    """Seed four mutations and require each caught, with specificity holding.

    Each is a distinct way the plane could lie: a FREES edge with no allocation, a Send/Sync impl
    with no justification, an UNKNOWN panic class hidden, and a refcount decrement with no
    increment. The baseline must be clean and each mutation must produce its own finding.
    """
    baseline = ownership_findings(body, census_body, tcb_body, ctx)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated_body: dict, marker: str) -> bool:
        found = ownership_findings(mutated_body, census_body, tcb_body, ctx)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {
            "caught": caught, "findings": len(found),
            "delta": len(found) - len(baseline), "marker": marker,
        }
        return caught

    def clone():
        return json.loads(json.dumps(body))

    # m1: a FREES edge with no allocation -- a fabricated release with no matching creation.
    def free_without_allocation() -> dict:
        b = clone()
        b["ownership_edges"].append({
            "edge_id": "oe-fabricated-free", "from_site": "us-fabricated",
            "to_site": "authority:CRYPTO_free", "kind": "FREES", "site_id": "us-fabricated",
            "symbol": "CRYPTO_free", "object": "CRYPTO_free", "file": "src/fabricated.rs",
            "matched_by": [], "evidence": ["fabricated"],
        })
        return b

    m1 = check("frees_without_allocation", free_without_allocation(), "FREES")

    # m2: a Send/Sync impl with no justification.
    def send_sync_no_justification() -> dict:
        b = clone()
        if b["send_sync"]:
            b["send_sync"][0]["justification"] = ""
        return b

    m2 = check("send_sync_without_justification", send_sync_no_justification(), "justification")

    # m3: an UNKNOWN panic class hidden -- flip an UNKNOWN export to a confident class.
    def hide_unknown() -> dict:
        b = clone()
        for p in b["panic_boundaries"]:
            if p["class"] == "UNKNOWN":
                p["class"] = "CANNOT_PANIC_BY_CONSTRUCTION"
                break
        return b

    m3 = check("unknown_panic_hidden", hide_unknown(), "panic_boundaries")

    # m4: a refcount decrement with no increment -- a fabricated release with no acquire.
    def refcount_decrement_no_increment() -> dict:
        b = clone()
        b["ownership_edges"].append({
            "edge_id": "oe-fabricated-dec", "from_site": "us-fabricated",
            "to_site": "authority:Fabricated", "kind": "DECREMENTS_REFCOUNT",
            "site_id": "us-fabricated", "symbol": "Fabricated", "object": "Fabricated",
            "file": "src/fabricated.rs", "matched_by": [], "evidence": ["fabricated"],
        })
        return b

    m4 = check("refcount_decrement_without_increment", refcount_decrement_no_increment(),
               "ownership_edges")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_source() -> tuple[dict, str, bytes]:
    """The synthetic source tree, its text, and the byte spans the synthetic census names."""
    lines = [
        '#[no_mangle]',
        'pub unsafe extern "C" fn synth_export() -> c_int {',
        '    guard_ffi(0, || {',
        '        unsafe { let p = CRYPTO_malloc(8, c"f", 1); CRYPTO_free(p, c"f", 1); }',
        '        0',
        '    })',
        '}',
        '',
        '// SAFETY: Synth is a read-only global with no interior mutability.',
        'unsafe impl Sync for Synth {}',
        '',
        '#[no_mangle]',
        'pub unsafe extern "C" fn synth_bare() -> c_int {',
        '    0',
        '}',
        '',
        '// SAFETY: G is written only under the process-wide global lock.',
        'static mut G: c_int = 0;',
    ]
    text = "\n".join(lines) + "\n"
    raw = text.encode("utf-8")
    # uc-a: the body of `synth_export`, which names CRYPTO_malloc and CRYPTO_free (so it carries an
    # ALLOCATES and a FREES edge in the same file).
    body_at = text.index("guard_ffi(0, || {")
    body_end = text.index("    })", body_at) + len("    })")
    # uc-b: the `no_mangle` token of the second export (the FFI_EXPORT context the census records).
    nm = text.rindex("#[no_mangle]")
    no_mangle_at = nm + len("#[")
    synth = {"src/synthetic.rs": {"text": text, "bytes": raw}}
    return {"uc_a": (body_at, body_end), "uc_b": (no_mangle_at, no_mangle_at + 9)}, text, raw


def _synthetic_census() -> dict:
    """A tiny well-formed census, built without a compiler, for the self-test."""
    spans, _text, _raw = _synth_source()

    def ctx(cid, kind, line, state, contract, site_ids, bs, be):
        return {"context_id": cid, "kind": kind, "file": "src/synthetic.rs", "line": line,
                "span": [bs, be, line + 1, 1], "safety_contract": contract,
                "contract_state": state, "site_ids": site_ids, "evidence": []}

    def site(sid, cid, kind, line, fn):
        return {"site_id": sid, "file": "src/synthetic.rs", "line": line, "column": 1,
                "operation_kind": kind, "context_id": cid, "compiler": "synthetic",
                "compiler_derived": True, "exposure_class": "INTERNAL_REACHABLE",
                "risk_tier": "S4", "safety_obligation_ids": [], "evidence": [],
                "function": fn, "module": "synthetic"}

    a_bs, a_be = spans["uc_a"]
    b_bs, b_be = spans["uc_b"]
    return {
        "unsafe_contexts": [
            ctx("uc-a", "UNSAFE_BLOCK", 3, "STATED",
                "SAFETY: p is a CRYPTO_malloc block freed here.", ["us-a"], a_bs, a_be),
            ctx("uc-b", "FFI_EXPORT_FN", 12, "STATED", "# Safety\n/// An exported symbol.",
                ["us-b"], b_bs, b_be),
        ],
        "sites": [
            site("us-a", "uc-a", "UNSAFE_FUNCTION_CALL", 3, "synth_export"),
            site("us-b", "uc-b", "FFI_EXPORT", 12, "synth_bare"),
        ],
    }


def _synthetic_tcb() -> dict:
    return {"ffi_boundaries": [
        {"boundary_id": "fb-export", "direction": "INBOUND", "exporter": "rust",
         "symbol": "synth_export", "census_site": "us-a", "sites": ["us-a"]},
        {"boundary_id": "fb-bare", "direction": "INBOUND", "exporter": "rust",
         "symbol": "synth_bare", "census_site": "us-b", "sites": ["us-b"]},
    ], "counts": {"variadic_boundaries": 0}}


def self_test() -> int:
    """Prove the metadata-only admission holds and the sensitivity control is honest."""
    failures: list[str] = []

    admission = phase25_guard.evaluate(entry_point="ms_ownership_planes.py", env={},
                                       dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_ownership_planes.py is not admitted as a metadata-only generator on "
                        "a host")

    census = _synthetic_census()
    tcb = _synthetic_tcb()
    _spans, text, raw = _synth_source()
    ctx = {"src": {"src/synthetic.rs": {"text": text, "bytes": raw}}}
    body = build_body(census, tcb, ctx)
    baseline = ownership_findings(body, census, tcb, ctx)
    if baseline:
        failures.append(f"the synthetic ownership body is not clean: {baseline[:4]}")
    if body["counts"]["panic_unknown"] < 1:
        failures.append("the synthetic body records no UNKNOWN panic boundary, so the hidden-"
                        "UNKNOWN mutation would not be exercised")
    if body["counts"]["ownership_edges"] < 2:
        failures.append("the synthetic body records no ALLOCATES/FREES edge pair")
    control = ownership_sensitivity_control(body, census, tcb, ctx)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-ownership-planes] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-ownership-planes] self-test ok: the guard admits it as metadata-only; the "
          "synthetic ownership body is clean; and all four seeded mutations (a FREES with no "
          "allocation, a Send/Sync with no justification, a hidden UNKNOWN panic class and a "
          "refcount decrement with no increment) are caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-ownership-planes] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def _write_planes(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic.

    The plane carries tens of thousands of records, so pretty-printing would multiply the file
    without adding evidence; determinism is preserved (sorted keys, fixed separators) and
    `body_hash` covers the body.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _crate_sources_hash(ctx: dict) -> str:
    return content_hash({p: sha256_bytes(e["bytes"]) for p, e in ctx["src"].items()})


def _inputs(ctx: dict) -> list[InputRef]:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-ownership-planes-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="non-rust-tcb", path=TCB),
        InputRef(name="safety-obligations", path=OBLIGATIONS),
        InputRef(name="crate-sources", sha256=_crate_sources_hash(ctx),
                 note="content hash of the sorted (path, sha256) pairs of every shipped "
                      "src/**/*.rs file the source classification reads"),
    ]


def _measure() -> int:
    """Derive the ownership planes from the committed census, TCB and source, and write them."""
    census_body = _load(CENSUS).get("body", {})
    tcb_body = _load(TCB).get("body", {})
    ctx = build_context()
    body = build_body(census_body, tcb_body, ctx)
    problems = ownership_findings(body, census_body, tcb_body, ctx)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-ownership-planes", authority=auth.id, inputs=_inputs(ctx),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_planes(OUT, doc)

    c = body["counts"]
    print(f"[ms-ownership-planes] {c['allocation_sites']} allocation site(s), "
          f"{c['ownership_edges']} ownership edge(s), {c['callback_lifetimes']} callback(s), "
          f"{c['send_sync']} Send/Sync impl(s), {c['globals']} global(s), "
          f"{c['panic_boundaries']} panic boundary/-ies")
    print(f"  edges by kind: {c['ownership_edges_by_kind']}")
    print(f"  panic by class: {c['panic_by_class']}")
    print(f"  unmatched frees={c['unmatched_frees']} unmatched refcount decrements="
          f"{c['unmatched_refcount_decrements']} double-free contexts={c['double_free_contexts']}")
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-ownership-planes] {rel(OUT)} is absent; run --measure")
        return 1
    body = _load(OUT).get("body", {})
    census_body = _load(CENSUS).get("body", {})
    tcb_body = _load(TCB).get("body", {})
    ctx = build_context()
    problems = ownership_findings(body, census_body, tcb_body, ctx)
    if problems:
        print(f"[ms-ownership-planes] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-ownership-planes] check ok: {c['allocation_sites']} allocation site(s), "
          f"{c['ownership_edges']} edge(s), {c['callback_lifetimes']} callback(s), "
          f"{c['send_sync']} Send/Sync impl(s), {c['globals']} global(s), "
          f"{c['panic_boundaries']} panic boundary/-ies; every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/ownership-planes.json from the committed inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed ownership plane")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the metadata-only admission and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool executes nothing, so the manifest
    # lists it `metadata_only` and the guard admits it on any host.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return _check()
    # The default action is the derivation (and `--measure` names it): `evidence_determinism.py`
    # regenerates every generator with no flags and compares the bytes.
    return _measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
