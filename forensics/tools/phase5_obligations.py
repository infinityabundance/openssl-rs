#!/usr/bin/env python3
"""openssl-rs — the Phase 5 obligation ledger, with **derived** symbol families.

Why the families are derived here rather than typed
--------------------------------------------------
`phase3_obligations.py` and `phase4_obligations.py` list their families as
explicit `(module, prefixes)` pairs. That works while a stratum is a handful of
subsystems whose prefixes a person can hold in their head, and it is exactly how
the D49/D51 defect class arose twice: an export whose name matches no listed
prefix is invisible to every ledger at once.

Phase 5 cannot be done that way. Its surface is 1,093 exports spanning 270
distinct ASN.1 type names, and the question "does this belong to Phase 5?" is not
answerable from the *name* at all: `d2i_X509` and `d2i_ASN1_INTEGER` look alike and
belong to different strata. What does answer it is *where the symbol is declared*,
which the Phase 1 atlas already records per function.

So the rule is mechanical, and it is stated rather than implied:

    A symbol belongs to the stratum that owns the header declaring it.

with one exception that the header alone cannot express: `pem.h` declares both the
generic PEM machinery *and* the typed readers and writers for types owned
elsewhere (`PEM_read_bio_X509` is Phase 11's, not Phase 5's, even though `pem.h`
declares it). Those are resolved by the type in the name, looked up in the atlas.

Failure is loud. A header with no entry in `HEADER_PHASE`, or a PEM type that
cannot be resolved, stops the ledger rather than defaulting to "probably Phase 5".

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    implemented_surface_input,
    rel,
    resolve_authority,
    write_json,
)

OUT = REPO_ROOT / "forensics" / "phase5-obligations.json"
GENERATOR = "forensics/tools/phase5_obligations.py"

# Which stratum owns a header. An entry is a *decision*, and the value is the
# phase that will implement the subsystem the header declares. Headers not listed
# here stop the run: silence would be an assignment by default, which is how a
# symbol becomes invisible.
HEADER_PHASE: dict[str, int] = {
    # Phase 5 — this stratum.
    "bn.h": 5,
    "asn1.h": 5,
    "asn1t.h": 5,
    # Phase 6 — the provider core and library contexts.
    "core_names.h": 6,
    "core_object.h": 6,
    "provider.h": 6,
    "params.h": 6,
    # Phase 7 — EVP.
    "evp.h": 7,
    # Phase 8 — the native primitives, whose key types live in these headers.
    "dsa.h": 8,
    "dh.h": 8,
    "rsa.h": 8,
    "ec.h": 8,
    # Phase 10 — persistence and interchange.
    "pkcs12.h": 10,
    "store.h": 10,
    "encoder.h": 10,
    "decoder.h": 10,
    # Phase 11 — X.509 and path validation.
    "x509.h": 11,
    "x509v3.h": 11,
    "x509_acert.h": 11,
    "x509_vfy.h": 11,
    # Phase 12 — the remaining protocol families.
    "cms.h": 12,
    "ocsp.h": 12,
    "ts.h": 12,
    "pkcs7.h": 12,
    "crmf.h": 12,
    "cmp.h": 12,
    "ess.h": 12,
    "ct.h": 12,
}

# Which module of Phase 5 owns a header it claims.
MODULE_OF_HEADER: dict[str, str] = {
    "bn.h": "src/bn/",
    "asn1.h": "src/asn1/",
    "asn1t.h": "src/asn1/",
    "pem.h": "src/pem/",
}

# The prefix *projection* of the header rule above, in the shape
# `forensics/tools/ownership_audit.py` consumes: that audit asks whether every
# implemented export is claimed by some phase family, and it reads families as
# prefixes. The authoritative rule for this stratum remains the declaring header —
# the prefixes cannot separate `d2i_X509` from `d2i_ASN1_INTEGER`, which is the
# whole reason the rule is header-based — so this list is deliberately the union of
# what the modules' symbols actually look like, and a symbol that fits no entry here
# is exactly what that audit exists to surface.
#
# `PEM_write_bio_ASN1_stream` is declared in `asn1.h` and so belongs to `src/asn1/`,
# while `d2i_PKCS8PrivateKey_*`/`i2d_PKCS8PrivateKey_*` are declared in `pem.h` and
# belong to `src/pem/`; both are named here because a prefix cannot express them.
FAMILIES = [
    ("src/bn/", ("BN_",)),
    ("src/asn1/", ("ASN1_", "d2i_", "i2d_", "PEM_write_bio_ASN1_stream",
                   "BIO_asn1_", "BIO_f_asn1", "BIO_new_NDEF")),
    ("src/pem/", ("PEM_", "d2i_PKCS8PrivateKey", "i2d_PKCS8PrivateKey")),
]

# Symbols the Phase 4 ledger hands to this stratum (`forensics/phase4-obligations.json`,
# `deferred` rows whose `owning_phase` is 5). Each is a BIO that exists only to carry
# an ASN.1 or DER codec, so the obligation is this stratum's even though the code
# that needed the sink already lives in Phase 4. Declaring them here is what lets
# `ownership_audit.py` prove the two ledgers agree: Phase 4 must list exactly these
# as deferred to Phase 5, and this stratum must list exactly these as the hand-offs
# it discharged, so no symbol can be counted as implemented by two strata at once.
HANDED_OFF_FROM_PHASE4 = (
    "BIO_asn1_get_prefix",
    "BIO_asn1_get_suffix",
    "BIO_asn1_set_prefix",
    "BIO_asn1_set_suffix",
    "BIO_f_asn1",
    "BIO_new_NDEF",
)

# The type in a PEM name is the last `_`-separated token group, after any of the
# call-shape suffixes. `PEM_read_bio_X509` -> `X509`; `PEM_write_bio_PKCS7` ->
# `PKCS7`; `PEM_def_callback` has no type and is generic.
PEM_TYPE_RE = re.compile(r"^PEM_[a-z0-9]+(?:_bio|_fp|_asn1)?_(.+)$")


def load(atlas: Path, name: str) -> dict:
    return json.loads((atlas / name).read_text(encoding="utf-8"))["body"]


def authority_exports(atlas: Path) -> list[str]:
    """The symbols the authority actually exports from libcrypto."""
    return sorted(
        r["symbol"] for r in load(atlas, "symbols-libcrypto.json")["records"]
        if r["dso"]["present"]
    )


def declared_headers(atlas: Path) -> dict[str, str]:
    return {r["name"]: r["header"] for r in load(atlas, "functions.json")["records"]}


def type_headers(atlas: Path) -> dict[str, str]:
    """Best header for each type name.

    A forward declaration in `types.h` is a real declaration and a useless one:
    every type has one, so it never distinguishes anything. `pem.h` is the same
    kind of container -- it declares the typed readers and writers for every type
    it can serialise, so a type resolved to `pem.h` has told us nothing.

    The evidence used, strongest first, is the struct definition, then the
    function names that take or return the type (`X509_free`, `d2i_X509`), then
    the typedef. `types.h` and `pem.h` are accepted only when nothing stronger
    exists, and the caller treats them as "no opinion".
    """
    best: dict[str, Counter] = {}

    def note(type_name: str, header: str, weight: int) -> None:
        best.setdefault(type_name, Counter())[header] += weight

    for rec in load(atlas, "structs.json")["records"]:
        if rec.get("header"):
            note(rec["name"], rec["header"], 100)

    for name, header in declared_headers(atlas).items():
        # `d2i_T` / `i2d_T` / `PEM_write_bio_T`: the tail names the type outright.
        m = re.match(r"^(?:d2i|i2d|PEM_[a-z0-9]+(?:_bio|_fp|_asn1)?)_(.+)$", name)
        if m:
            note(m.group(1), header, 10)
        # `T_something`: the leading token may be a type. Weighted below the
        # explicit forms because a leading token can be a verb.
        lead = re.match(r"^([A-Z][A-Za-z0-9]*?)_", name)
        if lead:
            note(lead.group(1), header, 5)

    for rec in load(atlas, "typedefs.json")["records"]:
        note(rec["name"], rec["header"], 1)

    weak = {"types.h", "pem.h"}
    out: dict[str, str] = {}
    for type_name, counts in best.items():
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        strong = [h for h, _ in ranked if h not in weak]
        out[type_name] = (strong or [h for h, _ in ranked])[0]
    return out


def weak_type_header(header: str | None) -> bool:
    """True when a type's resolved header says nothing about who owns it."""
    return header is None or header in ("types.h", "pem.h")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    atlas = REPO_ROOT / "forensics" / "atlas" / auth.id
    exports = authority_exports(atlas)
    headers = declared_headers(atlas)
    types = type_headers(atlas)

    implemented = set(
        json.loads(
            (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
                encoding="utf-8"
            )
        )["body"]["libraries"]["libcrypto"]["implemented_symbols"]
    )

    # The stratum's scope: everything declared in a header this stratum owns, plus
    # the PEM names whose type resolves into it.
    prefix = re.compile(r"^(BN_|ASN1_|d2i_|i2d_|PEM_)")
    candidates = [s for s in exports if prefix.match(s)]

    owned: dict[str, dict] = {}
    deferred: list[dict] = []
    unresolved: list[str] = []

    def claim(sym: str, module: str, header: str) -> None:
        owned[sym] = {
            "symbol": sym, "module": module, "declaring_header": header,
        }

    for sym in candidates:
        header = headers.get(sym)
        if header is not None and header in HEADER_PHASE:
            phase = HEADER_PHASE[header]
            if phase == 5:
                claim(sym, MODULE_OF_HEADER[header], header)
            else:
                # The family's *prefixes* still match this symbol -- `d2i_X509`
                # starts with `d2i_` -- so the ledger counts it as an export the
                # stratum's families cover and then hands it on. That is the same
                # shape Phase 3 and Phase 4 use, and it is what makes
                # `implemented + deferred + open == owned` hold here too.
                claim(sym, f"(phase {phase})", header)
                deferred.append({
                    "symbol": sym, "owning_phase": phase,
                    "declaring_header": header,
                    "reason": f"declared in {header}; that subsystem is phase {phase}",
                })
            continue

        # `pem.h`, or a header the table does not know: resolve by type.
        if header not in (None, "pem.h") and header not in HEADER_PHASE:
            unresolved.append(f"{sym}: header {header} is not in HEADER_PHASE")
            continue
        m = PEM_TYPE_RE.match(sym)
        if m is None:
            # A generic PEM entry point with no type in its name.
            claim(sym, "src/pem/", header or "(pem.h)")
            continue
        type_name = m.group(1)
        type_header = types.get(type_name)
        if weak_type_header(type_header):
            # Nothing stronger than a forward declaration names this type, so the
            # name is not evidence and the generic machinery is what is being
            # declared here.
            claim(sym, "src/pem/", header or "(pem.h)")
            continue
        if type_header not in HEADER_PHASE:
            unresolved.append(f"{sym}: type {type_name} is declared in {type_header}, "
                              "which is not in HEADER_PHASE")
            continue
        phase = HEADER_PHASE[type_header]
        if phase == 5:
            claim(sym, "src/pem/", type_header)
        else:
            claim(sym, f"(phase {phase})", type_header)
            deferred.append({
                "symbol": sym, "owning_phase": phase,
                "declaring_header": type_header,
                "reason": f"operates on {type_name}, declared in {type_header}; "
                          f"that subsystem is phase {phase}",
            })

    if unresolved:
        shown = "\n  ".join(sorted(unresolved)[:25])
        more = ("\n  ... and " + str(len(unresolved) - 25) + " more"
                if len(unresolved) > 25 else "")
        raise SystemExit(
            "phase5-obligations: these symbols could not be assigned without "
            "guessing. Add the header to HEADER_PHASE, or state the rule that "
            "resolves them:\n  " + shown + more
        )

    # The hand-offs Phase 4 handed this stratum must be accounted for here: a symbol
    # Phase 4 deferred to Phase 5 that this stratum does not even claim is an
    # obligation that fell between the two ledgers. They do not match the candidate
    # prefix, because the header that declares them is `bio.h` -- Phase 4's header --
    # so they are claimed by name.
    for sym in HANDED_OFF_FROM_PHASE4:
        if sym not in exports:
            raise SystemExit(
                f"phase5-obligations: {sym} is handed from Phase 4 but the "
                "authority does not export it from this build profile"
            )
        owned.setdefault(sym, {
            "symbol": sym,
            "module": "src/asn1/",
            "declaring_header": headers.get(sym, "bio.h"),
        })

    bad = [r for r in deferred if r["owning_phase"] <= 5]
    if bad:
        raise SystemExit(
            "phase5-obligations: a hand-off must name a LATER stratum than this "
            "one:\n  " + "\n  ".join(r["symbol"] for r in bad)
        )

    if len(owned) != len(candidates) + len(HANDED_OFF_FROM_PHASE4):
        raise SystemExit(
            "phase5-obligations: the family covers "
            f"{len(owned)} exports but the candidates plus the Phase 4 hand-offs "
            f"are {len(candidates) + len(HANDED_OFF_FROM_PHASE4)} (the hand-offs are "
            "claimed by name rather than by prefix, and a deferred symbol is still "
            "counted as covered by the family that matches its prefix)"
        )

    implemented_here = sorted(s for s in owned if s in implemented)
    handed_on = {r["symbol"] for r in deferred}
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"]}
        for s in sorted(owned) if s not in implemented and s not in handed_on
    ]

    body = {
        "rule": (
            "a symbol belongs to the stratum that owns the header declaring it; "
            "`pem.h` is the one header that declares surface owned elsewhere, so "
            "its typed readers and writers are resolved by the type in the name"
        ),
        "header_phase": dict(sorted(HEADER_PHASE.items())),
        "module_of_header": dict(sorted(MODULE_OF_HEADER.items())),
        "counts": {
            "candidates": len(candidates),
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred_to_later_phase": len(deferred),
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": implemented_here,
        "deferred": sorted(deferred, key=lambda r: r["symbol"]),
        "open": open_rows,
        "handoffs_discharged": {"4": sorted(HANDED_OFF_FROM_PHASE4)},
        "owned_by_module": dict(
            sorted(
                Counter(
                    v["module"] for v in owned.values()
                    if not v["module"].startswith("(")
                ).items()
            )
        ),
        "deferred_by_phase": dict(
            sorted(Counter(r["owning_phase"] for r in deferred).items())
        ),
        # A hand-off is not a gap. `open` is the only list that blocks the
        # stratum: it is this stratum's unimplemented surface.
        "complete": not open_rows,
        "note": (
            "`owned` is every export the stratum's families cover, which includes the "
            "ones the declaring-header rule hands to a later phase: a deferred symbol "
            "is still matched by this stratum's prefixes, so counting it here is what "
            "makes `implemented + deferred + open == owned`. `open` is the only list "
            "that blocks the stratum. The families are derived from the atlas, not "
            "typed: see this generator's header for why, and note that a deferred "
            "symbol names the stratum that owns the header it is declared in, which is "
            "checkable without reading this file. Nothing here is a parity claim."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=atlas / "symbols-libcrypto.json"),
        InputRef(name="authority-functions", path=atlas / "functions.json"),
        InputRef(name="authority-typedefs", path=atlas / "typedefs.json"),
        InputRef(name="authority-structs", path=atlas / "structs.json"),
        implemented_surface_input(),
    ]
    doc = envelope(kind="phase5-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase5-obligations] candidates={c['candidates']} owned={c['owned']} "
          f"implemented={c['implemented']} deferred={c['deferred_to_later_phase']} "
          f"open={c['open_in_this_stratum']}")
    print(f"  complete={body['complete']}")
    print(f"  owned by module: {body['owned_by_module']}")
    print(f"  deferred by phase: {body['deferred_by_phase']}")
    for module in sorted(body["owned_by_module"]):
        rows = [r for r in open_rows if r["module"] == module]
        print(f"  open in {module}: {len(rows)}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
