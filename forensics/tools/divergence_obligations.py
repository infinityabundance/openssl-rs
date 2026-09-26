#!/usr/bin/env python3
"""openssl-rs — the security-divergence register, made machine-readable.

Why this is generated
---------------------
`docs/SECURITY_DIVERGENCE_POLICY.md` is the one obligation register in this project
that is **prose**. Every other one -- the per-stratum ledgers, the coverage atlases,
the provider census -- is rendered from a table and re-derived by `--check`, so a
stratum that owns an open obligation cannot reach `complete`. The divergence register
had no such machinery, and the hole was named in review as the branch's most
interesting weakness: an entry can carry a `**Trigger:**` -- the condition under which
the divergence must be revisited or removed -- and nothing machine-checked it, so a
stratum could derive `complete` while an obligation it owned had had its trigger fire
and was still owed.

So the trigger-bearing entries are transcribed here, one row each, with the phase that
owns the closure and whether the trigger has fired, and the JSON is rendered from that
table. `forensics/tools/phase_state.py` reads the result and holds a stratum open when a
row it owns is both triggered and still `open`, which is the derivation the register
never had.

What a row is, and what `blocking` is not
-----------------------------------------
A row's fields are the register entry's own: `id`, `originating_phase`,
`trigger_phase`, `current_owner`, `trigger_condition`, `trigger_satisfied`,
`disposition`, `evidence`, `note`. `blocking` is **derived, never typed**: it is true
when the trigger has fired and the disposition is still `open`, i.e. when the row blocks
*its own* `current_owner`. It is not a field a human edits, and it is not the table.

`disposition` is one of four values, and the vocabulary is the whole point:

  * `open` -- owed and not yet done. Only a stratum that is not `complete` may own one.
  * `fixed` -- discharged; `evidence` must name the file or court that shows it.
  * `explicitly_deferred` -- owed, but handed to the later phase named in
    `current_owner`, with the reason in `note`.
  * `accepted_permanent_divergence` -- a deliberate, recorded narrowing that will not be
    removed (an authority fault not reproduced, or a perlasm-only construction the crate
    answers portably).

The tool fails closed on the table itself: unique ids, phase numbers that exist, a
disposition from the vocabulary, a `fixed` row that names its evidence, and an
`explicitly_deferred` row that names a later owner and gives a reason. A violation exits
nonzero with the row named.

Usage
-----
    python3 forensics/tools/divergence_obligations.py            # write the artefact
    python3 forensics/tools/divergence_obligations.py --check     # fail if any drift

`forensics/tools/pipeline.sh` runs both, before `phase_state.py`, so the JSON exists
when the state is derived and a hand-edit cannot survive.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    write_json,
)

OUT = REPO_ROOT / "forensics" / "divergence-obligations.json"
GENERATOR = "forensics/tools/divergence_obligations.py"

# The sources the classifications were read from, recorded as content-addressed inputs.
# The register is the prose being transcribed; the seals say which stratum owns each
# entry's closure and how it was discharged; the ledgers are what the owning strata
# report as open. Binding them means the artefact states what it read.
REGISTER = "docs/SECURITY_DIVERGENCE_POLICY.md"
PHASE8_SEAL = "docs/PHASE-8-CRYPTO-SEAL.md"
PHASE9_SEAL = "docs/PHASE-9-RAND-DRBG-SEAL.md"
PHASE8_LEDGER = "forensics/phase8-obligations.json"
PHASE9_LEDGER = "forensics/phase9-obligations.json"

INPUTS = [
    InputRef(name="divergence-register", path=REPO_ROOT / REGISTER,
             note="the prose register this table transcribes"),
    InputRef(name="phase-8-seal", path=REPO_ROOT / PHASE8_SEAL,
             note="says which of §5's entries are Phase 8's and how D-EC-2 and D372 read"),
    InputRef(name="phase-9-seal", path=REPO_ROOT / PHASE9_SEAL,
             note="says which trigger-bearing entries Phase 9 owns and what closed them"),
    InputRef(name="phase-8-obligations", path=REPO_ROOT / PHASE8_LEDGER,
             note="the Phase 8 ledger, whose open_in_this_stratum is what a freeing row would move"),
    InputRef(name="phase-9-obligations", path=REPO_ROOT / PHASE9_LEDGER,
             note="the Phase 9 ledger, whose open_in_this_stratum is what a freeing row would move"),
]

# The four dispositions, in the order the vocabulary is stated. A row's `disposition`
# must be one of these; anything else is a typo the tool refuses rather than a value it
# copies through.
DISPOSITIONS = ("open", "fixed", "explicitly_deferred", "accepted_permanent_divergence")

# The stratum registry: `phase_state.py`'s `STRATA`, phases 0 through 21. Validating
# against the range rather than a bare integer means a row cannot name a phase that does
# not exist, which is the typo class the whole table exists to make impossible.
PHASE_NUMBERS = set(range(22))

# What a `fixed` row's evidence must look like: a repository path with a known extension,
# or a court id. The rule is deliberately about the *shape* of the evidence and not its
# content -- the point is that "fixed" may not be asserted bare, and a court id is as good
# a citation as a file when the court is the evidence.
EVIDENCE = re.compile(
    r"(?:[\w.-]+/)*[\w.-]+\.(?:rs|c|h|md|json)\b"  # a file, e.g. src/bn/gf2m.rs
    r"|\bRT-[A-Z0-9-]+\b"                          # a runtime court, e.g. RT-CIPHER
    r"|\bCT-[A-Z0-9-]+\b"                          # a correctness court, e.g. CT-DSA
)


class Row(NamedTuple):
    """One register entry, transcribed. Deliberately data: the rule reads the table.

    `blocking` is not a field here on purpose. It is computed from `trigger_satisfied`
    and `disposition` when the artefact is rendered, so it cannot be typed by hand and
    cannot disagree with the two fields it is a function of.
    """

    id: str
    originating_phase: int
    trigger_phase: int
    current_owner: int
    trigger_condition: str
    trigger_satisfied: bool
    disposition: str
    evidence: str
    note: str


# The table. Nine of these are the register's `**Trigger:**` entries; the tenth,
# `D-GF2M-1`, states its closure condition in prose rather than under that label
# ("closes by adding the blinding when RAND exists") and is included because it was
# discharged in the same pass and is owed by the same stratum as the ninth.
#
# Field meanings, so a later editor does not have to guess:
#   originating_phase  the stratum whose subject code the entry concerns (the seal that
#                      lists the entry).
#   trigger_phase      the stratum the trigger phrase names, i.e. the one that will fire.
#   current_owner      the phase that owns the closure (the trigger phase when the work
#                      is future, the originating phase when it has landed).
OBLIGATIONS: list[Row] = [
    # -- Phase 9 discharged two of these in the working tree -------------------------
    Row(
        id="D-GF2M-1",
        originating_phase=5,
        trigger_phase=9,
        current_owner=9,
        trigger_condition=(
            "the Phase 9 RAND landing that makes the authority's blinding constructible: "
            "`BN_priv_rand_ex` exists, so `BN_GF2m_mod_inv` can draw `b`"
        ),
        trigger_satisfied=True,
        disposition="fixed",
        evidence=(
            "src/bn/gf2m.rs (BN_GF2m_mod_inv, the blinding at :643-712, and the "
            "`mod_inv_vartime` helper); the unit test "
            "`the_blinded_inverse_is_still_the_inverse`; RT-BN"
        ),
        note=(
            "The heading reads `-- **CLOSED**` and the entry's own `- **Closed:**` paragraph "
            "records the construction: `BN_priv_rand_ex(b, numbits - 1, BN_RAND_TOP_ANY, "
            "BN_RAND_BOTTOM_ANY, 0, ctx)` retrying while `b` is zero, `r := a*b`, a vartime "
            "inversion and a multiply by `b`, routed through `BN_GF2m_mod_mul`. The value, "
            "return class and error behaviour are unchanged (a field inverse is unique) and "
            "`OBL-GF2M-INV-BLINDING` is discharged; the unit test pins `a * a^-1 == 1`."
        ),
    ),
    Row(
        id="D-CBCHMAC-MULTIBLOCK-ENC-1",
        originating_phase=8,
        trigger_phase=9,
        current_owner=9,
        trigger_condition=(
            "Phase 9's first commit that lands `crypto/rand/`, which supplies the IVs the "
            "multiblock encrypt parameter draws through `RAND_bytes_ex`"
        ),
        trigger_satisfied=True,
        disposition="fixed",
        evidence=(
            "src/provider/cipher.rs (tls1_multi_block_encrypt_sha1/_sha256, drawing the "
            "IVs through `RAND_bytes_ex`); courts/phase8/rt_cipher_probe.c (the "
            "`cbchmac.*.mbenc` arm); RT-CIPHER"
        ),
        note=(
            "The heading reads `-- **CLOSED**`; the entry's `- **Closed:**` paragraph records "
            "the authority's two `tls1_multi_block_encrypt` bodies in `src/provider/cipher.rs` "
            "and the new `RT-CIPHER` arm, which observes `mbenc=1`, the packed length (5204 "
            "SHA-1 / 5268 SHA-256 at 5000 bytes), the four record headers and a round trip. "
            "The IV bytes are not compared -- no two machines draw the same ones."
        ),
    ),
    # -- Phase 8's method-object divergences, all repaired --------------------------
    Row(
        id="D-PKEY-AMETH-1",
        originating_phase=8,
        trigger_phase=8,
        current_owner=8,
        trigger_condition=(
            "Phase 8's first commit that lands an `EVP_PKEY_ASN1_METHOD` object, making "
            "`pkey_set_type`'s `if (ameth != NULL)` arm reachable"
        ),
        trigger_satisfied=True,
        disposition="fixed",
        evidence=(
            "src/evp/pkey_asn1.rs (STANDARD_METHODS, the authority's fifteen rows); "
            "src/evp/keymgmt_lib.rs (evp_keymgmt_util_assign_pkey/_copy call the public "
            "EVP_PKEY_set_type_by_keymgmt, so the name walk runs); src/evp/pkey.rs; "
            "RT-KEYFORMAT; docs/DECISIONS.md D353"
        ),
        note=(
            "Superseded by D-PKEY-AMETH-3 for the table, and closed on it: the 8.8 landing D353 "
            "populated `standard_methods[]` and D372 landed the four ECX rows. But the table alone "
            "was **not** sufficient. The observable stayed owed because "
            "`evp_keymgmt_util_assign_pkey`/`_copy` called a crate-local "
            "`evp_pkey_set_type_by_keymgmt` that passed a NULL `str` and skipped the name walk, so "
            "a provider key named `\"RSA\"`/`\"EC\"`/... stayed `EVP_PKEY_KEYMGMT`. D438 observed "
            "it and `RT-KEYFORMAT` measured it (`EVP_PKEY_get_id` answers 6/116/408 on the "
            "authority against `EVP_PKEY_KEYMGMT` (-1) here; `EVP_PKEY_get_base_id` 6/116/408 "
            "against `NID_undef` 0). Both call sites now call the public "
            "`EVP_PKEY_set_type_by_keymgmt` exactly as `crypto/evp/keymgmt_lib.c:64`/`:505` do, "
            "the helper is removed, and `RT-KEYFORMAT` passes 342 observations with zero "
            "residuals. The Phase 8 seal §5 records it under `D-PKEY-AMETH-1, -2, superseded by -3, "
            "which D372 supersedes in turn ... Every one is closed`."
        ),
    ),
    Row(
        id="D-PKEY-AMETH-3",
        originating_phase=8,
        trigger_phase=8,
        current_owner=8,
        trigger_condition=(
            "the slice that lands `crypto/ec/ecx_meth.c` and the ~9,000 lines its callbacks "
            "name, at which point the four rows are appended to both standard_methods[] tables"
        ),
        trigger_satisfied=True,
        disposition="fixed",
        evidence=(
            "src/ec/ecx_meth.rs; src/evp/pkey_asn1.rs (STANDARD_METHODS, 15 rows); "
            "src/evp/pkey_ctx.rs (PMETH_STANDARD_METHODS, 10 rows); src/evp/keymgmt_lib.rs (the "
            "name walk its provider-key-typing observable needs); docs/DECISIONS.md D372"
        ),
        note=(
            "Superseded by D372 (the entry's own quote says so), which landed the ECX chain; "
            "`EVP_PKEY_asn1_get_count` now answers 15 and `EVP_PKEY_meth_get_count` 10, "
            "`EVP_PKEY_asn1_find`/`_find_str` answer the four ECX objects and `EVP_PKEY_type` "
            "their four NIDs. The provider-key-typing observable it also names -- a keymgmt named "
            "`\"X25519\"`/`\"X448\"`/`\"ED25519\"`/`\"ED448\"` taking the legacy NID through "
            "`pkey_set_type` -- additionally required `evp_keymgmt_util_assign_pkey`/`_copy` to "
            "call the public `EVP_PKEY_set_type_by_keymgmt` rather than a crate-local NULL-`str` "
            "helper; that call site was repaired with D-PKEY-AMETH-1 and `RT-KEYFORMAT` measures "
            "it. The Phase 8 seal §5: `D372 landed the ECX chain and the register's third entry "
            "retires with it. Every one is closed`."
        ),
    ),
    # -- Phase 8's two standing narrowings ------------------------------------------
    Row(
        id="D-EC-1",
        originating_phase=8,
        trigger_phase=8,
        current_owner=8,
        trigger_condition=(
            "the slice that lands `ec_key.c`, `ecdh_ossl.c` and `ecdsa_ossl.c`, at which point "
            "the method column is written"
        ),
        trigger_satisfied=True,
        disposition="accepted_permanent_divergence",
        evidence=(
            "docs/SECURITY_DIVERGENCE_POLICY.md D-EC-2 (which supersedes it); "
            "forensics/prerequisites.json (src/ec/curve.rs, class `modelled_differently`)"
        ),
        note=(
            "Superseded by D-EC-2, and the entry records the shape of the supersession itself: "
            "`That slice landed in D340 and the trigger fired the other way: the column is "
            "written, its one non-NULL row is resolved to EC_GFp_simple_method, and the "
            "divergence is recorded rather than removed`. The divergence therefore persists as "
            "D-EC-2, which is why this row is not `fixed`; keeping it as its own row records "
            "that the trigger fired and the answer changed shape rather than disappeared."
        ),
    ),
    Row(
        id="D-EC-2",
        originating_phase=8,
        trigger_phase=8,
        current_owner=8,
        trigger_condition=(
            "the slice that supplies a construction for the perlasm unit "
            "(`crypto/ec/ecp_nistz256.c`), at which point `curve_list_method` answers "
            "`EC_GFp_nistz256_method`"
        ),
        trigger_satisfied=False,
        disposition="accepted_permanent_divergence",
        evidence=(
            "src/ec/curve.rs (curve_list_method); forensics/prerequisites.json "
            "(crypto/ec/ecp_nistz256.c, class `modelled_differently`, `covers` empty); "
            "docs/PHASE-8-CRYPTO-SEAL.md §5-§6"
        ),
        note=(
            "The trigger names no future stratum; the register records the divergence as "
            "`neither transcribable nor inventable` because every field operation is "
            "`ecp_nistz256-x86_64.s` with no `#else` arm, and D274's perlasm rule does not reach "
            "it either -- a Montgomery representation is observable through every subsequent "
            "multiplication. The Phase 8 seal §6 states it as `the standing consequence: where "
            "this authority's implementation is perlasm, this crate's is a portable "
            "reconstruction`. That is a deliberate permanent narrowing, and `prerequisites.json` "
            "carries it machine-readably as `modelled_differently` with empty `covers`, so it is "
            "recorded rather than left `open` for a stratum that does not exist."
        ),
    ),
    Row(
        id="D-CBCHMAC-MAXBUFSZ-ASSERT-1",
        originating_phase=8,
        trigger_phase=8,
        current_owner=8,
        trigger_condition=(
            "none planned: this is a permanent, deliberate safety divergence"
        ),
        trigger_satisfied=False,
        disposition="accepted_permanent_divergence",
        evidence=(
            "courts/phase8/rt_cipher_probe.c (the `cbchmac.*.g.maxbufsz` arm); "
            "docs/PHASE-8-CRYPTO-SEAL.md §5"
        ),
        note=(
            "The register's trigger is `none planned ... If a caller needs parity with the "
            "abort, that is docs/DECISIONS.md D276's to revisit, not an arm's`. The authority "
            "aborts (`cipher_aes_cbc_hmac_sha1_hw.c:701`, exit 134) before `maxsndfrag` is set; "
            "the crate computes 53. Reproducing a deliberate `abort()` would turn a caller's "
            "diagnostic into a denial of service, and the Phase 8 seal §5 agrees: `This one is "
            "permanent and deliberate: it is a safety divergence, not a gap`."
        ),
    ),
    # -- Phase 7's boundary entries whose triggers name future strata ----------------
    Row(
        id="D-PBE-PKCS12-KEYGEN-1",
        originating_phase=7,
        trigger_phase=10,
        current_owner=10,
        trigger_condition=(
            "Phase 10's first commit that lands `crypto/pkcs12/p12_crpt.c`, which supplies the "
            "two `PKCS12_PBE_keyivgen` function addresses the six rows lack"
        ),
        trigger_satisfied=True,
        disposition="fixed",
        evidence=(
            "src/pkcs12/p12_crpt.rs (PKCS12_PBE_keyivgen/_ex, transcribed against "
            "crypto/pkcs12/p12_crpt.c with its three raises); src/evp/evp_pbe.rs (the six "
            "BUILTIN_PBE rows now carry both addresses); courts/phase10/rt_pkcs12_probe.c "
            "(the `pbe.find.04`..`pbe.find.09` arms); RT-PKCS12"
        ),
        note=(
            "10.4 landed `crypto/pkcs12/p12_crpt.c`, which is this row's trigger, so the six "
            "`builtin_pbe[]` rows take both `PKCS12_PBE_keyivgen` addresses and "
            "`EVP_PBE_find`/`_ex` answer 1 with both keygen out-parameters **non-NULL**. What "
            "was a contents gap in two columns is now the authority's table. `RT-PKCS12` drives "
            "all six NIDs through `EVP_PBE_find_ex` and prints the return code, the type, the "
            "NID and both presence answers, which is the measurement `RT-EVP-PBE` held back "
            "with a marker while the two libraries differed. The heading reads "
            "`-- **CLOSED**`. Nothing was stubbed; the guard in `EVP_PBE_CipherInit_ex` still "
            "covers the eighteen PRF rows, and the six PKCS#12 rows stop taking it."
        ),
    ),
    Row(
        id="D-EVP-CIPHER-LEGACY-NID-1",
        originating_phase=7,
        trigger_phase=13,
        current_owner=13,
        trigger_condition=(
            "Phase 13's first legacy cipher wrapper, which populates the `OBJ_NAME` table "
            "`set_legacy_nid` searches -- so a fetched provider cipher's legacy NID becomes real"
        ),
        trigger_satisfied=False,
        disposition="open",
        evidence="RT-EVP-PBE (the `pbe.cipher_nid.legacy` marker)",
        note=(
            "The trigger phrase names Phase 13, which is not yet `complete`, so this row may be "
            "`open`. `evp_cipher_from_algorithm` calls `set_legacy_nid`, whose code landed in "
            "7.3b; what it searches is the legacy wrappers' table, which is Phase 13's and "
            "empty, so `EVP_CIPHER_get_nid` answers `NID_undef` (0) where the authority answers "
            "31 (`NID_des_cbc`)."
        ),
    ),
    # -- Phase 8's decoder boundary --------------------------------------------------
    Row(
        id="D-DECODER-ABSENT-1",
        originating_phase=8,
        trigger_phase=10,
        current_owner=10,
        trigger_condition=(
            "the slice that supplies a provider decoder -- the DER/PEM decoder rows and the "
            "keymgmt rows they construct into"
        ),
        trigger_satisfied=False,
        disposition="open",
        evidence="courts/phase8/rt_pubkey_probe.c (RT-PUBKEY)",
        note=(
            "Recorded by D369, and the trigger phrase names Phase 10, which is not yet "
            "`complete`, so this row may be `open`. The crate's decoder context carries no "
            "instances, so `d2i_PUBKEY` answers NULL for a decodable input and "
            "`pem_read_bio_key_decoder` returns NULL after its first failed walk; the only "
            "observable inside the shared path is the queue record. The entry retires with the "
            "provider decoder that lands the rows."
        ),
    ),
]


def validate(rows: list[Row]) -> list[str]:
    """The table's own fail-closed rules. Every problem names the row it is about."""
    problems: list[str] = []
    seen: set[str] = set()
    for r in rows:
        if not r.id.strip():
            problems.append("<unnamed row>: `id` is empty")
            continue
        if r.id in seen:
            problems.append(f"{r.id}: duplicate `id`")
        seen.add(r.id)

        for field in ("originating_phase", "trigger_phase", "current_owner"):
            value = getattr(r, field)
            if value not in PHASE_NUMBERS:
                problems.append(
                    f"{r.id}: `{field}` is {value!r}, which is not a phase in the registry "
                    f"({min(PHASE_NUMBERS)}..{max(PHASE_NUMBERS)})"
                )
        if r.disposition not in DISPOSITIONS:
            problems.append(
                f"{r.id}: `disposition` is {r.disposition!r}, which is not one of "
                f"{list(DISPOSITIONS)}"
            )
        if not r.trigger_condition.strip():
            problems.append(f"{r.id}: `trigger_condition` is empty")
        if r.disposition == "fixed" and not EVIDENCE.search(r.evidence):
            problems.append(
                f"{r.id}: a `fixed` row must name its evidence (a file or a court), but "
                f"`evidence` is {r.evidence!r}"
            )
        if r.disposition == "explicitly_deferred":
            if r.current_owner <= r.originating_phase:
                problems.append(
                    f"{r.id}: an `explicitly_deferred` row must name the later phase that "
                    f"owns the closure in `current_owner` (got {r.current_owner!r} against "
                    f"`originating_phase` {r.originating_phase!r})"
                )
            if not r.note.strip():
                problems.append(
                    f"{r.id}: an `explicitly_deferred` row must give its reason in `note`"
                )
    return problems


def build() -> dict:
    """Render the artefact from the table, deriving `blocking` rather than reading it."""
    rows: list[dict] = []
    for r in OBLIGATIONS:
        row = dict(r._asdict())
        # Derived, never typed: the row blocks its own `current_owner` exactly when the
        # trigger has fired and the disposition is still `open`. `phase_state.py` applies
        # the same test per stratum (`current_owner == phase`), which is the same
        # predicate scoped to the stratum being asked about.
        row["blocking"] = bool(r.trigger_satisfied and r.disposition == "open")
        rows.append(row)

    by_disposition: dict[str, int] = {}
    for row in rows:
        by_disposition[row["disposition"]] = by_disposition.get(row["disposition"], 0) + 1

    body = {
        "dispositions": list(DISPOSITIONS),
        "rule": (
            "an obligation blocks its `current_owner` when its trigger has fired "
            "(`trigger_satisfied`) and its `disposition` is still `open`; "
            "`phase_state.py` applies that test to each stratum"
        ),
        "counts": {
            "rows": len(rows),
            "blocking": sum(1 for row in rows if row["blocking"]),
            "by_disposition": by_disposition,
        },
        "rows": rows,
    }
    doc = envelope("divergence-obligations", GENERATOR, INPUTS, body)
    doc["body_hash"] = content_hash(body)
    return doc


def render(doc: dict) -> str:
    """Byte-for-byte what `atlas_common.write_json` writes, for `--check` to compare."""
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="do not write; fail if the artefact has drifted from the table")
    args = ap.parse_args(argv)

    problems = validate(OBLIGATIONS)
    if problems:
        print("[divergence-obligations] the table is invalid, so nothing was rendered:",
              file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    doc = build()
    text = render(doc)

    if args.check:
        if not OUT.is_file():
            print(f"[divergence-obligations] {rel(OUT)} is absent; run "
                  f"`python3 forensics/tools/divergence_obligations.py` to write it",
                  file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8") != text:
            print(f"[divergence-obligations] {rel(OUT)} has drifted from the table; run "
                  f"`python3 forensics/tools/divergence_obligations.py`", file=sys.stderr)
            return 1
        print(f"[divergence-obligations] ok: {len(OBLIGATIONS)} row(s) match the table "
              f"({body_count(doc)} blocking)")
        return 0

    write_json(OUT, doc)
    body = doc["body"]
    print(f"[divergence-obligations] wrote {rel(OUT)}: {body['counts']['rows']} row(s), "
          f"{body['counts']['blocking']} blocking, by disposition "
          f"{body['counts']['by_disposition']}")
    return 0


def body_count(doc: dict) -> int:
    return doc["body"]["counts"]["blocking"]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
