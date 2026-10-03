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

What a row is, and what `trigger_satisfied` and `blocking` are not
-----------------------------------------------------------------
A row's fields are the register entry's own: `id`, `originating_phase`,
`trigger_phase`, `current_owner`, `trigger_condition`, `trigger_basis`,
`trigger_predicate`, `adjudication`, `disposition`, `evidence`, `note`. The trigger's
*state* is not a hand-typed boolean either. `trigger_basis` says how it is decided --
`predicate` when a named predicate reads generated evidence, `manual` when it is a human
judgement -- and the rendered `trigger_satisfied` is derived from that: the predicate's
answer for a `predicate` row, and `null` for a `manual` row, because no artefact decides
it. `blocking` is likewise **derived, never typed**: a row blocks *its own* `current_owner`
when its disposition is `open` and either its trigger has materially fired or it is a
`manual` row with no `adjudication`. So an open `manual` row blocks its owner **until an
`adjudication` records, with evidence, why the trigger has not fired** -- which is
deliberately fail-closed, because a hand-typed trigger state is exactly what let
`D-DECODER-ABSENT-1` read `false` while its trigger had fired.

`disposition` is one of four values, and the vocabulary is the whole point:

  * `open` -- owed and not yet done. Only a stratum that is not `complete` may own one.
  * `fixed` -- discharged; `evidence` must name the file or court that shows it.
  * `explicitly_deferred` -- owed, but handed to the later phase named in
    `current_owner`, with the reason in `note`.
  * `accepted_permanent_divergence` -- a deliberate, recorded narrowing that will not be
    removed (an authority fault not reproduced, or a perlasm-only construction the crate
    answers portably).

The tool fails closed on the table itself: unique ids, phase numbers that exist, a
disposition from the vocabulary, a `trigger_basis` from the vocabulary, a `predicate` row
that names a predicate the `PREDICATES` table holds (and a `manual` row that names none), a
`fixed` row that names its evidence, and an `explicitly_deferred` row that names a later
owner and gives a reason. A violation exits nonzero with the row named.

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
from typing import Callable, NamedTuple

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
# The provider-algorithm census (`forensics/atlas/provider-algorithms.json`), the generated
# artefact a trigger predicate reads. It records every provider registration row of every admitted
# provider with an `operation` and an `implementation_state`, so a trigger whose condition is "the
# provider decoder layer lands" is decidable from evidence rather than typed.
PROVIDER_ALGORITHMS = "forensics/atlas/provider-algorithms.json"

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
    InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDER_ALGORITHMS,
             note="the census the decoder predicate reads: its OSSL_OP_DECODER rows and their "
                  "implementation_state"),
]

# The four dispositions, in the order the vocabulary is stated. A row's `disposition`
# must be one of these; anything else is a typo the tool refuses rather than a value it
# copies through.
DISPOSITIONS = ("open", "fixed", "explicitly_deferred", "accepted_permanent_divergence")

# The trigger bases, in the order the vocabulary is stated. A row's `trigger_basis` must be
# one of these; anything else is a typo the tool refuses. `predicate` means the trigger is decided
# by a named function that reads generated evidence; `manual` means it is a human judgement that no
# artefact decides, so its `trigger_satisfied` is `null` and an `adjudication` is what keeps it from
# blocking.
TRIGGER_BASES = ("predicate", "manual")

# The phase states a manual adjudication may rest on. A manual adjudication is a human judgement,
# but the *facts* it cites are frequently machine facts -- "Phase N is not-started" is the one
# D-EVP-CIPHER-LEGACY-NID-1 cited. A manual row with a nonempty `adjudication` must name the phase
# it rests on in `adjudication_phase` and the state it requires in `adjudication_requires`, so that
# `phase_state.py` can re-evaluate the predicate against the freshly derived states on every run
# and block the owner when the fact no longer holds, rather than letting the prose adjudication
# keep the row open-but-nonblocking forever. This is the vocabulary those states come from, and it
# is exactly `phase_state.py`'s own three states.
ADJUDICATION_STATES = ("not-started", "in-progress", "complete")

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


# The trigger predicates, by name. A `predicate` row names one of these; each reads generated
# evidence and returns `(satisfied_or_None, observation)`, where the observation names the file it
# read and the count it observed, or says why the trigger is undecidable.


def predicate_provider_decoders_implemented() -> tuple[bool | None, str]:
    """Satisfied when the census records every `OSSL_OP_DECODER` row as implemented.

    `D-DECODER-ABSENT-1`'s trigger is the provider decoder layer whose absence the entry records,
    and the census is the generated artefact that says whether that layer has landed: it carries
    one row per provider registration row with an `implementation_state`, and the decoder rows are
    the `OSSL_OP_DECODER` rows. The predicate is satisfied when the census carries at least one
    decoder row and every one of them is `implemented`. A census that is absent cannot decide the
    trigger and returns `None` with that reason rather than a guess.
    """
    path = REPO_ROOT / PROVIDER_ALGORITHMS
    if not path.is_file():
        return None, (
            f"{PROVIDER_ALGORITHMS} is absent, so the OSSL_OP_DECODER row count cannot be "
            f"read and the trigger is undecidable")
    doc = json.loads(path.read_text(encoding="utf-8"))
    decoders = [r for r in doc["body"]["rows"] if r["operation"] == "OSSL_OP_DECODER"]
    implemented = [r for r in decoders if r["implementation_state"] == "implemented"]
    return (
        bool(decoders) and len(implemented) == len(decoders),
        f"read {PROVIDER_ALGORITHMS}: {len(implemented)} of {len(decoders)} "
        f"OSSL_OP_DECODER row(s) are implemented",
    )


# The predicates by name. A `predicate` row names one of these keys in `trigger_predicate`.
PREDICATES: dict[str, Callable[[], tuple[bool | None, str]]] = {
    "provider-decoder-rows-implemented": predicate_provider_decoders_implemented,
}

# A `manual` row has no predicate to read, so there is no file and no count to name. The reason
# the trigger has not fired, when one is given, is the row's `adjudication`.
MANUAL_OBSERVATION = (
    "manual: the trigger is a human judgement and is not machine-observable, so "
    "`trigger_satisfied` is null; an `adjudication` is what records why it has not fired"
)


class Row(NamedTuple):
    """One register entry, transcribed. Deliberately data: the rule reads the table.

    Neither `trigger_satisfied` nor `blocking` is a field here on purpose. The trigger state is
    derived from `trigger_basis`/`trigger_predicate` and the predicate it names (or is `null` for a
    `manual` row), and `blocking` is computed from the rendered row when the artefact is written,
    so neither can be typed by hand and neither can disagree with the fields it is a function of.
    """

    id: str
    originating_phase: int
    trigger_phase: int
    current_owner: int
    trigger_condition: str
    trigger_basis: str
    trigger_predicate: str
    adjudication: str
    disposition: str
    evidence: str
    note: str
    # The machine fact a manual adjudication rests on: the phase whose derived state it cites and
    # the state it requires for the adjudication to remain true. `-1`/`""` mean "no machine fact"
    # (every non-manual row and every manual row with no adjudication). `phase_state.py`
    # re-evaluates `(adjudication_phase, adjudication_requires)` against the derived states and the
    # row blocks its owner the moment the derived state is anything else -- which is what makes a
    # stale manual adjudication fail closed instead of reading open-but-nonblocking.
    adjudication_phase: int = -1
    adjudication_requires: str = ""


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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
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
        trigger_basis="manual",
        trigger_predicate="",
        adjudication="",
        disposition="fixed",
        evidence=(
            "src/evp/c_allc.rs (openssl_add_all_ciphers_int, c_allc.c's rows and aliases); "
            "src/evp/c_alld.rs; src/runtime/init.rs (add_all_legacy_methods calls both for "
            "OPENSSL_INIT_ADD_ALL_CIPHERS/DIGESTS); src/context/namemap.rs (ossl_namemap_stored's "
            "first-use pre-population runs OPENSSL_init_crypto(ADD_ALL_CIPHERS|ADD_ALL_DIGESTS), "
            "so the table is filled on the fetch path before set_legacy_nid); "
            "courts/phase13/rt_evp_legacy_probe.c (the compared `<name>.byname` arms); "
            "courts/phase7/rt_evp_pbe_probe.c (the compared `pbe.alg_add.methods_nids` arm); "
            "RT-EVP-LEGACY; RT-EVP-PBE; docs/DECISIONS.md D526"
        ),
        note=(
            "The trigger fired when Phase 13 landed the legacy wrappers, and the last missing "
            "piece was the registration, not a wrapper: `src/runtime/init.rs`'s "
            "`add_all_legacy_methods` was `{ let _ = opts; }`, so `OPENSSL_init_crypto`'s two "
            "adder bits registered nothing and the `OBJ_NAME` table `set_legacy_nid` searches "
            "stayed empty. 13.6 transcribes `crypto/evp/c_allc.c`/`c_alld.c` and wires both bits "
            "to it; `ossl_namemap_stored` runs the authority's own first-use pre-population, "
            "whose `OPENSSL_init_crypto(ADD_ALL_CIPHERS|ADD_ALL_DIGESTS)` call fills the table on "
            "the fetch path too. `EVP_CIPHER_get_nid` on a fetched `DES-CBC` now answers "
            "`NID_des_cbc` (31) as the authority does, `EVP_get_cipherbyname` and "
            "`EVP_get_digestbyname` resolve, and the two courts compare the values instead of a "
            "marker. The row is kept, not deleted: it is the record that the divergence existed "
            "and was closed. This is the correction D526 records, and the stale manual "
            "adjudication it exposed is the general bug D527 closes."
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
        trigger_basis="predicate",
        trigger_predicate="provider-decoder-rows-implemented",
        adjudication="",
        disposition="fixed",
        evidence=(
            "src/provider/decode_der2key.rs (DEFLT_DECODERS/BASE_DECODERS, the decode_der2key "
            "rows and their two front doors); src/provider/decode_epki2pki.rs; "
            "src/provider/decode_pem2der.rs; src/provider/decode_spki2typespki.rs; "
            "src/provider/decode_msblob2key.rs; src/provider/decode_pvk2key.rs; "
            "courts/phase10/rt_codec_probe.c; RT-CODEC"
        ),
        note=(
            "Recorded by D369 while the provider decoder layer was absent: the crate's decoder "
            "context carried no instances, `d2i_PUBKEY` answered NULL for a decodable input and "
            "`pem_read_bio_key_decoder` returned NULL after its first failed walk. Phase 10 "
            "landed the layer -- the `decode_der2key.c` rows and their two front doors "
            "(`src/provider/decode_der2key.rs`), the `EncryptedPrivateKeyInfo` decoder "
            "(`src/provider/decode_epki2pki.rs`), `decode_pem2der.c` "
            "(`src/provider/decode_pem2der.rs`), `decode_spki2typespki.c` "
            "(`src/provider/decode_spki2typespki.rs`) and the `msblob`/`pvk` decoders "
            "(`src/provider/decode_msblob2key.rs`, `src/provider/decode_pvk2key.rs`) -- so the "
            "census `forensics/atlas/provider-algorithms.json` records every `OSSL_OP_DECODER` "
            "row `implemented`, and this row's trigger is now a predicate over that count rather "
            "than a hand-typed boolean. `RT-CODEC` (`courts/phase10/rt_codec_probe.c`) is the "
            "behavioural measurement of those decoder rows, and D450 measured the queue-count "
            "observable `RT-PUBKEY` carries. **D474's Phase 10 seal §5 named this row a "
            "retirement candidate** (`the trigger condition has been met and the machine row "
            "still reads otherwise`) and its §9 said the register row `should be removed with "
            "the boundary it records`; the row is retired here -- kept rather than deleted, as "
            "its siblings are, and marked `CLOSED` in `docs/SECURITY_DIVERGENCE_POLICY.md`."
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
        if r.trigger_basis not in TRIGGER_BASES:
            problems.append(
                f"{r.id}: `trigger_basis` is {r.trigger_basis!r}, which is not one of "
                f"{list(TRIGGER_BASES)}"
            )
        elif r.trigger_basis == "predicate":
            if r.trigger_predicate not in PREDICATES:
                problems.append(
                    f"{r.id}: `trigger_basis` is `predicate` but `trigger_predicate` is "
                    f"{r.trigger_predicate!r}, which is not in PREDICATES "
                    f"{sorted(PREDICATES)}"
                )
        elif r.trigger_predicate:
            problems.append(
                f"{r.id}: `trigger_basis` is `manual`, so `trigger_predicate` must be empty, "
                f"but it is {r.trigger_predicate!r}"
            )
        # A manual adjudication is a machine-checked claim: the fact it rests on must be named, so
        # `phase_state.py` can re-evaluate it. A manual row with no adjudication must name none.
        if r.trigger_basis == "manual" and r.adjudication.strip():
            if r.adjudication_phase not in PHASE_NUMBERS:
                problems.append(
                    f"{r.id}: its manual `adjudication` must name the phase it rests on in "
                    f"`adjudication_phase`, but that is {r.adjudication_phase!r}"
                )
            if r.adjudication_requires not in ADJUDICATION_STATES:
                problems.append(
                    f"{r.id}: its manual `adjudication` must name the state it requires in "
                    f"`adjudication_requires` (one of {list(ADJUDICATION_STATES)}), but that is "
                    f"{r.adjudication_requires!r}"
                )
        elif r.adjudication_phase != -1 or r.adjudication_requires:
            problems.append(
                f"{r.id}: `adjudication_phase`/`adjudication_requires` are only for a manual row "
                f"with a nonempty `adjudication`, but they are {r.adjudication_phase!r}/"
                f"{r.adjudication_requires!r}"
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


def derive_blocking(row: dict) -> bool:
    """The register's one rule, derived from a rendered row rather than typed.

    A row blocks *its own* `current_owner` when its disposition is still `open` and its trigger
    has either materially fired (`trigger_satisfied is True`, which for a `predicate` row is its
    named predicate's answer) or is unobservable and unadjudicated (`trigger_basis` is `manual`
    with no `adjudication`). The manual clause is the fail-closed half: an open manual row is
    presumed fired until an `adjudication` records why it has not.

    **A manual adjudication must itself be machine-checked.** An adjudication that rests on a
    machine fact -- `adjudication_requires` names the state the cited `adjudication_phase` must be
    in -- is only as good as the fact, so the row blocks its owner the moment
    `adjudication_predicate_satisfied` is false. `phase_state.py` fills that field by
    re-evaluating `(adjudication_phase, adjudication_requires)` against the freshly derived states
    on every run; the generator leaves it `None`, because it runs before the states exist and
    must not read a stale `phase-state.json`. A manual row with no machine fact
    (`adjudication_predicate_satisfied` absent/`None`) keeps the pre-existing behaviour: a
    nonempty `adjudication` is enough to keep it from blocking.

    `phase_state.py` applies the same test scoped to the stratum being asked about
    (`current_owner == phase`), and its `--self-test` imports this function so a reconstructed row
    is judged by the real rule.
    """
    if row["disposition"] != "open":
        return False
    if row["trigger_satisfied"] is True:
        return True
    if row["trigger_basis"] != "manual":
        return False
    if not row.get("adjudication", "").strip():
        return True
    # A manual adjudication that rests on a machine fact blocks when that fact no longer holds.
    return row.get("adjudication_predicate_satisfied") is False


def build() -> dict:
    """Render the artefact from the table, deriving the trigger state and `blocking`.

    Neither `trigger_satisfied` nor `blocking` is typed by hand: the first is the named predicate's
    answer for a `predicate` row (and `None` for a `manual` row, whose trigger no artefact
    decides), and the second is `derive_blocking` over the rendered row.
    """
    rows: list[dict] = []
    for r in OBLIGATIONS:
        row = dict(r._asdict())
        if r.trigger_basis == "predicate":
            satisfied, observation = PREDICATES[r.trigger_predicate]()
            row["trigger_satisfied"] = satisfied
            row["adjudication_predicate_satisfied"] = None
        else:
            row["trigger_satisfied"] = None
            observation = MANUAL_OBSERVATION
            # Undecided here: `phase_state.py` re-evaluates the machine fact against the freshly
            # derived states. `None` keeps the artefact honest (the generator runs before the
            # states exist) and `derive_blocking` reads `is False`, so a `None` cannot block.
            row["adjudication_predicate_satisfied"] = None
        row["trigger_observation"] = observation
        # Derived, never typed: see `derive_blocking`.
        row["blocking"] = derive_blocking(row)
        rows.append(row)

    by_disposition: dict[str, int] = {}
    for row in rows:
        by_disposition[row["disposition"]] = by_disposition.get(row["disposition"], 0) + 1

    body = {
        "dispositions": list(DISPOSITIONS),
        "trigger_bases": list(TRIGGER_BASES),
        "rule": (
            "an obligation blocks its `current_owner` when its `disposition` is `open` and "
            "either its trigger has materially fired (`trigger_satisfied` is true, which a "
            "`trigger_basis: predicate` row derives from its named predicate's read of generated "
            "evidence) or it is a `trigger_basis: manual` row with no `adjudication` -- a manual "
            "row's `trigger_satisfied` is null because the trigger is not machine-observable, so "
            "an open manual row blocks its owner until an `adjudication` records, with evidence, "
            "why the trigger has not fired. An `adjudication` that rests on a machine fact names "
            "`adjudication_phase`/`adjudication_requires`, and `phase_state.py` re-evaluates that "
            "fact against the freshly derived states on every run: when the named phase's derived "
            "state is no longer the required one, `adjudication_predicate_satisfied` is false and "
            "the row blocks. Its own stale-fact behaviour is exercised by `phase_state.py "
            "--self-test`; `phase_state.py` applies that test to each stratum"
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
