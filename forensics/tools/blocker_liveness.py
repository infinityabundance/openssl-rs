#!/usr/bin/env python3
"""openssl-rs — the blocker-liveness checker: is a deferral's *reason* still true?

Why this exists
---------------
A deferral records that a symbol is absent because a name it needs is absent. For
a year of this project the machinery proved only half of that: that the deferred
symbol is **still absent**. `forensics/tools/phase7_obligations.py`'s
`BLOCKED_HANDOFFS` and `forensics/prerequisites.json`'s `deferrals` both do that,
and both fail-closed when the deferred name lands. What neither could see is the
mirror image: the deferred name stays absent, but the *blocker named in the reason
has already landed*, so the symbol is absent for a reason that is no longer true.

That is not hypothetical. D193 swept `EVP_PKEY_new_mac_key` into a group whose
prose named `evp_pkey_get_legacy` as the blocker. The symbol stayed absent and the
row stayed "valid" — while the actual blockers (`EVP_PKEY_CTX_new_id`, D186, and
the ctrl plane, D188) had already landed. A human reading the call chain found it
(D196); the machinery did not. With 244 deferrals in the sealed Phase 7 ledger
that is too much surface to leave to prose freshness.

What this module checks
-----------------------
A deferral is a *structured* claim: a symbol, the latest phase it is blocked on
(`binding_phase`), and the smallest set of `Blocker`s that carries the claim. Each
blocker names its authority unit, the definition line, its `kind`
(`exported`/`internal`/`type`) and the `owning_phase` — the stratum that lands it.
For every row, `check_row` proves:

1. **The blocker is real.** It resolves against the export defining-unit atlas,
   the internal-symbol atlas, or the typedef atlas. A name no record contains is a
   typo, not a reason.
2. **The blocker is currently absent** from the candidate. This is the invariant
   that was missing.
3. **Its `owning_phase` matches the record.** The export/typedef atlas, or the
   `forensics/prerequisites.json` deferral that lands it, decides the phase; a row
   that says "blocked on phase 8" while its blocker is phase 10 is a lie.
4. **If every blocker has landed, the deferral is invalid immediately**, with the
   landed names and the decision that landed them when the caller can supply them.
5. **If the binding phase is complete and a blocker is still absent**, that is the
   mirror-image failure: a sealed stratum that did not produce the name it owed.

A blocker declared only in a weak header (`types.h`) has no authority phase of its
own. It is accepted only when another blocker in the same row carries the row's
`binding_phase`, so the type's phase is inherited from a name that can be checked;
otherwise the row fails rather than asserting an unbacked phase.

The line is recorded evidence. It is verified against the authority tree only by
existence and range, because a macro-generated export (`d2i_X509_ALGOR` from
`IMPLEMENT_ASN1_FUNCTIONS`) does not appear at its own definition site and a
general C definition parser is out of scope.

Used by both mechanisms on purpose
-----------------------------------
`phase7_obligations.py` and `prerequisite_gate.py` share this module rather than
each growing a private copy: the checks are the same facts about the same atlases,
and two copies would be two things to keep true. See `docs/DECISIONS.md` D198.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import PRODUCTION_AUTHORITY, REPO_ROOT, resolve_authority  # noqa: E402

KIND_EXPORTED = "exported"
KIND_INTERNAL = "internal"
KIND_TYPE = "type"
BLOCKER_KINDS = (KIND_EXPORTED, KIND_INTERNAL, KIND_TYPE)

EXPORT_UNITS = "forensics/atlas/export-defining-units.json"
INTERNAL_SYMBOLS = "forensics/atlas/internal-symbols.json"
TYPEDEF_OWNERS = "forensics/atlas/typedef-owners.json"
IMPLEMENTED_SURFACE = "forensics/atlas/implemented-surface.json"
PREREQUISITES = "forensics/prerequisites.json"
PHASE_STATE = "forensics/phase-state.json"

# The definition forms the crate can introduce a name with. Kept in step with
# `prerequisite_gate.py`'s scanner by construction: that tool's `built` set is the
# same superset, and a name is "landed" for a blocker when either lens sees it.
_RUST_DEFS = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:unsafe[ \t]+)?"
    r'(?:extern[ \t]+"[^"]*"[ \t]+)?'
    r"(?:(?:fn|const|static|type|struct|enum|union|trait|mod)[ \t]+"
    r"|static[ \t]+mut[ \t]+|macro_rules![ \t]+)"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.M,
)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class Blocker:
    """A name whose absence is why a deferred symbol cannot be written yet."""

    name: str
    authority_unit: str
    line: int
    kind: str
    owning_phase: int


@dataclass(frozen=True)
class Resolved:
    """What the authority's own records say about a blocker name."""

    name: str
    kind: str
    units: tuple[str, ...]
    owner_phase: int | None
    phase_source: str | None
    landed: bool


@dataclass(frozen=True)
class BlockedHandoff:
    """One deferral: its symbols, the phase that retires it, and its blockers.

    `label` is what a failure message names first; an empty label falls back to the
    symbol list, so the literal tables do not have to restate it.
    """

    symbols: tuple[str, ...]
    binding_phase: int
    blocked_by: tuple[Blocker, ...]
    reason: str
    note: str = ""
    label: str = ""


def load_body(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["body"]


def crate_definitions(src_root: Path) -> set[str]:
    """Every name a Rust definition form under `src/` introduces.

    Comments are blanked but string literals are kept, because `extern "C" fn
    name(` is the form almost every export in this crate is written in.
    """
    out: set[str] = set()
    for path in sorted(src_root.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"//[^\n]*", "", text)
        text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
        out.update(_RUST_DEFS.findall(text))
    return out


class BlockerAtlas:
    """The three authority records a blocker can resolve against, plus liveness."""

    def __init__(
        self,
        *,
        exports: dict[str, tuple[str, int]],
        internals: dict[str, tuple[str, tuple[str, ...]]],
        types: dict[str, tuple[tuple[str, ...], int | None]],
        landing: dict[str, int],
        implemented: set[str],
        implemented_internal: set[str],
        crate_defs: set[str],
        authority_source: Path,
        known_units: set[str],
    ) -> None:
        self.authority_source = authority_source
        # Every authority translation unit any committed atlas knows about. The 21 legacy
        # primitive units are checked against this rather than against the source tree, so
        # the check is as strong in CI (which has no 55 MB authority checkout) as it is in
        # the court.
        self.known_units = known_units
        self._index: dict[str, Resolved] = {}

        def landed(name: str) -> bool:
            return (
                name in implemented
                or name in implemented_internal
                or name in crate_defs
            )

        for name, (unit, phase) in exports.items():
            self._declare(
                name,
                Resolved(name, KIND_EXPORTED, (unit,), landing.get(name, phase),
                         "prerequisites.json" if name in landing else "export-defining-units.json",
                         landed(name)),
            )
        for name, (units, phase) in types.items():
            self._declare(
                name,
                Resolved(name, KIND_TYPE, units, landing.get(name, phase),
                         "prerequisites.json" if name in landing else "typedef-owners.json",
                         landed(name)),
            )
        for name, (unit, declared) in internals.items():
            self._declare(
                name,
                Resolved(name, KIND_INTERNAL, (unit, *declared),
                         landing.get(name),
                         "prerequisites.json" if name in landing else None,
                         landed(name)),
            )

    def _declare(self, name: str, resolved: Resolved) -> None:
        # Exports are declared first and win a collision: an export's defining unit
        # is the thing a caller names, and the internal atlas is the wider net.
        self._index.setdefault(name, resolved)

    def resolve(self, name: str) -> Resolved | None:
        return self._index.get(name)

    def unit_is_known(self, unit: str) -> bool:
        """True when some authority translation unit any atlas records lives under `unit`."""
        prefix = unit.rstrip("/") + "/"
        return any(u.startswith(prefix) for u in self.known_units)

    @classmethod
    def from_repo(
        cls,
        *,
        repo_root: Path = REPO_ROOT,
        authority_source: Path | None = None,
        implemented: set[str] | None = None,
        implemented_internal: set[str] | None = None,
        crate_defs: set[str] | None = None,
    ) -> "BlockerAtlas":
        if authority_source is None:
            authority_source = resolve_authority(PRODUCTION_AUTHORITY).source
        surface = load_body(repo_root / IMPLEMENTED_SURFACE)
        if implemented is None:
            implemented = set(surface["libraries"]["libcrypto"]["implemented_symbols"])
        if implemented_internal is None:
            implemented_internal = set(surface["internal_symbols"]["c_style"])
        if crate_defs is None:
            crate_defs = crate_definitions(repo_root / "src")
        export_body = load_body(repo_root / EXPORT_UNITS)
        exports = {
            r["symbol"]: (r["translation_unit"], int(r["owner_phase"]))
            for r in export_body["records"]
            if r.get("owner_phase") is not None
        }
        internal_records = load_body(repo_root / INTERNAL_SYMBOLS)["records"]
        internals = {
            r["symbol"]: (r["translation_unit"], tuple(r.get("declared_in") or ()))
            for r in internal_records
        }
        known_units = set(export_body["by_translation_unit"].keys()) | {
            r["translation_unit"] for r in internal_records
        }
        types = {
            r["name"]: (tuple(r.get("defined_in") or ()), r.get("owner_phase"))
            for r in load_body(repo_root / TYPEDEF_OWNERS)["records"]
            if r.get("kind") == "typedef"
        }
        landing = {
            r["symbol"]: int(r["owner_phase"])
            for r in load_body(repo_root / PREREQUISITES)["deferrals"]
        }
        return cls(
            exports=exports,
            internals=internals,
            types=types,
            landing=landing,
            implemented=implemented,
            implemented_internal=implemented_internal,
            crate_defs=crate_defs,
            authority_source=authority_source,
            known_units=known_units,
        )


def blockers_from_json(raw: list[dict]) -> tuple[Blocker, ...]:
    return tuple(
        Blocker(
            name=r["name"],
            authority_unit=r["authority_unit"],
            line=int(r["line"]),
            kind=r["kind"],
            owning_phase=int(r["owning_phase"]),
        )
        for r in raw
    )


def blockers_to_json(blockers: tuple[Blocker, ...]) -> list[dict]:
    return [
        {
            "name": b.name,
            "authority_unit": b.authority_unit,
            "line": b.line,
            "kind": b.kind,
            "owning_phase": b.owning_phase,
        }
        for b in blockers
    ]


def _line_in_range(atlas: BlockerAtlas, unit: str, line: int) -> str | None:
    """None when the evidence file exists and the line is inside it, else why not.

    A `unit` is a translation unit's path (`crypto/evp/p_lib.c`) or a header's basename
    (`types.h`, as the typedef atlas records it); the latter is resolved against the
    installed include directories.

    The authority's source tree lives only in the court, so this check has two tiers: with
    the tree present it proves the line is inside the file, and with the tree absent
    (CI's `evidence_determinism`) it proves nothing and does not fail. The unit itself is
    checked against the committed atlases either way, so a wrong path is still caught.
    """
    if not atlas.authority_source.is_dir():
        return None
    candidates = [
        atlas.authority_source / unit,
        atlas.authority_source / "include" / "openssl" / unit,
        atlas.authority_source / "include" / "internal" / unit,
        atlas.authority_source / "include" / "crypto" / unit,
    ]
    path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        return f"{unit} is not in the authority tree"
    count = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    if not 1 <= line <= count:
        return f"{unit} has {count} lines, so line {line} cannot be a definition site"
    return None


def check_row(
    atlas: BlockerAtlas,
    claim: BlockedHandoff,
    *,
    phase_state: dict[int, str],
    landed_in: dict[str, str] | None = None,
) -> list[str]:
    """Every reason a row's blocker claim does not hold. Empty means it does."""
    landed_in = landed_in or {}
    label = claim.label or ", ".join(claim.symbols)
    msgs: list[str] = []
    if not claim.blocked_by:
        return [
            f"{label}: {', '.join(claim.symbols)} names no blocker, so the "
            f"deferral is prose again rather than a machine-checkable claim"
        ]

    resolved: list[Resolved] = []
    landed_names: list[str] = []
    absent_names: list[str] = []
    max_phase: int | None = None

    for b in claim.blocked_by:
        r = atlas.resolve(b.name)
        if r is None:
            msgs.append(
                f"{label}: {', '.join(claim.symbols)} names blocker {b.name!r}, "
                f"which is in no authority record (export-defining-units, "
                f"internal-symbols or typedef-owners); a blocker that no authority "
                f"record contains is a typo, not a reason"
            )
            continue
        resolved.append(r)
        if b.kind != r.kind:
            msgs.append(
                f"{label}: blocker {b.name} is recorded kind={b.kind!r} but the "
                f"authority resolves it as {r.kind!r}"
            )
        if b.authority_unit not in r.units:
            msgs.append(
                f"{label}: blocker {b.name} is recorded in {b.authority_unit}, "
                f"but the authority defines it in {' or '.join(r.units)}"
            )
        why = _line_in_range(atlas, b.authority_unit, b.line)
        if why is not None:
            msgs.append(
                f"{label}: blocker {b.name} cites {b.authority_unit}:{b.line}, "
                f"but {why}"
            )

        if r.owner_phase is None:
            if r.kind == KIND_TYPE:
                corroborated = any(
                    (ro := atlas.resolve(o.name)) is not None
                    and ro.owner_phase == claim.binding_phase
                    for o in claim.blocked_by
                    if o is not b
                )
                if b.owning_phase != claim.binding_phase or not corroborated:
                    msgs.append(
                        f"{label}: blocker {b.name} is a type declared only in a "
                        f"weak header ({', '.join(r.units)}), so it carries no authority "
                        f"phase of its own; its phase {b.owning_phase} is accepted only "
                        f"when another blocker carries the row's binding_phase "
                        f"{claim.binding_phase}"
                    )
            else:
                msgs.append(
                    f"{label}: blocker {b.name} ({r.kind}) has no owner phase in "
                    f"the atlases or in forensics/prerequisites.json, so the row's "
                    f"phase cannot be checked; record the stratum that lands it"
                )
        elif b.owning_phase != r.owner_phase:
            msgs.append(
                f"{label}: blocker {b.name} is recorded owning_phase="
                f"{b.owning_phase}, but {r.phase_source} lands it in phase "
                f"{r.owner_phase}"
            )

        max_phase = b.owning_phase if max_phase is None else max(max_phase, b.owning_phase)
        if r.landed:
            landed_names.append(b.name)
        else:
            absent_names.append(b.name)

    if max_phase is not None and claim.binding_phase != max_phase:
        msgs.append(
            f"{label}: binding_phase is {claim.binding_phase}, but its blockers' "
            f"latest phase is {max_phase}; the row says it is blocked on a stratum its "
            f"own blockers do not name"
        )

    # 4. Every blocker has landed -- the EVP_PKEY_new_mac_key case.
    if resolved and len(landed_names) == len(resolved):
        detail = ", ".join(
            f"{name} (phase {next(b.owning_phase for b in claim.blocked_by if b.name == name)}"
            + (f", landed in {landed_in[name]}" if name in landed_in else "")
            + ")"
            for name in landed_names
        )
        msgs.append(
            f"{label}: every blocker of {', '.join(claim.symbols)} has landed "
            f"({detail}); the deferral is invalid -- retire it rather than leave a "
            f"stale reason covering the name"
        )

    # 5. The binding stratum is complete but a blocker is still absent.
    state = phase_state.get(claim.binding_phase)
    if state == "complete" and absent_names:
        msgs.append(
            f"{label}: binding phase {claim.binding_phase} is complete, but "
            f"blocker {', '.join(absent_names)} is still absent from the candidate; a "
            f"completed stratum did not produce the name it was supposed to"
        )
    return msgs


def check_rows(
    atlas: BlockerAtlas,
    claims: list[BlockedHandoff],
    *,
    phase_state: dict[int, str],
    landed_in: dict[str, str] | None = None,
) -> list[str]:
    out: list[str] = []
    for claim in claims:
        out.extend(check_row(atlas, claim, phase_state=phase_state, landed_in=landed_in))
    return out


def phase_states(repo_root: Path = REPO_ROOT) -> dict[int, str]:
    return {
        int(r["phase"]): r["state"]
        for r in load_body(repo_root / PHASE_STATE)["phases"]
    }


# ---------------------------------------------------------------------------------------------
# The sensitivity control: a check that has never been seen to fail is not evidence.
#
# The row below is `EVP_PKEY_new_mac_key` as D193's group reason worded it, with the
# blockers its own body actually calls -- `EVP_PKEY_CTX_new_id` and
# `EVP_PKEY_CTX_set_mac_key`, named by D173 and D193's prose, landed by D186 and D188. The
# deferral stayed in the ledger and the symbol stayed absent for a reason that had stopped
# being true. `--self-test` runs the checker on exactly that row and refuses to pass unless
# the "every blocker has landed" finding comes back.
# ---------------------------------------------------------------------------------------------

SELF_TEST_ROW = BlockedHandoff(
    label="BLOCKED_HANDOFFS (reconstructed: D193's EVP_PKEY_new_mac_key row, as D196 found it)",
    symbols=("EVP_PKEY_new_mac_key",),
    binding_phase=7,
    reason=(
        "reconstructed from D193's group reason: the symbol was swept into the twelve-name "
        "legacy-accessor group, but its own body calls EVP_PKEY_CTX_new_id and "
        "EVP_PKEY_CTX_set_mac_key, which landed in D186 and D188"
    ),
    blocked_by=(
        Blocker(
            name="EVP_PKEY_CTX_new_id",
            authority_unit="crypto/evp/pmeth_lib.c",
            line=447,
            kind=KIND_EXPORTED,
            owning_phase=7,
        ),
        Blocker(
            name="EVP_PKEY_CTX_set_mac_key",
            authority_unit="crypto/evp/pmeth_lib.c",
            line=1252,
            kind=KIND_EXPORTED,
            owning_phase=7,
        ),
    ),
)

SELF_TEST_LANDED_IN = {
    "EVP_PKEY_CTX_new_id": "D186",
    "EVP_PKEY_CTX_set_mac_key": "D188",
}


def self_test() -> int:
    atlas = BlockerAtlas.from_repo()
    msgs = check_row(
        atlas,
        SELF_TEST_ROW,
        phase_state=phase_states(),
        landed_in=SELF_TEST_LANDED_IN,
    )
    print("[blocker-liveness] the reconstructed EVP_PKEY_new_mac_key row:")
    for m in msgs:
        print(f"  {m}")
    if not any("every blocker" in m and "has landed" in m for m in msgs):
        print(
            "[blocker-liveness] SELF-TEST FAILED: the checker did not report that every "
            "blocker of EVP_PKEY_new_mac_key has landed",
            file=sys.stderr,
        )
        return 1
    print("[blocker-liveness] self-test ok: the stale row is caught without a human")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the reconstructed EVP_PKEY_new_mac_key row and require the finding",
    )
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
