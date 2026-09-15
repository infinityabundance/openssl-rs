#!/usr/bin/env python3
"""openssl-rs — generate the `ERR` reason codes (`src/runtime/err_reasons.rs`).

Why this generator exists
-------------------------
An `ERR_raise(lib, reason)` call's *reason* is an integer a caller can read back
with `ERR_get_error` and turn into text with `ERR_reason_error_string`. It is
therefore part of the observed contract exactly as much as the file, line and
function are — and every ASN.1, X.509, PEM, CMS and provider error path in this
crate needs the right one.

Those codes live as `#define`s in the authority's installed headers. Transcribing
them by hand has already produced a wrong answer twice: `ASN1_R_BAD_OBJECT_HEADER`
is 102 and `ASN1_R_EXPECTING_AN_OBJECT` is 116, and both were typed incorrectly
the first time. The header is a machine-readable fact, so it is *read*, not
copied.

Independence from `gen_err_strings.py`
--------------------------------------
`gen_err_strings.py` already reads the same `#define`s, because it needs a
symbol -> code mapping to build the string tables. This tool does not import
that function: it scans independently and then *cross-checks* its own result
against `gen_err_strings.parse_reason_codes`. Two independent readers of the same
headers disagreeing is a residual, not something to average away. The
cross-check runs on every invocation and fails the run.

What is emitted, and what is deliberately not
---------------------------------------------
Every `<LIB>_R_<NAME>` decimal `#define` reachable under the production
authority's `include/`, `crypto/`, `ssl/` and `providers/` trees, as a
`pub(crate) const` named exactly as the authority names it, with the declaring
header recorded in the doc comment. Names come through verbatim because the
correctness question a reader has is "does this match the header", and a
renamed constant answers a different question.

The module carries `#![allow(dead_code)]` for the same reason
`src/asn1/layout.rs` does: it is a complete projection of an authority fact
surface, consumed incrementally, and an unused row is not an unused
implementation. The justification is written in the file itself.

Nothing here is a parity claim. A reason code that matches the header only says
the number is right; whether the crate raises it from the authority's site, with
the authority's queue effect, is the courts' business.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    authority_source,
    content_hash,
    rel,
    sha256_bytes,
    sha256_file,
    write_json,
    write_text,
)
from gen_err_strings import parse_reason_codes  # noqa: E402

OUT_RS = REPO_ROOT / "src" / "runtime" / "err_reasons.rs"
OUT_ATLAS = REPO_ROOT / "forensics" / "atlas" / "err-reasons.json"

GENERATOR = "forensics/tools/gen_err_reasons.py"

# The trees the authority's reason headers live in. `include/` holds the
# installed `*err.h` files; the other three hold internal declarations that the
# authority's own `*_err.c` arrays compile against, so a reason that appears
# only there is still a reason the library can raise.
SCAN_ROOTS = ("include", "crypto", "ssl", "providers")

# `#define LIB_R_NAME 123`, with optional integer suffixes. Expressions are
# deliberately *not* evaluated here: `gen_err_reasons` records declared codes,
# and the only declared forms in these headers are decimals and the
# `SSL_R_*`-style aliases that `gen_err_strings` resolves via the string
# tables. An alias would need a resolve step and its own justification, so it is
# reported instead of guessed at.
DEFINE_RE = re.compile(
    r"^#\s*define\s+([A-Z][A-Z0-9_]*_R_[A-Za-z0-9_]+)\s+([0-9]+)[uUlL]*\s*(?:/\*.*)?$",
    re.M,
)


def scan(source: Path) -> tuple[dict[str, int], dict[str, str], dict[str, str]]:
    """Return (name -> code, name -> declaring header, header -> sha256).

    The declaring header matters twice: it is what the generated doc comment
    cites, and a code that two headers disagree about is a hard failure. The
    authority does not have such a disagreement today; if it ever does, the
    right answer is not "whichever the loop saw last".
    """
    codes: dict[str, int] = {}
    declared_in: dict[str, str] = {}
    digests: dict[str, str] = {}

    for root_name in SCAN_ROOTS:
        root = source / root_name
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.h")) + sorted(root.rglob("*.h.in")):
            text = path.read_text(encoding="utf-8", errors="replace")
            digest = sha256_bytes(text.encode("utf-8"))
            relpath = path.relative_to(source).as_posix()
            digests[relpath] = digest
            for m in DEFINE_RE.finditer(text):
                name, value = m.group(1), int(m.group(2))
                previous = codes.get(name)
                if previous is not None and previous != value:
                    raise SystemExit(
                        f"gen_err_reasons: {name} is {previous} "
                        f"({declared_in[name]}) and {value} ({relpath})"
                    )
                codes[name] = value
                declared_in[name] = relpath

    if not codes:
        raise SystemExit("gen_err_reasons: no <LIB>_R_<NAME> defines found")
    return codes, declared_in, digests


def cross_check(codes: dict[str, int], source: Path) -> None:
    """Require agreement with `gen_err_strings`' independent reader.

    `gen_err_strings.parse_reason_codes` uses a stricter regex (no trailing
    comment, no suffix) over the same trees, so its result should be a subset.
    A code present in both must agree; a code this scan found and that one did
    not is *reported*, not failed, because the looser pattern is this tool's
    deliberate choice. A code the other reader found and this one did not is a
    hard failure: it would mean this scan is missing a reason that the string
    tables already index.
    """
    other = parse_reason_codes(source)
    disagreements = [
        (name, code, other[name])
        for name, code in sorted(codes.items())
        if name in other and other[name] != code
    ]
    if disagreements:
        for name, mine, theirs in disagreements[:8]:
            print(f"  {name}: gen_err_reasons={mine} gen_err_strings={theirs}")
        raise SystemExit(
            f"gen_err_reasons: {len(disagreements)} reason code(s) disagree "
            "with gen_err_strings"
        )
    missing = sorted(set(other) - set(codes))
    if missing:
        raise SystemExit(
            "gen_err_reasons: gen_err_strings resolves "
            f"{len(missing)} reason(s) this scan missed: {missing[:8]}"
        )
    extra = sorted(set(codes) - set(other))
    if extra:
        print(
            f"[gen_err_reasons] {len(extra)} reason(s) read by the looser "
            f"pattern and not by gen_err_strings (comment/suffix forms), "
            f"first: {extra[:4]}"
        )


def render(codes: dict[str, int], declared_in: dict[str, str],
           digests: dict[str, str]) -> str:
    input_digest = content_hash(
        {name: digest for name, digest in sorted(digests.items())}
    )
    generator_digest = sha256_file(REPO_ROOT / GENERATOR)

    out: list[str] = []
    out.append("//! GENERATED by forensics/tools/gen_err_reasons.py — do not edit.")
    out.append("//!")
    out.append("//! The authority's `ERR` reason codes, read from the installed")
    out.append("//! `*err.h` headers rather than transcribed. See the generator's")
    out.append("//! docstring for why transcribing them produced wrong answers twice.")
    out.append("//!")
    out.append(f"//! Authority: `{PRODUCTION_AUTHORITY}`.")
    out.append(f"//! Scanned header set: {len(digests)} files, "
               f"content digest `{input_digest}`.")
    out.append(f"//! Generator `{GENERATOR}` sha256 `{generator_digest}`.")
    out.append("//!")
    out.append("//! `ERR_raise(lib, reason)` records the reason an `ERR_get_error`")
    out.append("//! caller reads back, so a wrong value here is observable in the")
    out.append("//! error queue with no other symptom. Each constant names the")
    out.append("//! header that declares it.")
    out.append("")
    out.append("// A complete projection of an authority fact surface, consumed")
    out.append("// incrementally: each later stratum reads the codes its own paths")
    out.append("// raise. An unused row here is an unused constant, not an unused")
    out.append("// implementation — the crate's rule that every `allow` carries")
    out.append("// its reason is why this one is written down rather than implied.")
    out.append("#![allow(dead_code)]")
    out.append("")
    out.append("use core::ffi::c_int;")

    last_lib = None
    for name in sorted(codes):
        lib = name.split("_R_", 1)[0]
        if lib != last_lib:
            out.append("")
            out.append(f"// --- {lib} ---")
            out.append("")
            last_lib = lib
        out.append(f"/// `{name}` — `{declared_in[name]}`.")
        out.append(f"pub(crate) const {name}: c_int = {codes[name]};")
    out.append("")

    return "\n".join(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-name", metavar="NAME",
        help="print the code for one reason and exit (used by the courts)",
    )
    args = parser.parse_args(argv)

    source = authority_source(PRODUCTION_AUTHORITY)
    codes, declared_in, digests = scan(source)

    if args.print_name:
        name = args.print_name
        if name not in codes:
            print(f"gen_err_reasons: {name} is not declared by the authority",
                  file=sys.stderr)
            return 1
        print(codes[name])
        return 0

    cross_check(codes, source)

    text = render(codes, declared_in, digests)
    digest = write_text(OUT_RS, text)

    write_json(
        OUT_ATLAS,
        {
            "kind": "err-reasons",
            "authority": PRODUCTION_AUTHORITY,
            "generator": GENERATOR,
            "inputs": [
                {"path": rel(source / path), "sha256": digest_}
                for path, digest_ in sorted(digests.items())
            ],
            "body": {
                "count": len(codes),
                "codes": {name: codes[name] for name in sorted(codes)},
                "declared_in": {name: declared_in[name] for name in sorted(codes)},
                "scanned_headers": len(digests),
                "scan_roots": list(SCAN_ROOTS),
            },
        },
    )

    libraries = sorted({name.split("_R_", 1)[0] for name in codes})
    print(
        f"[gen_err_reasons] {rel(OUT_RS)} reasons={len(codes)} "
        f"headers={len(digests)} libraries={len(libraries)} "
        f"sha256={digest[:16]}…"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
