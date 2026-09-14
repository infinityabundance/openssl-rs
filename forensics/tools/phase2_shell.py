#!/usr/bin/env python3
"""openssl-rs — Phase 2: generate the distribution / ABI shell.

Phase 2 proves that a *trivial external consumer can build and load* against the
candidate, before any complex semantics exist. It reconstructs the parts of an
OpenSSL distribution that are structural rather than behavioural:

    artifacts/phase2/
      libcrypto.ld, libssl.ld          generated ELF version scripts (export maps)
      pkgconfig/libcrypto.pc, libssl.pc  pkg-config metadata
      shell/libcrypto.shell.rs         SCAFFOLDED symbol definitions (libcrypto)
      shell/libssl.shell.rs            SCAFFOLDED symbol definitions (libssl)
      include/openssl/...              public header shell, with provenance
      SHELL_MANIFEST.json              content-addressed record of all of it

SCAFFOLDED, by construction and by rule
---------------------------------------
The generated symbol definitions are **scaffolds**. They are required so that the
distribution artifacts exist and can be linked and loaded, and they are governed
by `docs/CUSTODIAN_CONTRACT.md` §5:

  * classified `SCAFFOLDED` — `SHELL_MANIFEST.json` says so for every symbol;
  * they **cannot** count as parity: a scaffolded symbol is not an implemented
    obligation, and the parity ledger keeps it at `SCAFFOLDED`;
  * they must never return a plausible value. Each scaffold aborts with a
    diagnostic naming the symbol, so a consumer that *calls* one fails loudly
    instead of silently receiving invented output. That is the honest failure
    mode for an unimplemented obligation.

The scaffold set is DERIVED, not maintained
-------------------------------------------
The generator does not keep its own list of what is implemented. It reads
`forensics/atlas/implemented-surface.json`, which `implemented_surface.py`
derives by intersecting the authority's measured DSO exports with the symbols
the *built crate archive* actually defines. A symbol the crate defines is
scaffolded here **zero** times, so a scaffold and an implementation of the same
symbol can never collide in the link, and the implementation — not a generator's
opinion — decides the scaffold set.

Runtime flavour is decided by the link
--------------------------------------
`libcrypto.so.3` is linked together with the crate archive, so its scaffolds may
use `std` and resolve against the single Rust runtime already present. It is
built as an object rather than a second archive precisely because a second Rust
`staticlib` would drag a second copy of `std`/`core` into the same link.

`libssl.so.3` is linked from its scaffolds plus `libcrypto.so.3` **only**. It must
not carry a private copy of `libcrypto`'s implementation, because that would give
`libssl` its own copies of observable `libcrypto` state (the error queue is
thread-local, for instance) and applications would then observe two divergent
OpenSSLs in one process. Its scaffolds are therefore `no_std` and reference only
`write(2)` and `abort(3)`.

The header shell
----------------
`docs/ABI_POLICY.md` §4 and the contract's provenance rule allow interface
material to be carried from the authority with attribution. The header shell is
therefore *constructed from the authority's installed public headers*, with any
OpenSSL-derived interface material carrying its licence notice, and every file
recorded by hash. This is a deliberate, documented choice: hand-regenerating 142
headers from the AST would be a large source of silent divergence for no gain,
whereas a byte-identical shell is the strongest source-compatibility statement
available and is trivially verifiable.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    authority_atlas_dir,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_bytes,
    sha256_file,
    write_json,
    write_text,
    REPO_ROOT,
)

OUT = REPO_ROOT / "artifacts" / "phase2"
LIBRARIES = {"libcrypto": "libcrypto.so.3", "libssl": "libssl.so.3"}

# Which libraries are linked standalone (their scaffolds must be `no_std` and
# reference only libc) versus linked together with the crate archive (their
# scaffolds may use `std`, which the crate runtime already provides).
STANDALONE = {"libcrypto": False, "libssl": True}

IMPLEMENTED_SURFACE = REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json"

# `#![no_std]` flavour: no Rust runtime is available in the link, so the scaffold
# speaks to libc directly. `write(2)`/`abort(3)` are the only undefined symbols it
# may leave behind.
SCAFFOLD_PRELUDE_NOSTD = """#![no_std]
#![allow(non_snake_case)]

use core::ffi::{c_int, c_void};

extern "C" {
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn abort() -> !;
}

#[panic_handler]
fn openssl_rs_scaffold_panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: `abort` takes no arguments and does not return.
    unsafe { abort() }
}

#[cold]
#[inline(never)]
fn openssl_rs_scaffolded(name: &'static [u8]) -> ! {
    // SAFETY: `name` points at static storage for its whole length, and
    // `write`/`abort` are libc entry points that do not retain the pointer.
    unsafe {
        write(2, name.as_ptr().cast::<c_void>(), name.len());
        abort()
    }
}
"""

# `std` flavour: the crate archive is in the link, so the scaffold can report
# through the ordinary Rust runtime.
SCAFFOLD_PRELUDE_STD = """#![allow(non_snake_case)]

use core::ffi::c_int;
use std::io::Write;

#[cold]
#[inline(never)]
fn openssl_rs_scaffolded(name: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "{name}");
    std::process::abort();
}

/// Report that `name` is scaffolded. Never returns.
macro_rules! scaffolded {
    ($name:literal) => {
        openssl_rs_scaffolded($name)
    };
}
"""

HEADER_SHELL_NOTICE = """/* SPDX-License-Identifier: Apache-2.0
 *
 * openssl-rs — public header shell (Phase 2).
 *
 * PROVENANCE: this directory is constructed from the installed public headers of
 * the admitted OpenSSL authority `openssl-3.6.4-production`, which is licensed
 * under the Apache License 2.0. It is carried here so that unmodified consumers
 * can compile against a byte-faithful interface, and it is recorded by hash in
 * artifacts/phase2/SHELL_MANIFEST.json.
 *
 * This is interface material, not implementation. The implementation is native
 * Rust and lives in src/. See docs/CUSTODIAN_CONTRACT.md §3 (provenance rule).
 */
"""


def generate_version_script(doc: dict, soname: str) -> str:
    """Emit a GNU ld version script from the authority's measured DSO bindings.

    The binding of each symbol to a version node is taken from what the *built
    authority DSO* actually did (plane C), not from the source `.num` inventory,
    because that is what a downstream binary resolves against.
    """
    by_node: dict[str, list[str]] = {}
    for rec in doc["body"]["records"]:
        dso = rec.get("dso") or {}
        if not dso.get("present"):
            continue
        node = dso.get("version") or soname
        by_node.setdefault(node, []).append(rec["symbol"])
    lines = [
        f"# Generated by forensics/tools/phase2_shell.py — do not edit.",
        f"# Export map for {soname}, derived from the built authority DSO.",
        f"#",
        f"# Every symbol the authority actually exports, bound to the same ELF",
        f"# version node. Nothing is added and nothing is dropped: the ABI-SYMBOL",
        f"# court compares this script's effect against the authority exactly.",
        "",
    ]
    nodes = [n for n in sorted(by_node) if n != soname]
    for idx, node in enumerate(nodes):
        lines.append(f"{node} {{")
        lines.append("    global:")
        for sym in sorted(by_node[node]):
            lines.append(f"        {sym};")
        if idx == len(nodes) - 1:
            # The authority's own script carries `local: *;` in its final node,
            # which is what hides every symbol not explicitly listed. Omitting
            # it leaks whatever else ends up in the object graph (in particular
            # the Rust runtime's symbols, since a whole-archive link pulls them
            # in). Matching the authority here is not cosmetic: it is the
            # difference between a 5896-symbol ABI and an exported runtime.
            lines.append("    local: *;")
        lines.append("};")
        lines.append("")
    return "\n".join(lines) + "\n"


def generate_shell_rs(doc: dict, lib: str, implemented: set[str], standalone: bool) -> str:
    """Emit SCAFFOLDED Rust symbol definitions for one library.

    `implemented` is the set of symbols the built crate archive already defines
    for this library's namespace; those are omitted so the shell cannot collide
    with the implementation it would otherwise shadow.

    `standalone` selects the runtime flavour: a `no_std` scaffold that references
    only `write(2)`/`abort(3)` when the DSO is linked without the crate archive,
    or a `std` scaffold when the crate runtime is already in the link.
    """
    present = [rec for rec in doc["body"]["records"]
               if (rec.get("dso") or {}).get("present")]
    # A scaffold is a function definition. If the authority ever exports a data
    # symbol, emitting a function for it would produce a symbol whose ELF type is
    # wrong and the ABI-SYMBOL court would (correctly) fail. Refuse to guess.
    non_func = sorted({(r.get("dso") or {}).get("type")
                       for r in present
                       if (r.get("dso") or {}).get("type") not in (None, "FUNC")})
    if non_func:
        raise SystemExit(
            f"phase2_shell: {lib} exports non-FUNC symbol types {non_func}; "
            "the scaffold emitter only knows how to emit functions. Extend the "
            "emitter (and the ABI-SYMBOL court) rather than emitting a wrong type."
        )

    symbols = sorted(r["symbol"] for r in present if r["symbol"] not in implemented)
    out = [
        "// GENERATED by forensics/tools/phase2_shell.py — do not edit by hand.",
        "//",
        f"// openssl-rs — Phase 2 ABI shell for {lib} ({LIBRARIES[lib]}).",
        "//",
        "// STATUS: SCAFFOLDED. Every symbol below is a scaffold, not an",
        "// implementation. It exists so the distribution artifact can be linked",
        "// and loaded; it is governed by docs/CUSTODIAN_CONTRACT.md §5 and",
        "// *cannot* count as parity.",
        "//",
        "// A scaffold never returns a plausible value. Calling one aborts with a",
        "// diagnostic naming the symbol, so an unimplemented obligation fails",
        "// loudly rather than silently inventing output.",
        "//",
        "// Symbols the crate already implements are ABSENT by construction: this",
        "// file is generated against forensics/atlas/implemented-surface.json.",
        "",
        SCAFFOLD_PRELUDE_NOSTD if standalone else SCAFFOLD_PRELUDE_STD,
    ]
    for sym in symbols:
        out.append(f'#[no_mangle]\npub extern "C" fn {sym}() -> c_int {{')
        if standalone:
            out.append(f'    openssl_rs_scaffolded({scaffold_message_bytes(sym)})')
        else:
            out.append(f'    scaffolded!({json.dumps(scaffold_message(sym))})')
        out.append("}")
        out.append("")
    return "\n".join(out)


def scaffold_message(sym: str) -> str:
    return (
        f"openssl-rs: SCAFFOLDED symbol {sym} was called. It is not implemented; "
        "the ABI shell exists only so distribution artifacts can be linked and "
        "loaded. See docs/RELEASE_GATES.md."
    )


def scaffold_message_bytes(sym: str) -> str:
    """The message as a Rust byte-string literal (the `no_std` flavour)."""
    return 'b"' + scaffold_message(sym) + '\\n"'


def load_implemented(authority_id: str) -> dict[str, set[str]]:
    """Read the candidate implemented-surface manifest for one authority.

    The manifest is produced by `implemented_surface.py` from the *built crate
    archive*, so the shell cannot scaffold a symbol the crate already defines.
    A missing manifest is a hard error, not an empty default: defaulting would
    silently emit a scaffold that collides with the implementation at link time,
    and the cause (a stale or absent build) would be far from the symptom.
    """
    if not IMPLEMENTED_SURFACE.is_file():
        raise SystemExit(
            f"phase2_shell: {rel(IMPLEMENTED_SURFACE)} is missing.\n"
            "  It is derived from the built crate. Run:\n"
            "    cargo build --release\n"
            "    python3 forensics/tools/implemented_surface.py\n"
            "  (forensics/tools/build_phase2.sh does both.)"
        )
    doc = json.loads(IMPLEMENTED_SURFACE.read_text())
    if doc.get("authority") != authority_id:
        raise SystemExit(
            f"phase2_shell: {rel(IMPLEMENTED_SURFACE)} was generated for "
            f"{doc.get('authority')!r}, not {authority_id!r}; regenerate it."
        )
    libs = doc["body"]["libraries"]
    return {lib: set(libs[lib]["implemented_symbols"]) for lib in LIBRARIES}


def generate_pkgconfig(lib: str, version: str) -> str:
    soname = LIBRARIES[lib]
    other = "libssl" if lib == "libcrypto" else None
    req = "Requires.private: libcrypto" if lib == "libssl" else "Requires.private:"
    return f"""# Generated by forensics/tools/phase2_shell.py — do not edit.
# pkg-config metadata for the openssl-rs {lib} ABI shell.

prefix=/usr/local
exec_prefix=${{prefix}}
libdir=${{exec_prefix}}/lib
includedir=${{prefix}}/include

Name: {lib}
Description: openssl-rs — custodian reconstruction of OpenSSL {version} ({lib} ABI shell)
Version: {version}
Libs: -L${{libdir}} -l{lib.replace('lib', '', 1)}
Libs.private: -ldl -lpthread
Cflags: -I${{includedir}}
{req}
"""


SCAFFOLD_HEADER = """// GENERATED by forensics/tools/phase2_shell.py — do not edit by hand.
//
// STATUS: SCAFFOLDED. This artefact exists so the distribution shell is
// complete enough to be installed, linked, loaded and substituted; it is
// governed by docs/CUSTODIAN_CONTRACT.md §5 and cannot count as parity.
// It aborts with a diagnostic rather than returning a plausible value.

use std::io::Write;

#[allow(dead_code)] // the CLI shell routes through `main` instead
#[cold]
#[inline(never)]
fn openssl_rs_scaffolded(name: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "openssl-rs: SCAFFOLDED {name} invoked.");
    let _ = writeln!(std::io::stderr(), "openssl-rs: not implemented; the Phase 2 shell exists so the");
    let _ = writeln!(std::io::stderr(), "openssl-rs: distribution artifacts can be linked and loaded.");
    std::process::abort();
}
"""


def generate_provider_module_rs() -> str:
    """The legacy provider module.

    The authority's `lib/ossl-modules/legacy.so` exports exactly ONE symbol,
    `OSSL_provider_init`, and declares `NEEDED libcrypto.so.3`. Reproducing that
    shape is what makes the module discoverable at the same path with the same
    loading contract; the build step passes `-Wl,--no-as-needed -lcrypto` so the
    dependency is really declared rather than assumed.
    """
    return (
        SCAFFOLD_HEADER
        + "\n#[no_mangle]\npub extern \"C\" fn OSSL_provider_init() -> core::ffi::c_int {\n"
        + '    openssl_rs_scaffolded("OSSL_provider_init")\n}\n'
    )


def generate_cli_rs(version: str) -> str:
    """The `openssl` executable.

    Phase 2 requires the executable to EXIST with the right name and install
    path so that a consumer's build scripts and `which openssl` behave. Its
    behaviour is Phase 16 work; until then it fails loudly rather than pretending.
    """
    return (
        SCAFFOLD_HEADER
        + "\nfn main() {\n"
        + f'    let _ = writeln!(std::io::stderr(), "openssl-rs: SCAFFOLDED openssl CLI ({version} shell).");\n'
        + '    let _ = writeln!(std::io::stderr(), "openssl-rs: the command surface is Phase 16 work; nothing was executed.");\n'
        + "    std::process::exit(2);\n}\n"
    )


def generate_c_rehash_sh() -> str:
    return (
        "#!/bin/sh\n"
        "# GENERATED by forensics/tools/phase2_shell.py — SCAFFOLDED.\n"
        "# The authority installs bin/c_rehash; Phase 2 ships the name and path so\n"
        "# the install layout is complete. Behaviour is Phase 16 work.\n"
        "echo \"openssl-rs: SCAFFOLDED c_rehash (Phase 2 shell); nothing was executed.\" >&2\n"
        "exit 2\n"
    )


def generate(authority_id: str) -> None:
    auth = resolve_authority(authority_id)
    adir = authority_atlas_dir(authority_id)
    print(f"[phase2] {auth.id}")

    docs = {lib: json.loads((adir / f"symbols-{lib}.json").read_text())
            for lib in LIBRARIES}
    implemented = load_implemented(authority_id)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "shell").mkdir(exist_ok=True)
    (OUT / "pkgconfig").mkdir(exist_ok=True)

    produced: list[dict] = []

    for lib, doc in sorted(docs.items()):
        soname = LIBRARIES[lib]
        ld = generate_version_script(doc, soname)
        p = OUT / f"{lib}.ld"
        write_text(p, ld)
        produced.append({"artifact": p.name, "role": "version-script",
                         "sha256": sha256_file(p)})

        standalone = STANDALONE[lib]
        rs = generate_shell_rs(doc, lib, implemented[lib], standalone)
        p = OUT / "shell" / f"{lib}.shell.rs"
        write_text(p, rs)
        exports = sum(1 for r in doc["body"]["records"]
                      if (r.get("dso") or {}).get("present"))
        produced.append({"artifact": rel(p), "role": "scaffolded-symbols",
                         "sha256": sha256_file(p),
                         "authority_exports": exports,
                         "scaffolded": exports - len(implemented[lib]),
                         "implemented_excluded": len(implemented[lib]),
                         "runtime": "no_std" if standalone else "std"})

        pc = generate_pkgconfig(lib, auth.version)
        p = OUT / "pkgconfig" / f"{lib}.pc"
        write_text(p, pc)
        produced.append({"artifact": rel(p), "role": "pkg-config",
                         "sha256": sha256_file(p)})

    # --- the remaining distribution artefacts ----------------------------
    extra = {
        "shell/legacy.shell.rs": generate_provider_module_rs(),
        "shell/openssl.shell.rs": generate_cli_rs(auth.version),
        "shell/c_rehash.sh": generate_c_rehash_sh(),
    }
    for name, text in extra.items():
        p = OUT / name
        write_text(p, text)
        produced.append({"artifact": rel(p), "role": "scaffold-source",
                         "sha256": sha256_file(p)})

    # --- header shell: constructed from the authority's installed headers -----
    src_inc = auth.prefix / "include"
    dst_inc = OUT / "include"
    if dst_inc.exists():
        shutil.rmtree(dst_inc)
    shutil.copytree(src_inc, dst_inc, symlinks=False)
    header_files = sorted(p for p in dst_inc.rglob("*") if p.is_file())
    write_text(dst_inc / "PROVENANCE-NOTICE.h", HEADER_SHELL_NOTICE)
    header_files = sorted(p for p in dst_inc.rglob("*") if p.is_file())
    lines = [f"{sha256_file(p)}  {p.relative_to(dst_inc).as_posix()}\n"
             for p in header_files]
    produced.append({
        "artifact": rel(dst_inc),
        "role": "header-shell",
        "file_count": len(header_files),
        "root_hash": sha256_bytes("".join(lines).encode("utf-8")),
    })
    print(f"  header shell: {len(header_files)} files")

    # --- development symlinks -------------------------------------------
    # A real OpenSSL install ships `libcrypto.so` -> `libcrypto.so.3` so that
    # `-lcrypto` resolves at link time while the runtime object carries the
    # SONAME. Without these, a consumer cannot link (the linker searches for
    # `libcrypto.so`). Recorded as part of the install-layout contract.
    for lib, soname in LIBRARIES.items():
        link = OUT / f"{lib}.so"
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(soname)
        produced.append({"artifact": f"{lib}.so", "role": "development-symlink",
                         "target": soname})

    manifest_body = {
        "authority": auth.id,
        "authority_version": auth.version,
        "sonames": LIBRARIES,
        "scaffold_policy": (
            "every generated symbol definition is SCAFFOLDED; it cannot count as "
            "parity, and it aborts rather than returning a plausible value "
            "(docs/CUSTODIAN_CONTRACT.md §5)"
        ),
        "scaffold_set_derivation": (
            "the scaffold set is the authority's measured DSO exports minus the "
            "symbols the built crate archive defines ("
            "forensics/atlas/implemented-surface.json, derived by "
            "forensics/tools/implemented_surface.py). No list is maintained here."
        ),
        "implemented_excluded": {
            lib: len(implemented[lib]) for lib in LIBRARIES
        },
        "artifacts": produced,
    }
    doc = envelope("phase2-shell", "forensics/tools/phase2_shell.py", [],
                   manifest_body, authority=auth.id)
    doc["body_hash"] = content_hash(manifest_body)
    write_json(OUT / "SHELL_MANIFEST.json", doc)
    print(f"  manifest: {rel(OUT / 'SHELL_MANIFEST.json')}")
    for a in produced:
        extra = a.get("scaffolded") or a.get("file_count") or ""
        print(f"    {a['role']:<18} {a['artifact']} {extra}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate the Phase 2 ABI shell.")
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    generate(args.authority)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
