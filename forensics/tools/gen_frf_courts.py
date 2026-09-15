#!/usr/bin/env python3
"""openssl-rs — generate the FRF court declarations for the runtime strata.

Why this is generated
---------------------
A runtime court is nine-tenths boilerplate. `openssl-rs-rt-mem` and
`openssl-rs-rt-lhash` differ only in the court id, the one-line description of
the subsystem, the staging phase of the probe binaries and the paths those
imply. Hand-writing them means the *table of what exists* is spread across
nineteen YAML files, and a reader asking "which runtime surfaces have an FRF
court?" has to shell out to `ls`.

Nineteen files is already enough for that to matter, and Phases 5-21 will add
hundreds. So the table lives here, in one place, and the declarations are output.

What a generated court is
--------------------------
Each court compares the transcript of *one* differential probe: a C program that
prints one `key=value` observation per line. The same source is compiled against
the admitted authority and against the candidate distribution shell, each side
runs its own binary, and FRF compares the two transcripts.

The fixture list is load-bearing rather than decorative: it is what `{fixture}`
resolves to, and FRF requires a court to reference its fixture for the court to
be *challengeable* at all (`docs/DECISIONS.md` D13). A court that cannot be
challenged cannot produce sensitivity evidence, and a passing comparison without
a sensitivity control is weak evidence.

Usage
-----
    python3 forensics/tools/gen_frf_courts.py            # write the declarations
    python3 forensics/tools/gen_frf_courts.py --check     # fail if any drift

`--check` is what CI and `evidence_determinism.py` run: it re-derives every
declaration from this table and compares byte for byte, so a hand-edit to one
manifest cannot survive.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def candidate_version() -> str:
    """The candidate version the courts name, read from `Cargo.toml`.

    This used to be a literal in this file, with the comment "one place, so a
    release bumps every court rather than the ones somebody remembered". One place
    is right; a *second* place relative to `Cargo.toml` is not, because nothing
    held the two together and the manifests would have gone on naming a version the
    crate no longer was -- the same class as the stale phase registry D94 records.
    `--check` now fails if a declaration names a version the manifest does not, so a
    release edits `Cargo.toml` alone.
    """
    manifest = REPO_ROOT / "Cargo.toml"
    if not manifest.is_file():
        raise SystemExit(
            "gen-frf-courts: Cargo.toml is absent, so the candidate version the "
            "court declarations name cannot be derived"
        )
    with manifest.open("rb") as fh:
        doc = tomllib.load(fh)
    try:
        return str(doc["package"]["version"])
    except KeyError as exc:
        raise SystemExit(
            f"gen-frf-courts: Cargo.toml has no [package] {exc} to name as the "
            "candidate version"
        ) from exc


CANDIDATE_VERSION = candidate_version()
AUTHORITY = "openssl-rt-3.6.4-r2"
BUILD_PROFILE = "linux-x86_64-default-shared-legacy-notests"
AUTHORITY_LIB = "forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
CANDIDATE_LIB = "artifacts/phase2/libcrypto.so.3"

# (court id, phase, probe stem, description)
#
# `id` is the court, the `fixtures` directory and the `fixture_family`; `probe` is
# the staged binary both sides run. The description is the one line a reader needs
# to know what the transcript is about, and it is deliberately the same text that
# appears in the stratum's court generator and in the seal.
COURTS: list[tuple[str, int, str, str]] = [
    # Phase 3 — the core runtime.
    ("rt-mem", 3, "rt_mem_probe",
     "allocation, sizing, cleansing and the installable allocator"),
    ("rt-mem-default", 3, "rt_mem_default_probe",
     "the allocation family in the branch a consumer who never installs an "
     "allocator is in: the zero-length arms of malloc, zalloc, calloc, the array "
     "forms, the secure heap and the duplication family; CRYPTO_memdup's INT_MAX "
     "refusal; the CRYPTO_realloc(addr, 0) release observed through a libc "
     "interposer because the return value hides it; and the allow_customize latch"),
    ("rt-mem-install", 3, "rt_mem_install_probe",
     "the allocator dispatch itself: the identity of the reported default, partial "
     "installation of one slot at a time, reinstallation, installing the default "
     "back, and the installed branch's answer to a zero-length request"),
    ("rt-exdata", 3, "rt_exdata_probe",
     "per-object extension data (CRYPTO_*_ex_data)"),
    ("rt-err", 3, "rt_err_probe",
     "the thread-local error queue, its bounded ring, marks, the data attached "
     "to a slot and\nthe string tables that are loaded rather than compiled in"),
    ("rt-stack", 3, "rt_stack_probe",
     "the OPENSSL_sk_* metadata stack, its index-returning searches and its\n"
     "comparator calling convention"),
    ("rt-thread", 3, "rt_thread_probe",
     "threads, atomics and thread-local storage"),
    ("rt-secure", 3, "rt_secure_probe",
     "the secure heap"),
    ("rt-runtime-ext", 3, "rt_runtime_ext_probe",
     "the OSSL_trace_* surface under OPENSSL_NO_TRACE (the two category interrogators\n"
     "and OSSL_trace_string are fully live), the OSSL_ERR_STATE_* save/restore round\n"
     "trip observed through the public ERR_* queue, OSSL_sleep, the thread-support\n"
     "flags, the two privilege predicates, the three empty OPENSSL_fork_* hooks, and\n"
     "OPENSSL_die through a forked child"),
    ("rt-lhash", 3, "rt_lhash_probe",
     "the OPENSSL_LH_* hash table"),
    # Phase 4 — BIO, CONF and the buffer object.
    ("rt-bio", 4, "rt_bio_probe",
     "the BIO core: methods, chains, the memory, secure-memory and null BIOs,\n"
     "flags, retries, callbacks, printing and the buffer object"),
    ("rt-err-bio", 4, "rt_err_bio_probe",
     "the error-printing entry points, which write to a BIO or FILE sink"),
    ("rt-bio-addr", 4, "rt_bio_addr_probe",
     "the BIO_ADDR value API, its string conversions and its rejection cases"),
    ("rt-bio-resolve", 4, "rt_bio_resolve_probe",
     "BIO_lookup, BIO_ADDRINFO iteration and the socket put/get controls"),
    ("rt-bio-sock", 4, "rt_bio_sock_probe",
     "the socket BIO and the BIO_socket_* descriptor helpers"),
    ("rt-bio-comp", 4, "rt_bio_comp_probe",
     "the compression BIO and the name map over it"),
    ("rt-bio-debug", 4, "rt_bio_debug_probe",
     "BIO_debug_callback and its indentation"),
    ("rt-bio-print", 4, "rt_bio_print_probe",
     "BIO_printf, BIO_snprintf, the formatter they share and BIO_dump"),
    ("rt-bio-file", 4, "rt_bio_file_probe",
     "the file BIO, its descriptor ownership and its controls"),
    ("rt-bio-filter", 4, "rt_bio_filter_probe",
     "the buffer, line-buffer, read-buffer and prefix filter BIOs"),
    ("rt-bio-pair", 4, "rt_bio_pair_probe",
     "the BIO pair, its put/get directions and its retry behaviour"),
    ("rt-bio-dgram-pair", 4, "rt_bio_dgram_pair_probe",
     "the in-memory datagram pair"),
    ("rt-bio-dgram", 4, "rt_bio_dgram_probe",
     "the kernel datagram BIO and its peer/control surface"),
    ("rt-bio-conn", 4, "rt_bio_conn_probe",
     "the connect and accept BIOs"),
    ("rt-obj-stream", 4, "rt_obj_stream_probe",
     "OBJ_create_objects and the object description stream behind it"),
    ("rt-conf", 4, "rt_conf_probe",
     "the CONF reader, the classic hash bridge and the NCONF_* accessors"),
    ("rt-comp", 4, "rt_comp_probe",
     "the COMP_* object API as this profile builds it (all six factories answer NULL\n"
     "under no-zlib/no-zstd/no-brotli), the NULL contracts of the four NULL-tolerant\n"
     "accessors, OPENSSL_config, the reachable conf_ssl_name_find answers, and the two\n"
     "halves of OPENSSL_info"),
    # Phase 5 — the arithmetic and encoding substrate.
    ("rt-bn", 5, "rt_bn_probe",
     "the observable surface of the opaque BIGNUM: the values read back through the\n"
     "conversions, the sign, the bit length, the predicate answers, the return\n"
     "classes, the error queue after a failure and the division identity a == b*q + r"),
    ("rt-asn1", 5, "rt_asn1_probe",
     "the DER header decoder over every boundary it has -- short and long form, the\n"
     "length-length boundaries, indefinite and constructed forms, the high-tag form,\n"
     "a declared length past the buffer and the end-of-contents marker -- together\n"
     "with the two's-complement content codec, the string layer, the object layer,\n"
     "the text writers and the two parsers"),
    ("rt-asn1-template", 5, "rt_asn1_template_probe",
     "the template interpreter over a *caller-built* descriptor, which no built-in\n"
     "item can reach: a SEQUENCE with an EMBED field and an OPTIONAL one, a CHOICE,\n"
     "the SEQUENCE OF and SET OF content writers including the canonical ordering\n"
     "that only the SET one applies, the twelve primitive-hook items where the value\n"
     "is behind the slot for some and *in* the slot for LONG/ZLONG, and the two\n"
     "ASN1_TYPE octet-string pairs whose int form goes through a private template"),
    ("rt-asn1-time", 5, "rt_asn1_time_probe",
     "the time family: the two RFC 5280 syntaxes read by their only parser (the\n"
     "field-bounds tables, the leap-year calendar, the shortest legal spelling and\n"
     "the fraction field), the two type guards, the offset `+hhmm` that is validated\n"
     "without a destination and applied only with one, the RFC 5280 profile and the\n"
     "`YYYY`->`YY` shortening, the four constructors and their year-window choice,\n"
     "the Julian-day diff and compare answers, the three printer formats, the\n"
     "duplicates and the two in-place converters"),
    ("rt-asn1-str", 5, "rt_asn1_str_probe",
     "the string classification, table and printing surface: which of\n"
     "PrintableString/IA5String/T61String a buffer fits in, the four-byte-per-\n"
     "character narrowing, the raw printer's 80-octet blocking measured through a\n"
     "write callback that records the chunk lengths, the mask-narrowing classifier\n"
     "over its four input and four output encodings with its two size limits, the\n"
     "28-row per-NID string table with the runtime stack that shadows it and the\n"
     "global mask's STABLE_NO_MASK exemption, the five spellings of\n"
     "ASN1_STRING_set_default_mask_asc, the two number printers, and the escaping\n"
     "printer ASN1_STRING_print_ex over twenty-three flag sets and every one of the\n"
     "256 byte values, with ASN1_STRING_to_UTF8 over each character type"),
    ("rt-bio-asn1", 5, "rt_bio_asn1_probe",
     "the ASN.1 filter BIO and the NDEF bridge: the write path as a state machine\n"
     "that re-emits its header when the declared content is exhausted, the prefix\n"
     "and suffix runs with their cleanup callbacks counted, the four prefix/suffix\n"
     "controls and the two EX_ARG controls, the flush-before-any-write case, the\n"
     "pass-through paths, and BIO_new_NDEF over a caller-declared streaming item"),
    ("rt-asn1-print", 5, "rt_asn1_print_probe",
     "the structural printer over every arm of its itype switch: the <ABSENT> rule\n"
     "and the boolean that lives in its slot, the primitive leaves including the\n"
     "128-bit decimal/hex threshold and the object's long name, the MSTRING that\n"
     "reads its type from the value, the ANY that repoints at its own union, a\n"
     "caller-declared SEQUENCE with an EMBED field and an OPTIONAL one, a CHOICE\n"
     "with an out-of-range selector, the SEQUENCE OF and SET OF empty/absent cases,\n"
     "the twenty-space indent blocks measured through a short-count sink, and the\n"
     "negative indent that fails the whole call"),
    ("rt-asn1-mime", 5, "rt_asn1_mime_probe",
     "asn_mime.c's copying half: the two null refusals, the verbatim binary and\n"
     "CMS_BINARY modes, the CRLF policy under every combination of SMIME_TEXT,\n"
     "SMIME_CRLFEOL and SMIME_ASCIICRLF including the held-back blank lines and the\n"
     "trailing-space rule, the buffering filter measured through a sink that logs each\n"
     "write length, the short-write and failing-flush failures with the flush\n"
     "combination, and i2d_ASN1_bio_stream with and without SMIME_STREAM"),
    ("rt-pem", 5, "rt_pem_probe",
     "the two pem.h exports that need nothing but BIO_snprintf: PEM_proc_type over\n"
     "its three named types and the BAD-TYPE fallback, PEM_dek_info over its byte\n"
     "counts and the 0xff mask that keeps a negative char two digits wide, the two\n"
     "appending to one buffer in the order PEM_ASN1_write_bio_internal uses them, and\n"
     "the conditional newline as the header buffer fills up"),
    # Phase 6 — the parameter surface and the provider core.
    ("rt-param", 6, "rt_param_probe",
     "the OSSL_PARAM descriptor as a matrix rather than a scenario list: every "
     "accessor against every source width, signedness and data type, with the "
     "return code, the error queue and the value or bytes produced; the setters "
     "against every destination shape including the NULL-buffer size queries that "
     "answer success; the string and pointer forms and the two readers that accept "
     "either; BIGNUM in and out with the sign and width rules; dup, merge and "
     "free; text allocation with the hex prefix; and the builder's one-block "
     "layout and reuse"),
    ("rt-libctx", 6, "rt_libctx_probe",
     "the OSSL_LIB_CTX identity contract: a fresh context distinct from every other, "
     "the global default handing back one stable address that freeing does not "
     "release, the thread-default chain including the clear-not-store that passing "
     "the global default performs, the two of three `free` arguments that are "
     "no-ops -- NULL and a context this thread has made its default -- "
     "conf_diagnostics as per-context state read and written through a NULL "
     "context, and the index registry's boundary: the dead indices and everything "
     "past the end of the switch answer NULL, while the slot whose answer is the "
     "address of a field answers a pointer for every context including an empty "
     "one"),
    ("rt-threaddata", 6, "rt_threaddata_probe",
     "the per-context thread slot's two accessors: the counter is per context "
     "rather than per process, so setting it on one must not move another; a "
     "NULL context resolves through the library context default chain, so "
     "installing a thread default changes what the same call answers; and the "
     "value is stored verbatim, with no range check, so UINT64_MAX is legal to "
     "set and to read back and zero is a value rather than 'unset'"),
]


def court_dir(court_id: str) -> Path:
    return REPO_ROOT / "forensics" / "frf" / "courts" / f"openssl-rs-{court_id}"


def preamble(court_id: str, phase: int, description: str) -> str:
    # The description may be wrapped over several lines; every continuation needs
    # its own `#` or the manifest stops being YAML-comment and becomes a parse
    # error at the wrapped line.
    described = "\n".join(f"#     {line}" for line in description.splitlines())
    return (
        f"# openssl-rs court: the Phase {phase} `{court_id}` runtime surface.\n"
        "#\n"
        "# The subject is the transcript of a differential probe: one C program that\n"
        "# prints one `key=value` line per observation while exercising\n"
        "#\n"
        f"{described}\n"
        "#\n"
        "# The same source is compiled against the admitted authority and against the\n"
        "# candidate, each side executes its own binary, and FRF compares the\n"
        "# transcripts.\n"
        "#\n"
        "# Scope: the observations the probe makes. It is NOT a claim about surface the\n"
        "# probe does not touch, and not a cryptographic or security claim.\n"
    )


def manifest(court_id: str, phase: int, probe: str, description: str) -> str:
    stem = f"openssl-rs-{court_id}"
    return (
        preamble(court_id, phase, description)
        + "\n"
        "court:\n"
        f"  id: {stem}\n"
        "  question: >-\n"
        f"    For the {court_id} runtime surface in fixture family {court_id}, does\n"
        "    the candidate produce the same observable transcript as the admitted\n"
        "    authority OpenSSL 3.6.4 when both run the same probe over the same\n"
        "    fixture?\n"
        "  falsifier: >-\n"
        "    Any observation line differs between the two transcripts, or either\n"
        "    side's exit class differs.\n"
        f"  authority: {AUTHORITY}\n"
        "  candidate:\n"
        "    name: openssl-rs\n"
        f'    version_or_commit: "{CANDIDATE_VERSION}"\n'
        f"    build_profile: {BUILD_PROFILE}\n"
        "    path: forensics/frf/refs/candidate-runtime-probe.sh\n"
        "  fixture:\n"
        "    id: probe-list.txt\n"
        f"    path: forensics/frf/courts/{stem}/fixtures/probe-list.txt\n"
        f'    arguments: ["{{fixture}}", "phase{phase}"]\n'
        "  admissibility_envelope:\n"
        f"    fixture_family: {court_id}\n"
        '    platforms: ["x86_64-linux"]\n'
        "    observables: [stdout, exit]\n"
        "    normalizers: []\n"
        "    replay_scope: single-run\n"
        "  execution_context:\n"
        "    artifacts:\n"
        "      - path: forensics/frf/refs/authority-runtime-probe.sh\n"
        "        role: child-executable\n"
        "      - path: forensics/frf/refs/candidate-runtime-probe.sh\n"
        "        role: child-executable\n"
        f"      - path: artifacts/phase{phase}/probes/{probe}.authority\n"
        "        role: child-executable\n"
        f"      - path: artifacts/phase{phase}/probes/{probe}.candidate\n"
        "        role: child-executable\n"
        f"      - path: courts/phase{phase}/{probe}.c\n"
        "        role: data\n"
        f"      - path: {AUTHORITY_LIB}\n"
        "        role: runtime-library\n"
        f"      - path: {CANDIDATE_LIB}\n"
        "        role: runtime-library\n"
        "  environment:\n"
        "    LC_ALL: C\n"
        "    TZ: UTC\n"
    )


def fixture(court_id: str, probe: str) -> str:
    return (
        f"# Fixture for the {court_id} runtime court.\n"
        "#\n"
        "# The probe list is the query: it selects which staged probe binaries each side\n"
        "# runs. It is required rather than decorative because a court whose arguments do\n"
        "# not reference {fixture} cannot be challenged (docs/DECISIONS.md D13).\n"
        f"{probe}\n"
    )


def wanted() -> dict[Path, str]:
    out: dict[Path, str] = {}
    seen: set[str] = set()
    for court_id, phase, probe, description in COURTS:
        if court_id in seen:
            raise SystemExit(f"gen_frf_courts: duplicate court id {court_id}")
        seen.add(court_id)
        d = court_dir(court_id)
        out[d / "manifest.yaml"] = manifest(court_id, phase, probe, description)
        out[d / "fixtures" / "probe-list.txt"] = fixture(court_id, probe)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="do not write; fail if any declaration has drifted")
    args = ap.parse_args(argv)

    files = wanted()
    if args.check:
        drift = []
        for path, text in files.items():
            if not path.exists():
                drift.append(f"missing: {path.relative_to(REPO_ROOT)}")
            elif path.read_text(encoding="utf-8") != text:
                drift.append(f"differs: {path.relative_to(REPO_ROOT)}")
        if drift:
            print("[gen-frf-courts] the declarations have drifted from the table:")
            for d in sorted(drift):
                print(f"  {d}")
            print("  run: python3 forensics/tools/gen_frf_courts.py")
            return 1
        print(f"[gen-frf-courts] ok: {len(files)} file(s) match the table "
              f"({len(COURTS)} courts)")
        return 0

    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    # A court renamed or removed in the table must not leave its directory
    # behind, or the stale manifest would still be run.
    table_dirs = {court_dir(c) for c, *_ in COURTS}
    courts_root = REPO_ROOT / "forensics" / "frf" / "courts"
    for existing in sorted(courts_root.glob("openssl-rs-rt-*")):
        if existing not in table_dirs:
            print(f"[gen-frf-courts] removing {existing.relative_to(REPO_ROOT)}: "
                  "no longer in the table")

    print(f"[gen-frf-courts] wrote {len(files)} file(s) for {len(COURTS)} court(s)")
    for phase in sorted({p for _c, p, _pr, _d in COURTS}):
        n = sum(1 for _c, p, _pr, _d in COURTS if p == phase)
        print(f"  phase {phase}: {n} court(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
