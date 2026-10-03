#!/usr/bin/env python3
"""openssl-rs — generate Phase 14.3's cipher/ciphersuite tables from the authority's own source.

`crypto/ssl/s3_lib.c` defines the three tables the whole cipher surface reads — the TLSv1.3
`tls13_ciphers`, the TLSv1.2-and-earlier `ssl3_ciphers`, and the two `ssl3_scsvs` signalling
values — and `crypto/ssl/ssl_ciph.c` defines the alias table (the `ALL`, `DEFAULT`, `kRSA`, ... rule
tokens) and the four mask->NID lookup tables `SSL_CIPHER_get_*_nid` uses. Every one of those is a
*transcription*: nearly two hundred rows of structural masks that D33 refuses to recall. This
generator reads the authority's C, resolves its macros from the pinned headers, and emits
`src/ssl/ssl_ciph_table.rs`.

The generated file is data only. The reader/parser *structure* is transcribed by hand in
`src/ssl/ssl_ciph.rs` and driven by `RT-SSL-CIPH`.

    python3 forensics/tools/gen_phase14_cipher_tables.py            # write
    python3 forensics/tools/gen_phase14_cipher_tables.py --check    # fail on drift

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import PRODUCTION_AUTHORITY, REPO_ROOT, rel, resolve_authority  # noqa: E402

OUT_RS = REPO_ROOT / "src" / "ssl" / "ssl_ciph_table.rs"
GENERATOR = "forensics/tools/gen_phase14_cipher_tables.py"

# The headers whose `#define`s the tables' identifiers resolve against. `ssl_local.h` carries the
# algorithm/strength masks; `ssl3.h`/`tls1.h` carry the names, RFC names and wire ids; `obj_mac.h`
# carries the `NID_*` values the four lookup tables name.
HEADERS = [
    "ssl/ssl_local.h",
    "include/openssl/ssl3.h",
    "include/openssl/tls1.h",
    "include/openssl/ssl.h.in",
    "include/openssl/obj_mac.h",
    "include/openssl/prov_ssl.h",
]

IDENT = re.compile(r"(?<![0-9A-Za-z_])[A-Za-z_][A-Za-z0-9_]*")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def join_continuations(text: str) -> str:
    return re.sub(r"\\\n", " ", text)


def configured_macros(auth) -> set[str]:
    """The `OPENSSL_NO_*` flags the admitted build was configured with."""
    defined: set[str] = set()
    for path in (
        auth.prefix / "include" / "openssl" / "configuration.h",
        auth.prefix / "include" / "openssl" / "opensslconf.h",
    ):
        if path.is_file():
            for m in re.finditer(r"#\s*define\s+(OPENSSL_NO_\w+)", path.read_text()):
                defined.add(m.group(1))
    return defined


def split_top_commas(text: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def load_macros(auth_src: Path) -> dict[str, object]:
    """Object-like macros map to their body; function-like ones to `(params, body)`."""
    macros: dict[str, object] = {}
    for relpath in HEADERS:
        path = auth_src / relpath
        if not path.is_file():
            continue
        text = join_continuations(
            strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        )
        for line in text.splitlines():
            m = re.match(r"\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)(\([^)]*\))?\s*(.*)$", line)
            if not m:
                continue
            name, params, body = m.group(1), m.group(2), m.group(3).strip()
            if body == "":
                continue
            value: object = body
            if params is not None:
                value = ([p.strip() for p in params[1:-1].split(",") if p.strip()], body)
            if name not in macros:
                macros[name] = value
    return macros


def expand_funcs(macros: dict[str, object], expr: str) -> str:
    pos = 0
    while True:
        m = IDENT.search(expr, pos)
        if not m:
            return expr
        name = m.group(0)
        after = expr[m.end() :]
        if not after.lstrip().startswith("(") or not isinstance(macros.get(name), tuple):
            pos = m.end()
            continue
        open_idx = expr.index("(", m.end())
        depth = 0
        close = open_idx
        for i in range(open_idx, len(expr)):
            if expr[i] == "(":
                depth += 1
            elif expr[i] == ")":
                depth -= 1
                if depth == 0:
                    close = i
                    break
        params, body = macros[name]
        args = split_top_commas(expr[open_idx + 1 : close])
        if len(args) != len(params):
            raise ValueError(f"{name}: {len(args)} args, expected {len(params)}")
        repl = body
        for p, a in zip(params, args):
            repl = re.sub(rf"(?<![0-9A-Za-z_]){re.escape(p)}(?![0-9A-Za-z_])", a, repl)
        expr = expr[: m.start()] + "(" + repl + ")" + expr[close + 1 :]
        pos = 0


CAST_RE = re.compile(
    r"\(\s*(?:unsigned|signed)?\s*(?:int|long|short|char|size_t|"
    r"u?int(?:8|16|32|64)_t|uint(?:8|16|32|64))\.?\s*\)"
)


def resolve(macros: dict[str, object], expr: str, _seen: frozenset[str] = frozenset()):
    expr = expr.strip()
    if expr == "NULL":
        return None
    if expr.startswith('"'):
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', expr)
        return "".join(parts)
    expr = expand_funcs(macros, expr)
    # Drop C integer-literal suffixes (`0x20U`, `1UL`) and casts so the expression is plain
    # arithmetic Python can evaluate.
    expr = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", expr)
    expr = CAST_RE.sub("", expr)
    if not IDENT.search(expr):
        return int(eval(expr, {"__builtins__": {}}, {})) & 0xFFFF_FFFF_FFFF_FFFF  # noqa: S307
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        body = expr
        def sub(m: re.Match[str]) -> str:
            key = m.group(0)
            if key not in macros or isinstance(macros[key], tuple):
                raise ValueError(f"unresolved macro {key} in {expr!r}")
            v = resolve(macros, macros[key], _seen)
            if not isinstance(v, int):
                raise ValueError(f"non-integer {key} in {expr!r}")
            return str(v)
        return int(eval(IDENT.sub(sub, body), {"__builtins__": {}}, {})) & 0xFFFF_FFFF_FFFF_FFFF  # noqa: S307
    name = expr
    if name in _seen:
        raise ValueError(f"macro cycle through {name}")
    if name not in macros or isinstance(macros[name], tuple):
        raise ValueError(f"unresolved macro {name} in {expr!r}")
    return resolve(macros, macros[name], _seen | {name})


def apply_conditionals(text: str, defined: set[str]) -> str:
    out: list[str] = []
    stack: list[bool] = []
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"#\s*ifndef\s+(\w+)", s)
        if m:
            stack.append(m.group(1) not in defined)
            continue
        m = re.match(r"#\s*ifdef\s+(\w+)", s)
        if m:
            stack.append(m.group(1) in defined)
            continue
        if re.match(r"#\s*else\b", s):
            stack[-1] = not stack[-1]
            continue
        if re.match(r"#\s*endif\b", s):
            stack.pop()
            continue
        if s.startswith("#"):
            continue
        if all(stack):
            out.append(line)
    return "\n".join(out)


def extract_braced(text: str, name: str) -> str:
    """The text inside the outermost `{...}` of the `name[...] = { ... }` definition."""
    m = re.search(rf"{re.escape(name)}\s*\[[^\]]*\]\s*=\s*\{{", text)
    if not m:
        raise ValueError(f"no definition of {name}")
    start = m.end() - 1
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    raise ValueError(f"unterminated {name}")


def split_entries(array_body: str) -> list[str]:
    entries: list[str] = []
    depth = 0
    start = None
    for i, ch in enumerate(array_body):
        if ch == "{":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                entries.append(array_body[start:i])
                start = None
    return entries


def split_fields(entry: str) -> list[str]:
    fields: list[str] = []
    depth = 0
    cur = ""
    for ch in entry:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            fields.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        fields.append(cur.strip())
    return fields


FIELD_NAMES = [
    "valid", "name", "stdname", "id", "algorithm_mkey", "algorithm_auth",
    "algorithm_enc", "algorithm_mac", "min_tls", "max_tls", "min_dtls", "max_dtls",
    "algo_strength", "algorithm2", "strength_bits", "alg_bits",
]

# The named masks, strengths, versions and flags `src/ssl/ssl_ciph.rs` and `src/ssl/ssl_conf.rs`
# read. Curated rather than "every SSL_* define", so the generated file names only what is used.
CONSTS = [
    # protocol versions
    "SSL3_VERSION", "TLS1_VERSION", "TLS1_1_VERSION", "TLS1_2_VERSION", "TLS1_3_VERSION",
    "DTLS1_VERSION", "DTLS1_2_VERSION", "DTLS1_BAD_VER",
    # key exchange / authentication / encryption / mac masks
    "SSL_kRSA", "SSL_kDHE", "SSL_kECDHE", "SSL_kECDHEPSK", "SSL_kDHEPSK", "SSL_kRSAPSK",
    "SSL_kPSK", "SSL_kSRP", "SSL_kGOST", "SSL_kGOST18", "SSL_kANY",
    "SSL_aRSA", "SSL_aDSS", "SSL_aNULL", "SSL_aECDSA", "SSL_aPSK", "SSL_aSRP",
    "SSL_aGOST01", "SSL_aGOST12", "SSL_aANY",
    "SSL_eNULL", "SSL_DES", "SSL_3DES", "SSL_RC4", "SSL_RC2", "SSL_IDEA",
    "SSL_AES128", "SSL_AES256", "SSL_CAMELLIA128", "SSL_CAMELLIA256", "SSL_SEED",
    "SSL_AES128GCM", "SSL_AES256GCM", "SSL_AES128CCM", "SSL_AES256CCM",
    "SSL_AES128CCM8", "SSL_AES256CCM8", "SSL_CHACHA20POLY1305", "SSL_ARIA128GCM",
    "SSL_ARIA256GCM", "SSL_MAGMA", "SSL_KUZNYECHIK", "SSL_eGOST2814789CNT",
    "SSL_eGOST2814789CNT12", "SSL_AESGCM", "SSL_AES", "SSL_AESCCM", "SSL_ARIA",
    "SSL_ARIAGCM", "SSL_CHACHA20", "SSL3_CK_CIPHERSUITE_FLAG",
    "SSL_MD5", "SSL_SHA1", "SSL_SHA256", "SSL_SHA384", "SSL_AEAD", "SSL_GOST89MAC",
    "SSL_GOST89MAC12", "SSL_GOST94", "SSL_GOST12_256", "SSL_GOST12_512",
    "SSL_MD_MD5_SHA1_IDX", "SSL_HANDSHAKE_MAC_MASK", "TLS1_PRF", "TLS1_PRF_DGST_SHIFT",
    "SSL_QUIC", "SSL_ENC_FLAG_DTLS", "SSL_ENC_FLAG_TLS1_2_CIPHERS",
    "SSL_STRONG_MASK", "SSL_DEFAULT_MASK", "SSL_STRONG_NONE", "SSL_NOT_DEFAULT",
    "SSL_LOW", "SSL_MEDIUM", "SSL_HIGH", "SSL_FIPS",
    "SSL_CERT_FLAG_SUITEB_128_LOS", "SSL_CERT_FLAG_SUITEB_128_LOS_ONLY",
    "SSL_CERT_FLAG_SUITEB_192_LOS", "SSL_CERT_FLAG_TLS_STRICT",
    # verification modes
    "SSL_VERIFY_NONE", "SSL_VERIFY_PEER", "SSL_VERIFY_FAIL_IF_NO_PEER_CERT",
    "SSL_VERIFY_CLIENT_ONCE", "SSL_VERIFY_POST_HANDSHAKE",
    # SSL_CONF flags / value types
    "SSL_CONF_FLAG_CMDLINE", "SSL_CONF_FLAG_FILE", "SSL_CONF_FLAG_CLIENT",
    "SSL_CONF_FLAG_SERVER", "SSL_CONF_FLAG_SHOW_ERRORS", "SSL_CONF_FLAG_CERTIFICATE",
    "SSL_CONF_FLAG_REQUIRE_PRIVATE",
    "SSL_CONF_TYPE_UNKNOWN", "SSL_CONF_TYPE_STRING", "SSL_CONF_TYPE_FILE",
    "SSL_CONF_TYPE_DIR", "SSL_CONF_TYPE_NONE", "SSL_CONF_TYPE_STORE",
    # option bits the SSL_CONF option/protocol tables name
    "SSL_OP_NO_SSLv2", "SSL_OP_NO_SSLv3", "SSL_OP_NO_TLSv1", "SSL_OP_NO_TLSv1_1",
    "SSL_OP_NO_TLSv1_2", "SSL_OP_NO_TLSv1_3", "SSL_OP_NO_DTLSv1", "SSL_OP_NO_DTLSv1_2",
    "SSL_OP_NO_SSL_MASK", "SSL_OP_NO_TICKET", "SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS",
    "SSL_OP_ALL", "SSL_OP_NO_COMPRESSION", "SSL_OP_SERVER_PREFERENCE",
    "SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION", "SSL_OP_SINGLE_DH_USE",
    "SSL_OP_SINGLE_ECDH_USE", "SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION",
    "SSL_OP_LEGACY_SERVER_CONNECT", "SSL_OP_ALLOW_CLIENT_RENEGOTIATION",
    "SSL_OP_NO_ENCRYPT_THEN_MAC", "SSL_OP_NO_RENEGOTIATION", "SSL_OP_ALLOW_NO_DHE_KEX",
    "SSL_OP_PREFER_NO_DHE_KEX", "SSL_OP_PRIORITIZE_CHACHA", "SSL_OP_ENABLE_MIDDLEBOX_COMPAT",
    "SSL_OP_NO_ANTI_REPLAY", "SSL_OP_NO_EXTENDED_MASTER_SECRET",
    "SSL_OP_DISABLE_TLSEXT_CA_NAMES", "SSL_OP_ENABLE_KTLS",
    "SSL_OP_NO_TX_CERTIFICATE_COMPRESSION", "SSL_OP_NO_RX_CERTIFICATE_COMPRESSION",
    "SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE", "SSL_OP_IGNORE_UNEXPECTED_EOF",
    "SSL_OP_LEGACY_EC_POINT_FORMATS",
]


def parse_rows(text: str, macros: dict[str, str], array_name: str, defined: set[str]):
    arr = apply_conditionals(extract_braced(text, array_name), defined)
    rows = []
    for entry in split_entries(arr):
        fields = split_fields(entry)
        values: dict[str, object] = {}
        for i, fname in enumerate(FIELD_NAMES):
            raw = fields[i] if i < len(fields) else "0"
            values[fname] = resolve(macros, raw)
        rows.append(values)
    return rows


def rust_str(s: object) -> str:
    if s is None:
        return 'b"\\0"'
    data = s.encode("utf-8")
    out = "".join(f"\\x{c:02x}" for c in data)
    return f'b"{out}\\0"'


def emit_rows(rows) -> str:
    lines = []
    for v in rows:
        lines.append("    SslCipher {")
        lines.append(f"        valid: {int(v['valid'])},")
        lines.append(f"        name: {rust_str(v['name'])},")
        lines.append(f"        stdname: {rust_str(v['stdname'])},")
        for f in FIELD_NAMES[3:]:
            lines.append(f"        {f}: {int(v[f]) & 0xFFFF_FFFF},")
        lines.append("    },")
    return "\n".join(lines)


def mask_nids(ciph: str, defined: set[str], macros: dict[str, str], table: str):
    body = apply_conditionals(extract_braced(ciph, table), defined)
    entries = []
    for e in split_entries(body):
        f = split_fields(e)
        entries.append((resolve(macros, f[0]), resolve(macros, f[1])))
    return entries


def rustfmt(text: str) -> str:
    """Run the emitted module through `rustfmt`, so `cargo fmt --check` and this generator agree."""
    try:
        import subprocess

        res = subprocess.run(
            ["rustfmt", "--edition", "2021"],
            input=text,
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return text
    if res.returncode == 0 and res.stdout:
        return res.stdout
    return text


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    auth_src = auth.source
    if not auth_src.is_dir():
        raise SystemExit(f"{GENERATOR}: authority source {auth_src} is absent")

    defined = configured_macros(auth)
    macros = load_macros(auth_src)

    s3 = join_continuations(
        strip_comments((auth_src / "ssl" / "s3_lib.c").read_text(encoding="utf-8", errors="replace"))
    )
    ciph = join_continuations(
        strip_comments(
            (auth_src / "ssl" / "ssl_ciph.c").read_text(encoding="utf-8", errors="replace")
        )
    )

    tls13 = parse_rows(s3, macros, "tls13_ciphers", defined)
    ssl3 = parse_rows(s3, macros, "ssl3_ciphers", defined)
    scsv = parse_rows(s3, macros, "ssl3_scsvs", defined)
    aliases = parse_rows(ciph, macros, "cipher_aliases", defined)

    # `ssl_sort_cipher_list` (`s3_lib.c:3729-3736`) qsorts the three tables by `id` at init. The
    # authority's `ssl3_get_cipher(u)` reverses the *sorted* table, so the emitted arrays carry the
    # post-sort order the readers and the parser see.
    tls13.sort(key=lambda r: int(r["id"]))
    ssl3.sort(key=lambda r: int(r["id"]))
    scsv.sort(key=lambda r: int(r["id"]))

    tables = {
        "SSL_CIPHER_TABLE_CIPHER": mask_nids(ciph, defined, macros, "ssl_cipher_table_cipher"),
        "SSL_CIPHER_TABLE_MAC": mask_nids(ciph, defined, macros, "ssl_cipher_table_mac"),
        "SSL_CIPHER_TABLE_KX": mask_nids(ciph, defined, macros, "ssl_cipher_table_kx"),
        "SSL_CIPHER_TABLE_AUTH": mask_nids(ciph, defined, macros, "ssl_cipher_table_auth"),
    }

    out = [
        "//! Phase 14.3's cipher and ciphersuite tables, generated from the authority's own",
        "//! source. **Generated. Do not edit.**",
        "//!",
        f"//! `{GENERATOR}` reads `crypto/ssl/s3_lib.c`'s `tls13_ciphers`,",
        "//! `ssl3_ciphers` and `ssl3_scsvs`, `crypto/ssl/ssl_ciph.c`'s `cipher_aliases`,",
        "//! and the four mask->NID lookup tables, resolves every macro against the pinned",
        "//! headers, and re-derives this file. The reader and parser *structure* is",
        "//! transcribed by hand in `src/ssl/ssl_ciph.rs`.",
        "//!",
        "//! SPDX-License-Identifier: Apache-2.0",
        "",
        "#![allow(dead_code)] // a named constant is kept only when a reader references it",
        "#![allow(non_upper_case_globals)] // the names are the authority's C macro spellings",
        "",
        "use core::ffi::c_int;",
        "",
        "/// `struct ssl_cipher_st` — `ssl_local.h:381-402`. The `name`/`stdname` slices carry",
        "/// their C terminator, so their `as_ptr()` is a valid `const char *`. The pointer crosses",
        "/// the FFI boundary, so the type is public; a consumer never constructs it.",
        "#[repr(C)]",
        "pub struct SslCipher {",
        "    pub(crate) valid: u32,",
        "    pub(crate) name: &'static [u8],",
        "    pub(crate) stdname: &'static [u8],",
        "    pub(crate) id: u32,",
        "    pub(crate) algorithm_mkey: u32,",
        "    pub(crate) algorithm_auth: u32,",
        "    pub(crate) algorithm_enc: u32,",
        "    pub(crate) algorithm_mac: u32,",
        "    pub(crate) min_tls: c_int,",
        "    pub(crate) max_tls: c_int,",
        "    pub(crate) min_dtls: c_int,",
        "    pub(crate) max_dtls: c_int,",
        "    pub(crate) algo_strength: u32,",
        "    pub(crate) algorithm2: u32,",
        "    pub(crate) strength_bits: i32,",
        "    pub(crate) alg_bits: u32,",
        "}",
        "",
        "/// `tls13_ciphers[]` — `ssl/s3_lib.c:40-...`.",
        f"pub(crate) static TLS13_CIPHERS: [SslCipher; {len(tls13)}] = [",
        emit_rows(tls13),
        "];",
        "",
        "/// `ssl3_ciphers[]` — `ssl/s3_lib.c:181-...`.",
        f"pub(crate) static SSL3_CIPHERS: [SslCipher; {len(ssl3)}] = [",
        emit_rows(ssl3),
        "];",
        "",
        "/// `ssl3_scsvs[]` — `ssl/s3_lib.c:3680-3717`.",
        f"pub(crate) static SSL3_SCSVS: [SslCipher; {len(scsv)}] = [",
        emit_rows(scsv),
        "];",
        "",
        "/// `cipher_aliases[]` — `ssl/ssl_ciph.c:162-281`.",
        f"pub(crate) static CIPHER_ALIASES: [SslCipher; {len(aliases)}] = [",
        emit_rows(aliases),
        "];",
        "",
    ]
    for name, entries in tables.items():
        out.append(f"/// `{name}[]` — `ssl/ssl_ciph.c`.")
        out.append(f"pub(crate) static {name}: [(u32, c_int); {len(entries)}] = [")
        for mask, nid in entries:
            out.append(f"    ({mask}, {nid}),")
        out.append("];")
        out.append("")

    out.append("// Named masks, strengths, versions and flags the readers and parser read. Values")
    out.append("// resolved from the pinned headers by the generator.")
    unresolved = []
    const_lines = []
    for name in CONSTS:
        try:
            value = resolve(macros, name)
        except ValueError:
            unresolved.append(name)
            continue
        if not isinstance(value, int):
            unresolved.append(name)
            continue
        const_lines.append(f"pub(crate) const {name}: u64 = {value};")
    if unresolved:
        raise SystemExit(f"{GENERATOR}: unresolved constants: {', '.join(unresolved)}")
    out.extend(const_lines)
    out.append("")
    text = "\n".join(out) + "\n"
    text = rustfmt(text)

    if args.check:
        current = OUT_RS.read_text(encoding="utf-8") if OUT_RS.is_file() else ""
        if current != text:
            print(f"[{GENERATOR}] DRIFT: {rel(OUT_RS)} does not match the authority")
            return 1
        print(f"[{GENERATOR}] {rel(OUT_RS)} matches")
        return 0

    OUT_RS.parent.mkdir(parents=True, exist_ok=True)
    OUT_RS.write_text(text, encoding="utf-8")
    print(f"[{GENERATOR}] tls13={len(tls13)} ssl3={len(ssl3)} scsv={len(scsv)} "
          f"aliases={len(aliases)}")
    for name, entries in tables.items():
        print(f"  {name}: {len(entries)}")
    print(f"  -> {rel(OUT_RS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
