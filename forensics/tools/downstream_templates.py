#!/usr/bin/env python3
"""openssl-rs — declarative downstream template layer.

The P1000 build/runtime atlases historically admitted a family only when a
bespoke recipe *and* a bespoke workload had been written for it.  That does not
scale to the long tail: most remaining families fall into a small number of
observable buckets whose acquisition/build/workload shape is identical apart
from a handful of fields.

This module is the template layer.  A family entry in
``downstream_template_families.json`` names:

* the pristine release (URL + SHA-256 + archive kind);
* a declarative build (``autotools`` / ``configure`` / ``cmake`` / ``meson`` /
  ``make``), exactly the build vocabulary ``downstream_build_link`` already runs;
* the built program and its identity argv;
* a workload bucket from :data:`HARNESS_TEMPLATES`.

The tools import this module rather than growing another bespoke branch:

* ``downstream_build_link`` appends :func:`recipe_specs` to its shared
  catalogue and uses :func:`write_pkgconfig_shim` for prefixes that ship no
  ``openssl.pc``;
* ``downstream_runtime`` merges :func:`programs` / :func:`runners` and calls
  :func:`admit_binary` *before* a template family may claim L7.

An entry may set ``"recipe": "admitted"``.  That means the family already has
an admitted pristine recipe in the shared build/link catalogue (with its own
auxiliary packages); :func:`recipe_specs` then emits no recipe, so the template
row adds only the runtime intent and workload and never shadows the admitted
build.  This is how a mechanism template is proved on an existing admitted
family rather than by admitting a second copy of it.

A ``workload`` may be a single recipe object or a tuple of them.  The latter is
for one family whose consumer exposes more than one mechanism (Bootgen signs
*and* runs a counter-mode KDF), and each item still carries its own positive
behaviour and negative control.

The template layer is deliberately honest about what it does **not** do: a
bucket template is a local, deterministic exercise of the program's OpenSSL
path, not a security proof, and a family that never loads the subject
libssl/libcrypto is refused by :func:`admit_binary` rather than promoted.

However, a template is also not allowed to manufacture an L7 by calling OpenSSL
from the harness while merely linking the consumer.  Every mechanism template
is gated by :func:`verify_consumer_boundary`: the *consumer* artifact must
import at least one OpenSSL symbol (and, when a consumer shared library is
named, the workload must reference a symbol that library actually exports),
while a compiled typed harness must import **no** OpenSSL symbol of its own.
A workload that fails that gate is recorded as ``false-l7`` and cannot pass.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import zipfile
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import downstream_census as census  # noqa: E402

TEMPLATE_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = TEMPLATE_ROOT / "downstream_template_families.json"

#: The workload buckets the registry implements.  ``library-only (needs C)`` is
#: intentionally absent: a library with no executable needs a *typed* consumer,
#: which is the one bucket this declarative layer cannot honestly template.
HARNESS_TEMPLATES: tuple[str, ...] = (
    "digest",
    "http_client",
    "http_bench",
    "http_mirror",
    "tls_server",
    "signature",
    "ssh_client",
    # Mechanism-oriented templates.  Each has a positive behaviour and an
    # essential negative control; see the handlers below.
    "x509_verification",
    "evp_signing",
    "aead_roundtrip",
    "hmac_kdf",
)

_TEMPLATE_SCHEMA = "openssl-rs/downstream-template-families/1"


# --------------------------------------------------------------------------------------------
# declarative family config
# --------------------------------------------------------------------------------------------

def _load_document() -> dict:
    if not CONFIG_PATH.is_file():
        return {"schema": _TEMPLATE_SCHEMA, "families": []}
    doc = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if doc.get("schema") != _TEMPLATE_SCHEMA:
        raise SystemExit(f"[downstream-templates] unsupported schema in {CONFIG_PATH}")
    return doc


def families() -> tuple[dict, ...]:
    """The configured template families, in file order (pure; reads one JSON file)."""
    return tuple(_load_document().get("families") or ())


_BY_FAMILY: dict[str, dict] = {str(e["family"]): e for e in families()}


def recipe_specs() -> tuple[dict, ...]:
    """The build/link recipe form of each entry, in the shared catalogue vocabulary.

    The same recipe is run against the authority and the candidate with only
    ``{prefix}`` substituted, so the identical-build-intent rule is preserved.
    """
    out: list[dict] = []
    for entry in families():
        if str(entry.get("recipe") or "") == "admitted":
            # The family's pristine build recipe already lives in the shared
            # catalogue (usually with auxiliary pins).  Emitting a second,
            # reduced recipe here would shadow it; the template row contributes
            # only the runtime intent and workload.
            continue
        rec = {
            "family": entry["family"],
            "version": entry["version"],
            "url": entry["url"],
            "archive": entry.get("archive", "tar.gz"),
            "sha256": entry["sha256"],
            "build_system": entry["build_system"],
            "configure": list(entry.get("configure") or []),
            "make": list(entry.get("make") or [census.MAKE_JOBS]),
            "artifact": entry["artifact"],
            "launch": list(entry.get("launch") or []),
            "env_extra": entry.get("env_extra"),
            "pre_build": entry.get("pre_build"),
            "pkgconfig_shim": bool(entry.get("pkgconfig_shim")),
            "template": True,
            "bucket": entry.get("bucket"),
            "note": (f"template recipe ({entry.get('bucket')}); pristine release built against "
                     "the subject prefix, with the workload supplied by the bucket template"),
        }
        out.append(rec)
    return tuple(out)


def programs() -> dict[str, dict]:
    """The runtime intent (program, launch argv, version pattern) for each family."""
    out: dict[str, dict] = {}
    for entry in families():
        prog = {
            "program": entry["program"],
            "launch": list(entry.get("launch") or []),
            "version_re": entry["version_re"],
            "template": True,
            "bucket": entry.get("bucket"),
        }
        if entry.get("lib_paths"):
            prog["lib_paths"] = list(entry["lib_paths"])
        if entry.get("env"):
            prog["env"] = dict(entry["env"])
        if entry.get("harness"):
            prog["harness"] = dict(entry["harness"])
        if entry.get("make_steps"):
            prog["make_steps"] = [list(step) for step in entry["make_steps"]]
        out[str(entry["family"])] = prog
    return out


def runners() -> dict[str, Callable[[dict], dict]]:
    """The bucket workload for each configured family."""
    return {str(e["family"]): partial(run_template, str(e["family"])) for e in families()}


# --------------------------------------------------------------------------------------------
# build helpers shared by every template
# --------------------------------------------------------------------------------------------

def write_pkgconfig_shim(work: Path, prefix: Path) -> Path:
    """Write ``libssl.pc`` / ``libcrypto.pc`` for a subject prefix that ships none.

    Several upstream ``configure`` scripts probe with ``pkg-config libssl``.
    The candidate drop-in install intentionally carries no ``openssl.pc``; this
    shim is a generated build input (never a source patch) pointing at exactly
    the subject prefix, and is identical for both subjects.
    """
    pc_dir = work / "pkgconfig"
    pc_dir.mkdir(parents=True, exist_ok=True)
    version = "3"
    for header in (prefix / "include" / "openssl" / "opensslv.h",):
        try:
            text = header.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"OPENSSL_VERSION_STR\s+\"([^\"]+)\"", text)
            if m:
                version = m.group(1)
        except OSError:
            pass
    for name, lib in (("libssl", "ssl"), ("libcrypto", "crypto")):
        (pc_dir / f"{name}.pc").write_text(
            "Description: subject-prefix shim for the openssl-rs template layer\n"
            f"prefix={prefix}\nlibdir={prefix}/lib\nincludedir={prefix}/include\n"
            f"Name: {name}\nVersion: {version}\n"
            f"Libs: -L{prefix}/lib -l{lib}\nCflags: -I{prefix}/include\n",
            encoding="utf-8")
    return pc_dir


def _run(argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
         timeout: int = 120, input_text: str | None = None) -> dict:
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(cwd) if cwd else None, env=env,
                              capture_output=True, text=True, timeout=timeout,
                              input=input_text, check=False)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        code = -1
        out = (exc.stdout or b"").decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) \
            else (exc.stdout or "")
        err = f"TIMEOUT after {timeout}s"
    except (FileNotFoundError, OSError) as exc:
        code, out, err = 127, "", str(exc)
    return {"argv": argv, "exit_code": code, "ok": code == 0, "stdout": out, "stderr": err,
            "elapsed_seconds": round(time.monotonic() - start, 3)}


def _expand(value: Any, mapping: dict[str, Any]) -> Any:
    """Substitute only the named ``{placeholders}`` (regex braces are left alone)."""
    if isinstance(value, list):
        return [_expand(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v, mapping) for k, v in value.items()}
    if isinstance(value, str):
        out = value
        for key, val in mapping.items():
            out = out.replace("{" + key + "}", str(val))
        return out
    return value


def _transcript(parts: list[tuple[str, dict]]) -> str:
    lines: list[str] = []
    for label, res in parts:
        lines.append(f"== {label} ==")
        lines.append(f"exit={res.get('exit_code')}")
        if res.get("stdout"):
            lines.append(str(res["stdout"]).rstrip())
        if res.get("stderr"):
            lines.append(str(res["stderr"]).rstrip())
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------
# deterministic ports and TMPDIR isolation
# --------------------------------------------------------------------------------------------

def allocate_port(family: str, purpose: str, *, host: str = "127.0.0.1",
                  attempts: int = 64) -> int:
    """A deterministic loopback port derived from (family, purpose).

    The port is a function of the family and purpose, never of wall-clock or PID
    state.  A collision is resolved by walking forward deterministically; the
    chosen port is normalised out of the transcript by the runtime atlas.
    """
    digest = hashlib.sha256(f"{family}:{purpose}".encode("utf-8")).hexdigest()
    base = 21000 + (int(digest[:8], 16) % 20000)
    for i in range(attempts):
        port = 21000 + ((base - 21000 + i) % 20000)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError:
                continue
        return port
    raise RuntimeError(f"no free deterministic port for {family}:{purpose}")


def isolated_tmpdir(workdir: Path) -> Path:
    """A per-run TMPDIR under the court scratch tree (never a shared /tmp)."""
    tmp = workdir / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp


def _env_for(ctx: dict, *, tmpdir: Path | None = None) -> dict:
    env = dict(ctx.get("env") or os.environ)
    if tmpdir is not None:
        env["TMPDIR"] = str(tmpdir)
        env["TMP"] = str(tmpdir)
        env["TEMP"] = str(tmpdir)
    return env


# --------------------------------------------------------------------------------------------
# admission: refuse L7 for a binary that never loads the subject
# --------------------------------------------------------------------------------------------

def admit_binary(program: Path, prefix: Path, authority_prefix: Path | None = None,
                 env: dict | None = None) -> dict:
    """Read the loader's own resolution of libssl/libcrypto and decide admission.

    This is the generic admission gate: a family may not claim L6/L7 merely
    because its recipe built.  At least one OpenSSL soname must appear in the
    program's transitive ``ldd`` closure, every one that appears must resolve
    under the subject prefix, and a candidate prefix must not resolve any of
    them under the admitted authority.
    """
    run_env = dict(env or os.environ)
    ldd = _run(["ldd", str(program)], env=run_env, timeout=60)
    sonames: dict[str, dict] = {}
    under_all = True
    under_auth = False
    for line in (ldd.get("stdout") or "").splitlines():
        left = line.split("=>")[0].strip()
        if not (left == "libssl.so" or left.startswith("libssl.so.") or
                left == "libcrypto.so" or left.startswith("libcrypto.so.")):
            continue
        resolved = ""
        if "=>" in line:
            resolved = line.split("=>", 1)[1].strip().split(" (")[0].strip()
        under = bool(resolved) and _under(resolved, prefix)
        under_authority = bool(resolved) and authority_prefix is not None and \
            _under(resolved, authority_prefix)
        sonames[left] = {"resolved": resolved or "unresolved", "under_prefix": under,
                         "under_authority": under_authority}
        under_all = under_all and under
        under_auth = under_auth or under_authority
    is_authority = authority_prefix is None or _same_path(prefix, authority_prefix)
    admitted = bool(sonames) and under_all and (is_authority or not under_auth)
    reason = None
    if not sonames:
        reason = "the program's loader closure names no libssl/libcrypto"
    elif not under_all:
        reason = "an OpenSSL soname resolves outside the subject prefix"
    elif not is_authority and under_auth:
        reason = "a candidate OpenSSL soname resolves under the authority prefix"
    return {"admitted": admitted, "sonames": sonames, "reason": reason,
            "ldd_exit": ldd.get("exit_code"), "all_under_prefix": under_all,
            "resolved_under_authority": under_auth}


def _same_path(a: Path, b: Path) -> bool:
    try:
        return os.path.realpath(str(a)) == os.path.realpath(str(b))
    except OSError:
        return False


def _under(path: str, prefix: Path) -> bool:
    try:
        return os.path.realpath(path).startswith(os.path.realpath(str(prefix)) + os.sep)
    except OSError:
        return False


# --------------------------------------------------------------------------------------------
# the consumer-API invariant (enforced, never merely documented)
# --------------------------------------------------------------------------------------------
#
# A workload is admitted only when the artifact that proves L7 is the consumer
# itself.  The generic rule has two verifiable limbs:
#
#   1. the consumer artifact (the family's program, or the named consumer shared
#      library) must have at least one *undefined* OpenSSL symbol in its own
#      dynamic symbol table -- i.e. its code calls into the subject OpenSSL; and
#   2. when the workload is a compiled typed harness that links a consumer
#      library, the harness must reference at least one symbol the consumer
#      library exports, and the harness must import **zero** OpenSSL symbols.
#
# Limb 2 is what rejects the false L7 in the brief: a harness that links the
# consumer library but only calls OpenSSL itself is refused with
# `failure_class=false-l7` and cannot be recorded as functional.  The local
# fixture peer (an HTTPS/FTPS listener in this module) may use Python's `ssl`;
# it is a peer, not the workload, and is recorded separately as
# `fixture_openssl=true` -- it is never counted as the consumer's call.

_OPENSSL_SYMBOL_PREFIXES: tuple[str, ...] = (
    "EVP_", "SHA", "HMAC", "X509", "SSL_", "OPENSSL_", "CRYPTO_", "BN_", "RSA_",
    "EC_", "ECDSA_", "PEM_", "PKCS", "BIO_", "ERR_", "RAND_", "OBJ_", "ASN1_",
    "BUF_", "OSSL_", "ENGINE_", "CMS_", "OCSP", "CONF_", "TS_", "POLY1305",
    "CHACHA20", "AES_", "DES_", "MD5", "MD4", "RIPEMD", "WHIRLPOOL", "BLAKE2",
)


def _is_openssl_symbol(symbol: str) -> bool:
    return any(symbol.startswith(prefix) for prefix in _OPENSSL_SYMBOL_PREFIXES)


def _symbol_name(line: str) -> str:
    """The bare symbol from one ``nm`` line (version suffixes removed)."""
    parts = line.split()
    if not parts:
        return ""
    return parts[-1].split("@", 1)[0]


def _nm_symbols(path: Path, *args: str) -> list[str]:
    res = _run(["nm", *args, str(path)], timeout=60)
    if not res["ok"] and "-D" in args:
        # A relocatable object (the typed harness before linking) has no dynamic
        # table; fall back to the ordinary symbol table for that one case.
        args = tuple(a for a in args if a != "-D")
        res = _run(["nm", *args, str(path)], timeout=60)
    return [_symbol_name(line) for line in (res.get("stdout") or "").splitlines()
            if _symbol_name(line)]


def _undefined_symbols(path: Path) -> list[str]:
    return _nm_symbols(path, "-D", "-u") or _nm_symbols(path, "-u")


def _defined_symbols(path: Path) -> list[str]:
    return _nm_symbols(path, "-D", "--defined-only") or \
        _nm_symbols(path, "--defined-only")


def _real_binary(path: Path) -> Path:
    """Resolve a libtool wrapper to the ELF it launches."""
    try:
        if path.is_file() and path.read_bytes()[:4] == b"\x7fELF":
            return path
    except OSError:
        return path
    sibling = path.parent / ".libs" / path.name
    try:
        if sibling.is_file() and sibling.read_bytes()[:4] == b"\x7fELF":
            return sibling
    except OSError:
        pass
    return path


def verify_consumer_boundary(entry: dict, ctx: dict, *, program: Path | None = None,
                             harness_obj: Path | None = None) -> dict:
    """Prove the workload exercises the consumer's own OpenSSL-consuming code.

    ``entry["consumer"]`` is required for the mechanism templates:

    * ``{"self": true}`` -- the family's executable is the consumer; it must
      import at least one OpenSSL symbol.
    * ``{"library_globs": [...], "required_symbols": [...]}`` -- the workload
      must link one of the named consumer libraries, that library must import
      OpenSSL, and (for a typed harness) the harness must reference a symbol
      the library exports while importing no OpenSSL symbol itself.

    Returns ``{"ok": bool, "reason": str|None, "evidence": {...}}``.  A caller
    must not record a functional workload when ``ok`` is false.
    """
    spec = entry.get("consumer") or {}
    root = Path(ctx["root"])
    target = _real_binary(Path(program or ctx["program"]))
    libraries: list[Path] = []
    for pattern in spec.get("library_globs") or ():
        libraries.extend(sorted(root.glob(str(pattern))))
    libraries = [p for p in libraries if p.is_file()]
    self_mode = bool(spec.get("self")) or (not libraries and not spec.get("library_globs"))
    evidence: dict = {
        "rule": "consumer-boundary/1",
        "consumer_mode": "self" if self_mode else "library",
        "workload": str(target),
        "fixture_openssl": bool(spec.get("fixture_openssl", False)),
    }
    if not target.is_file():
        return {"ok": False, "reason": f"the workload artifact {target} does not exist",
                "evidence": evidence}
    if not self_mode and not libraries:
        return {"ok": False, "reason": "the configured consumer library was not built",
                "evidence": evidence}

    consumer_artifacts = [target] if self_mode else libraries
    for artifact in consumer_artifacts:
        undefined = _undefined_symbols(artifact)
        openssl = [s for s in undefined if _is_openssl_symbol(s)]
        evidence.setdefault("consumers", []).append({
            "artifact": str(artifact),
            "undefined_symbols": len(undefined),
            "openssl_imports": len(openssl),
            "openssl_sample": openssl[:8],
        })
        if not openssl:
            return {
                "ok": False,
                "reason": (f"{artifact} imports no OpenSSL symbol: a workload that does not "
                           "call the consumer's OpenSSL path is a false L7"),
                "evidence": evidence,
            }

    if harness_obj is not None:
        harness = _real_binary(Path(harness_obj))
        h_undefined = _undefined_symbols(harness)
        h_openssl = [s for s in h_undefined if _is_openssl_symbol(s)]
        evidence["harness"] = {"artifact": str(harness),
                               "undefined_symbols": len(h_undefined),
                               "openssl_imports": h_openssl[:8]}
        if h_openssl:
            return {
                "ok": False,
                "reason": ("the typed harness itself imports OpenSSL ("
                           + ", ".join(h_openssl[:4])
                           + "); the workload must exercise the consumer's OpenSSL path, not "
                             "reimplement it in the harness"),
                "evidence": evidence,
            }
        if not self_mode:
            defined: set[str] = set()
            for library in libraries:
                defined.update(_defined_symbols(library))
            referenced = [s for s in h_undefined if s in defined]
            evidence["harness"]["consumer_symbols_referenced"] = len(referenced)
            evidence["harness"]["consumer_symbols_sample"] = referenced[:8]
            if not referenced:
                return {
                    "ok": False,
                    "reason": ("the typed harness references no symbol exported by the consumer "
                               "library, so the consumer's code is not actually exercised"),
                    "evidence": evidence,
                }
            required = [str(s) for s in spec.get("required_symbols") or ()]
            missing = [needle for needle in required
                       if not any(needle in symbol for symbol in referenced)]
            if missing:
                return {
                    "ok": False,
                    "reason": ("the typed harness does not reference the declared consumer "
                               f"symbol(s) {missing}"),
                    "evidence": evidence,
                }

    if not self_mode:
        ldd = _run(["ldd", str(target)], timeout=60)
        evidence["workload_ldd_names_consumer"] = any(
            library.name in (ldd.get("stdout") or "") for library in libraries)
        if not evidence["workload_ldd_names_consumer"]:
            return {
                "ok": False,
                "reason": (f"the workload's loader closure does not name {libraries[0].name}; "
                           "linking is not exercising the consumer"),
                "evidence": evidence,
            }
    return {"ok": True, "reason": None, "evidence": evidence}


# --------------------------------------------------------------------------------------------
# fixtures: PKI, HTTPS, plaintext negative peer, Gemini/TLS peer
# --------------------------------------------------------------------------------------------

def _openssl(ctx: dict, argv: list[str], cwd: Path) -> dict:
    binary = ctx["authority_prefix"] / "bin" / "openssl"
    if not binary.is_file():
        binary = Path(shutil.which("openssl") or "openssl")
    env = _env_for(ctx)
    # The authority CLI resolves its own libssl/libcrypto from its prefix; a subject
    # LD_LIBRARY_PATH (the runtime's ctx env) would otherwise shadow them.  The prefix ships no
    # ssl/openssl.cnf, and the fixture supplies every distinguished name/extensions explicitly, so
    # an empty config is the honest input (the same choice the runtime's own PKI helper makes).
    env["LD_LIBRARY_PATH"] = os.pathsep.join(
        [str(ctx["authority_prefix"] / "lib"), env.get("LD_LIBRARY_PATH", "")]).rstrip(
            os.pathsep)
    env["OPENSSL_CONF"] = "/dev/null"
    return _run([str(binary), *argv], cwd=cwd, env=env, timeout=60)


def _generate_pki(ctx: dict) -> dict:
    d = ctx["workdir"] / "pki"
    d.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt = d / "ca.key", d / "ca.crt"
    srv_key, srv_crt = d / "server.key", d / "server.crt"
    wrong_key, wrong_crt = d / "wrong.key", d / "wrong.crt"
    steps = [
        ["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2",
         "-subj", "/CN=template-ca", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", str(ca_key), "-out", str(ca_crt)],
        ["req", "-newkey", "rsa:2048", "-sha256", "-nodes", "-subj", "/CN=localhost",
         "-keyout", str(srv_key), "-out", str(d / "server.csr")],
        ["x509", "-req", "-sha256", "-days", "2", "-in", str(d / "server.csr"),
         "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
         "-extfile", str(_write_san(d)), "-out", str(srv_crt)],
        ["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2",
         "-subj", "/CN=wrong-ca", "-keyout", str(wrong_key), "-out", str(wrong_crt)],
    ]
    for argv in steps:
        res = _openssl(ctx, argv, d)
        if not res["ok"]:
            raise RuntimeError(f"PKI fixture failed: {census._error_line(res)}")
    return {"ca": ca_crt, "cert": srv_crt, "key": srv_key, "wrong_ca": wrong_crt}


def _write_san(d: Path) -> Path:
    path = d / "san.cnf"
    path.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                    "basicConstraints=CA:FALSE\n"
                    "keyUsage=digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth\n", encoding="utf-8")
    return path


class _HTTPFixture:
    """A deterministic loopback HTTP peer; TLS-wrapped for the positive fixture."""

    def __init__(self, port: int, body: str, *, cert: Path | None = None,
                 key: Path | None = None):
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.requests = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib name
                outer.requests += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args):  # noqa: D401 - silence
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        if cert and key:
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(str(cert), str(key))
            self.server.socket = sctx.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        return False


class _FTPSFixture:
    """A deterministic loopback FTPS peer (explicit ``AUTH TLS``) for the x509 template.

    The peer only presents a certificate chain.  The *consumer* is the family's
    program: it performs the chain verification and is the workload's OpenSSL
    caller.  ``SSL_CERT_FILE`` selects the trust anchor for each run, so the
    positive and negative controls differ only in the CA (and never in the
    server, payload or URL).
    """

    def __init__(self, port: int, body: bytes, *, cert: Path, key: Path):
        self.body = body
        self.sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.sslctx.load_cert_chain(str(cert), str(key))
        try:
            self.sock = socket.create_server(("::", port), family=socket.AF_INET6,
                                            dualstack_ipv6=True, backlog=16)
        except (OSError, AttributeError):
            self.sock = socket.create_server(("127.0.0.1", port), backlog=16)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self._closed = False

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self._closed = True
        try:
            self.sock.close()
        except OSError:
            pass
        return False

    def _serve(self):
        while not self._closed:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn):
        buffer = b""
        wrapped = False
        data_listener = None

        def readline():
            nonlocal buffer
            while b"\n" not in buffer:
                chunk = conn.recv(4096)
                if not chunk:
                    return None
                buffer += chunk
            line, _, buffer = buffer.partition(b"\n")
            return line.decode("latin-1").strip()

        def send(text):
            conn.sendall((text + "\r\n").encode("latin-1"))

        def open_data_listener():
            try:
                listener = socket.create_server(("::", 0), family=socket.AF_INET6,
                                                dualstack_ipv6=True, backlog=4)
            except (OSError, AttributeError):
                listener = socket.create_server(("127.0.0.1", 0), backlog=4)
            return listener

        try:
            send("220 s65 FTP fixture")
            while True:
                line = readline()
                if line is None:
                    return
                command, _, argument = line.partition(" ")
                command = command.upper()
                argument = argument.strip()
                if command == "AUTH" and argument.upper() == "TLS":
                    send("234 AUTH TLS accepted")
                    conn = self.sslctx.wrap_socket(conn, server_side=True)
                    wrapped = True
                elif command == "PBSZ":
                    send("200 PBSZ 0")
                elif command == "PROT":
                    send("200 PROT P")
                elif command == "USER":
                    send("331 password required")
                elif command == "PASS":
                    send("230 logged in")
                elif command == "SYST":
                    send("215 UNIX Type: L8")
                elif command == "FEAT":
                    send("211-Features:"); send(" AUTH TLS"); send(" PBSZ")
                    send(" PROT"); send("211 End")
                elif command in ("TYPE", "OPTS", "MODE", "STRU", "NOOP"):
                    send("200 ok")
                elif command == "PWD":
                    send('257 "/"')
                elif command in ("CWD", "CDUP"):
                    send("250 ok")
                elif command == "SIZE":
                    send(f"213 {len(self.body)}")
                elif command == "MDTM":
                    send("213 20260101000000")
                elif command == "PASV":
                    if data_listener is not None:
                        data_listener.close()
                    data_listener = open_data_listener()
                    port = data_listener.getsockname()[1]
                    send(f"227 Entering Passive Mode (127,0,0,1,{port // 256},{port % 256})")
                elif command == "EPSV":
                    if data_listener is not None:
                        data_listener.close()
                    data_listener = open_data_listener()
                    port = data_listener.getsockname()[1]
                    send(f"229 Entering Extended Passive Mode (|||{port}|)")
                elif command in ("LIST", "NLST"):
                    if data_listener is None:
                        send("425 use PASV first")
                        continue
                    send("150 opening data connection")
                    data_conn, _ = data_listener.accept()
                    try:
                        if wrapped:
                            data_conn = self.sslctx.wrap_socket(data_conn, server_side=True)
                        if command == "NLST":
                            listing = b"payload.bin\r\n"
                        else:
                            listing = (f"-rw-r--r-- 1 ftp ftp {len(self.body)} Jan 01 00:00 "
                                       "payload.bin\r\n").encode("latin-1")
                        data_conn.sendall(listing)
                        data_conn.close()
                    except OSError:
                        pass
                    data_listener.close()
                    data_listener = None
                    send("226 transfer complete")
                elif command == "RETR":
                    if data_listener is None:
                        send("425 use PASV first")
                        continue
                    send("150 opening data connection")
                    data_conn, _ = data_listener.accept()
                    try:
                        if wrapped:
                            data_conn = self.sslctx.wrap_socket(data_conn, server_side=True)
                        data_conn.sendall(self.body)
                        data_conn.close()
                    except OSError:
                        pass
                    data_listener.close()
                    data_listener = None
                    send("226 transfer complete")
                elif command == "QUIT":
                    send("221 bye")
                    return
                else:
                    send("502 command not implemented")
        except (OSError, ssl.SSLError):
            return
        finally:
            if data_listener is not None:
                try:
                    data_listener.close()
                except OSError:
                    pass
            try:
                conn.close()
            except OSError:
                pass


def _wait_tcp(port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.1)
    return False


def _write_fixture_files(ctx: dict) -> dict:
    d = ctx["workdir"] / "fixtures"
    d.mkdir(parents=True, exist_ok=True)
    payload = d / "payload.bin"
    tampered = d / "tampered.bin"
    payload.write_bytes(b"template-payload\n")
    tampered.write_bytes(b"template-payloaX\n")
    text = d / "payload.txt"
    text.write_text("template-payload\n", encoding="utf-8")
    return {"payload": payload, "tampered": tampered, "payload_txt": text}


# --------------------------------------------------------------------------------------------
# bucket templates
# --------------------------------------------------------------------------------------------

def run_template(name: str, ctx: dict) -> dict:
    entry = _BY_FAMILY.get(name)
    if entry is None:
        return _fail("no template entry for this family", "harness-failure")
    workloads = entry.get("workload") or {}
    if isinstance(workloads, dict):
        workloads = [workloads]
    tmpdir = isolated_tmpdir(ctx["workdir"])
    env = _env_for(ctx, tmpdir=tmpdir)
    env.setdefault("HOME", str(ctx["workdir"]))
    # The caller's env carries LD_LIBRARY_PATH; keep it and add the isolated TMPDIR.
    ctx = dict(ctx, env=env)
    handlers: dict[str, Callable[[dict, dict], dict]] = {
        "digest": _tpl_digest,
        "http_client": _tpl_http,
        "http_bench": _tpl_http,
        "http_mirror": _tpl_http,
        "tls_server": _tpl_tls_server,
        "signature": _tpl_signature,
        "ssh_client": _tpl_ssh_client,
        "x509_verification": _tpl_x509_verification,
        "evp_signing": _tpl_evp_signing,
        "aead_roundtrip": _tpl_aead_roundtrip,
        "hmac_kdf": _tpl_hmac_kdf,
    }
    results: list[dict] = []
    for wl in workloads:
        kind = (wl or {}).get("template")
        handler = handlers.get(str(kind))
        if handler is None:
            return _fail(f"template {kind!r} is not implemented in this venue",
                         "harness-failure")
        try:
            results.append(handler(dict(entry, workload=wl), ctx))
        except Exception as exc:  # noqa: BLE001 - a fixture failure is recorded, never raised
            return _fail(f"the {kind} template failed: {exc}", "harness-failure")
    if len(results) == 1:
        return results[0]
    functional = all(r.get("functional_ok") for r in results)
    runtime_ok = all(r.get("runtime_ok") for r in results)
    first_bad = next((r for r in results if not r.get("functional_ok")), None)
    return {
        "runtime_ok": runtime_ok,
        "functional_ok": functional,
        "failure_class": None if functional else (first_bad or {}).get("failure_class"),
        "residual": "none" if functional else (first_bad or {}).get("residual"),
        "reason": None if functional else "; ".join(
            str(r.get("reason")) for r in results if r.get("reason")),
        "transcript": "\n\n".join(str(r.get("transcript") or "") for r in results),
        "workload": f"{name}: " + " + ".join(
            str((r.get("workload") or "").split(": ", 1)[-1]) for r in results),
        "consumer_evidence": [r.get("consumer_evidence") for r in results
                              if r.get("consumer_evidence") is not None],
        "local_only": True,
    }


def _fail(reason: str, failure_class: str) -> dict:
    return {"runtime_ok": False, "functional_ok": False, "failure_class": failure_class,
            "residual": "out-of-scope", "reason": reason, "transcript": "",
            "workload": "template", "local_only": True}


def _base(entry: dict, ctx: dict, wl: dict) -> dict[str, Any]:
    files = _write_fixture_files(ctx)
    port = allocate_port(str(entry["family"]), "positive")
    return {"files": files, "port": port, "entry": entry, "ctx": ctx, "wl": wl,
            "workdir": ctx["workdir"], "root": ctx["root"], "program": ctx["program"]}


def _expand_wl(value: Any, body: dict, *, extra: dict | None = None) -> Any:
    mapping = {
        "payload": body["files"]["payload"],
        "tampered": body["files"]["tampered"],
        "payload_txt": body["files"]["payload_txt"],
        "workdir": body["workdir"],
        "root": body["root"],
        "port": body["port"],
        "ca": (body.get("ca") or ""),
        "cert": (body.get("cert") or ""),
        "key": (body.get("key") or ""),
        "pem": (body.get("pem") or ""),
        "wrong_ca": (body.get("wrong_ca") or ""),
        "url": (body.get("url") or ""),
        "config": (body.get("config") or ""),
    }
    if extra:
        mapping.update(extra)
    return _expand(value, mapping)


def _tpl_digest(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    argv = _expand_wl(wl["argv"], b)
    pos = _run([str(ctx["program"]), *argv], cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    expect = str(wl["expect"])
    pos_match = re.search(expect, pos["stdout"] + pos["stderr"], re.MULTILINE)
    neg_argv = _expand_wl(wl.get("negative_argv") or wl["argv"], b)
    neg = _run([str(ctx["program"]), *neg_argv], cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    # The negative control compares the *expectation* the family declares, not an assumed
    # lowercase-hex shape: NSEC3 hashes are base32hex and would otherwise never be compared.
    different = bool(pos_match) and pos_match.group(0) not in (neg["stdout"] + neg["stderr"])
    functional = bool(pos["ok"] and pos_match and (different or neg["exit_code"] != 0))
    return {
        "runtime_ok": bool(pos["ok"]),
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos["ok"] else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos["ok"] else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the digest tool did not produce the expected digest" if not pos_match else
            "a tampered input did not change the digest"),
        "transcript": _transcript([("digest", pos), ("tampered input", neg)]),
        "workload": f"{entry['family']}: digest bucket",
        "local_only": True,
    }


def _http_client_argv(entry: dict, body: dict, *, negative: bool) -> list[str]:
    wl = entry["workload"]
    argv = wl.get("negative_argv") if negative and wl.get("negative_argv") else wl["argv"]
    mode = str(wl.get("negative", "wrong_ca"))
    ca = body["ca"]
    url = body["url"]
    port = body["port"]
    if negative:
        if mode in ("plaintext", "closed_port"):
            url = f"https://127.0.0.1:{body['neg_port']}/"
            port = body["neg_port"]
            ca = body["ca"]
        else:
            ca = body["wrong_ca"]
    return _expand_wl(argv, body, extra={"url": url, "ca": ca, "port": port})


def _mirror_has(ctx: dict, needle: str, name: str = "mirror") -> bool:
    mirror = ctx["workdir"] / name
    return any(p.is_file() and needle.encode("utf-8") in p.read_bytes()
               for p in mirror.rglob("*")) if mirror.exists() else False


def _tpl_http(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    pki = _generate_pki(ctx)
    b["ca"], b["wrong_ca"] = pki["ca"], pki["wrong_ca"]
    b["url"] = f"https://127.0.0.1:{b['port']}/"
    neg_port = allocate_port(str(entry["family"]), "negative")
    b["neg_port"] = neg_port
    body_text = str(wl.get("expect", "template-payload"))
    mode = str(wl.get("negative", "wrong_ca"))
    results: list[tuple[str, dict]] = []
    functional = False
    mirror_ok = False
    with _HTTPFixture(b["port"], body_text, cert=pki["cert"], key=pki["key"]) as good:
        if mode == "plaintext":
            with _HTTPFixture(neg_port, body_text) as plain:
                pos = _run([str(ctx["program"]), *_http_client_argv(entry, b, negative=False)],
                           cwd=ctx["workdir"], env=ctx["env"], timeout=120)
                neg = _run([str(ctx["program"]), *_http_client_argv(entry, b, negative=True)],
                           cwd=ctx["workdir"], env=ctx["env"], timeout=120)
                results += [("positive", pos), ("negative (plaintext peer)", neg)]
                good_requests, plain_requests = good.requests, plain.requests
        else:
            # ``closed_port`` is for a client that does not verify certificates (wrk): an
            # unrelated CA is not a rejection it can express, but a refused connection must
            # never be reported as a successful transaction.
            pos = _run([str(ctx["program"]), *_http_client_argv(entry, b, negative=False)],
                       cwd=ctx["workdir"], env=ctx["env"], timeout=120)
            neg = _run([str(ctx["program"]), *_http_client_argv(entry, b, negative=True)],
                       cwd=ctx["workdir"], env=ctx["env"], timeout=120)
            results += [("positive", pos), ("negative (no listener)", neg)]
            good_requests, plain_requests = good.requests, 0
    pos_match = re.search(str(wl["expect"]), pos["stdout"] + pos["stderr"], re.MULTILINE)
    if wl["template"] == "http_mirror":
        mirror_ok = _mirror_has(ctx, body_text)
        # httrack's own progress log is not the evidence; the mirrored payload is.
        pos_match = mirror_ok
    if mode == "closed_port":
        # The client must not report the refused connection as a completed transaction.
        neg_output = neg["stdout"] + neg["stderr"]
        neg_bad = (neg["exit_code"] != 0
                   and re.search(str(wl["expect"]), neg_output, re.MULTILINE) is None)
    else:
        neg_bad = (neg["exit_code"] != 0 or not re.search(
            str(wl["expect"]), neg["stdout"] + neg["stderr"], re.MULTILINE)) \
            and not (wl["template"] == "http_mirror"
                     and _mirror_has(ctx, body_text, "mirror-neg"))
    functional = bool(pos["ok"] and pos_match and good_requests >= 1 and neg_bad
                      and (mirror_ok if wl["template"] == "http_mirror" else True))
    return {
        "runtime_ok": bool(pos["ok"]),
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos["ok"] else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos["ok"] else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the client did not complete the expected HTTPS exchange" if not pos_match else
            "the negative-control peer was not rejected" if not neg_bad else
            "the mirror did not contain the fixture payload"),
        "transcript": _transcript(results),
        "workload": f"{entry['family']}: {wl['template']} bucket",
        "local_only": True,
    }


def _tpl_tls_server(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    workdir = ctx["workdir"]
    root = workdir / "root"
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.gmi").write_text("template-payload\n", encoding="utf-8")
    # A family that does not mint its own certificate (lighttpd, h2o, httpd) is given the same
    # fixture PKI the HTTP bucket uses; the server certificate is CA-signed, so the positive
    # client verifies it and an unrelated CA must be rejected.  A family that generates its own
    # certificate on first use (gmnisrv) keeps `cert_path` and never references these names.
    pki = _generate_pki(ctx)
    pem = workdir / "pki" / "server.pem"
    pem.write_bytes(pki["cert"].read_bytes() + pki["key"].read_bytes())
    b["ca"], b["wrong_ca"] = pki["ca"], pki["wrong_ca"]
    b["cert"], b["key"], b["pem"] = pki["cert"], pki["key"], pem
    config_path = workdir / "server.conf"
    b["config"] = config_path
    config_path.write_text(str(_expand_wl(wl["config"], b)), encoding="utf-8")
    argv = [str(ctx["program"]), *_expand_wl(wl["server_argv"], b)]
    server = subprocess.Popen(argv, cwd=str(workdir), env=ctx["env"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if not _wait_tcp(b["port"], timeout=20):
            out, err = server.communicate(timeout=5)
            return _fail(f"the TLS server did not listen: {(err or out or '')[-300:]}",
                         "runtime-failure")
        cert_path = Path(str(_expand_wl(wl.get("cert_path", "{ca}"), b)))
        # gmnisrv creates its self-signed certificate on first use; trigger and wait.
        deadline = time.monotonic() + 5
        while not cert_path.is_file() and time.monotonic() < deadline:
            try:
                raw = ssl._create_unverified_context().wrap_socket(
                    socket.create_connection(("127.0.0.1", b["port"]), timeout=2),
                    server_hostname="localhost")
                raw.close()
            except OSError:
                pass
            time.sleep(0.1)
        good = _tls_exchange(b["port"], cert_path, str(wl.get("payload", "")),
                             verify_host=True,
                             read_once=bool(wl.get("read_once")),
                             payload_bytes=(bytes.fromhex(str(wl["payload_hex"]))
                                            if wl.get("payload_hex") else None))
        wrong = _tls_exchange(b["port"], b["wrong_ca"],
                              str(wl.get("payload", "")), verify_host=True,
                              read_once=bool(wl.get("read_once")),
                              payload_bytes=(bytes.fromhex(str(wl["payload_hex"]))
                                             if wl.get("payload_hex") else None))
    finally:
        server.terminate()
        try:
            out, err = server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            out, err = server.communicate()
    expect = str(wl["expect"])
    pos_match = bool(good.get("data")) and re.search(expect, good.get("data", ""),
                                                     re.MULTILINE) is not None
    neg_rejected = not wrong.get("ok")
    functional = bool(pos_match and neg_rejected)
    return {
        "runtime_ok": pos_match,
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos_match else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos_match else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the TLS server did not return the expected protocol response" if not pos_match else
            "a client trusting only an unrelated CA was not rejected"),
        "transcript": _transcript([("tls client", {"exit_code": 0 if good.get("ok") else 1,
                                                   "stdout": good.get("data", ""),
                                                   "stderr": good.get("error", "")}),
                                   ("unrelated CA (must fail)",
                                    {"exit_code": 0 if wrong.get("ok") else 1,
                                     "stdout": wrong.get("data", ""),
                                     "stderr": wrong.get("error", "")}),
                                   ("server", {"exit_code": server.returncode,
                                               "stdout": (out or "")[-1000:],
                                               "stderr": (err or "")[-1000:]})]),
        "workload": f"{entry['family']}: {wl.get('protocol', 'TLS')} server bucket",
        "local_only": True,
    }


def _tls_exchange(port: int, ca: Path, payload: str, *, verify_host: bool,
                 server_hostname: str = "localhost", read_once: bool = False,
                 payload_bytes: bytes | None = None) -> dict:
    try:
        sctx = ssl.create_default_context(cafile=str(ca))
        sctx.check_hostname = verify_host
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            with sctx.wrap_socket(sock, server_hostname=server_hostname) as tls:
                # The exchange is bounded: a server that keeps the connection open (or a
                # forked worker that never closes its copy) must not hang the court. The
                # timeout is evidence-neutral: it only turns a stall into a measured error.
                tls.settimeout(10)
                tls.sendall(payload_bytes if payload_bytes is not None
                            else payload.encode("utf-8"))
                if read_once:
                    # A protocol whose server greets and then holds the connection open (IRC)
                    # never sends EOF; one bounded read is the whole response the contract
                    # promises, so return it rather than reading until the timeout.
                    chunk = tls.recv(4096)
                    return {"ok": True, "data": chunk.decode("utf-8", "replace"),
                            "error": ""}
                chunks: list[bytes] = []
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return {"ok": True, "data": b"".join(chunks).decode("utf-8", "replace"),
                        "error": ""}
    except (ssl.SSLError, OSError) as exc:
        return {"ok": False, "data": "", "error": str(exc)}


def _tpl_signature(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    pos = _run([str(ctx["program"]), *_expand_wl(wl["argv"], b)], cwd=ctx["workdir"],
               env=ctx["env"], timeout=120)
    neg = _run([str(ctx["program"]), *_expand_wl(wl.get("negative_argv") or wl["argv"], b)],
               cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    signed = Path(str(_expand_wl("{workdir}/signed.appx", b)))
    unsigned = Path(str(_expand_wl("{workdir}/unsigned.appx", b)))
    entry_name = str(wl["artifact_entry"])
    signed_ok = _zip_has_entry(signed, entry_name)
    unsigned_ok = unsigned.is_file() and not _zip_has_entry(unsigned, entry_name)
    functional = bool(pos["ok"] and signed_ok and neg["ok"] and unsigned_ok)
    return {
        "runtime_ok": bool(pos["ok"] and signed.is_file()),
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos["ok"] else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos["ok"] else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the signed artifact did not contain the signature entry" if not signed_ok else
            "the unsigned control unexpectedly contained a signature entry"),
        "transcript": _transcript([("signed", pos), ("unsigned control", neg)]),
        "workload": f"{entry['family']}: signature bucket",
        "local_only": True,
    }


def _zip_has_entry(path: Path, name: str) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return any(info.filename == name and info.file_size > 0 for info in zf.infolist())
    except (OSError, zipfile.BadZipFile):
        return False


# --------------------------------------------------------------------------------------------
# mechanism templates
# --------------------------------------------------------------------------------------------

def _gate_reject(gate: dict, transcript: str) -> dict:
    """The one outcome a workload that fails the consumer gate can have."""
    return {
        "runtime_ok": False,
        "functional_ok": False,
        # The closed failure taxonomy has no `false-l7`; a workload rejected by
        # the consumer gate is a harness failure whose reason names the
        # invariant.  It can never be promoted to L7.
        "failure_class": "harness-failure",
        "residual": "out-of-scope",
        "reason": f"false-L7 rejected by the consumer-API invariant: {gate.get('reason')}",
        "transcript": transcript,
        "workload": "template (false-L7 rejected)",
        "consumer_evidence": gate.get("evidence"),
        "local_only": True,
    }


def _tpl_x509_verification(entry: dict, ctx: dict) -> dict:
    """Accept a chain signed by the trusted CA; reject one signed by an unrelated CA.

    ``mode: "peer"`` (the proof family) drives the consumer against a local FTPS
    peer whose certificate is signed by the fixture CA.  ``SSL_CERT_FILE`` is
    the only difference between the positive and negative runs.  ``mode:
    "chain"`` is for an offline chain verifier: ``argv`` names ``{ca}`` and
    ``negative_argv`` names ``{wrong_ca}``.
    """
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    pki = _generate_pki(ctx)
    b["ca"], b["wrong_ca"] = pki["ca"], pki["wrong_ca"]
    b["cert"], b["key"] = pki["cert"], pki["key"]
    program = Path(str(wl.get("program") or ctx["program"]))
    mode = str(wl.get("mode", "peer"))
    if mode == "chain":
        pos = _run([str(program), *_expand_wl(wl["argv"], b)], cwd=ctx["workdir"],
                   env=ctx["env"], timeout=120)
        neg = _run([str(program), *_expand_wl(wl.get("negative_argv") or wl["argv"], b)],
                   cwd=ctx["workdir"], env=ctx["env"], timeout=120)
        pos_match = re.search(str(wl["expect"]), pos["stdout"] + pos["stderr"], re.MULTILINE)
        neg_match = re.search(str(wl["expect"]), neg["stdout"] + neg["stderr"], re.MULTILINE)
        functional = bool(pos["ok"] and pos_match and (neg["exit_code"] != 0 or not neg_match))
        pos_ok = bool(pos["ok"] and pos_match)
        transcript = _transcript([("valid chain", pos), ("unrelated CA (must fail)", neg)])
        reason = ("the valid chain was not accepted" if not pos_ok else
                  "a chain signed by an unrelated CA was not rejected")
    else:
        payload = b"template-payload\n"
        download = str(wl.get("download", "payload.bin"))
        pos_dir = ctx["workdir"] / "x509-positive"
        neg_dir = ctx["workdir"] / "x509-negative"
        for directory in (pos_dir, neg_dir):
            directory.mkdir(parents=True, exist_ok=True)
        # The released master ``gftprc`` ships ``verify_ssl_peer=0``, which
        # would make the negative control meaningless.  gftp expands ``~`` with
        # getpwuid() (not $HOME) and copies the master config to that user file
        # when it is absent, so re-enable verification in the installed master
        # and drop any user copy left by an earlier process.  This is a fixture
        # precondition in the family scratch, not a source patch.
        master = Path(ctx["root"]) / ".l7-install" / "share" / "gftp" / "gftprc"
        if master.is_file():
            master.write_text(
                master.read_text(encoding="utf-8", errors="ignore").replace(
                    "verify_ssl_peer=0", "verify_ssl_peer=1"), encoding="utf-8")
        try:
            Path("~/.gftp/gftprc").expanduser().unlink()
        except (OSError, RuntimeError):
            pass
        pos_env = dict(ctx["env"], SSL_CERT_FILE=str(pki["ca"]), HOME=str(pos_dir))
        neg_env = dict(ctx["env"], SSL_CERT_FILE=str(pki["wrong_ca"]), HOME=str(neg_dir))
        with _FTPSFixture(b["port"], payload, cert=pki["cert"], key=pki["key"]):
            pos = _run([str(program), *_expand_wl(wl["argv"], b)], cwd=pos_dir,
                       env=pos_env, timeout=120)
            neg = _run([str(program), *_expand_wl(wl.get("negative_argv") or wl["argv"], b)],
                       cwd=neg_dir, env=neg_env, timeout=120)
        pos_file = pos_dir / download
        neg_file = neg_dir / download
        pos_ok = bool(pos["ok"] and pos_file.is_file() and pos_file.read_bytes() == payload)
        neg_rejected = not (neg_file.is_file() and neg_file.read_bytes() == payload)
        functional = bool(pos_ok and neg_rejected)
        transcript = _transcript([
            ("trusted CA", pos),
            ("downloaded under trusted CA", {"exit_code": 0 if pos_file.is_file() else 1,
                                              "stdout": (pos_file.read_bytes()[:200].decode(
                                                  "utf-8", "replace")
                                                  if pos_file.is_file() else ""),
                                              "stderr": ""}),
            ("unrelated CA (must fail)", neg),
            ("downloaded under unrelated CA", {"exit_code": 0 if neg_file.is_file() else 1,
                                                "stdout": (neg_file.read_bytes()[:200].decode(
                                                    "utf-8", "replace")
                                                    if neg_file.is_file() else ""),
                                                "stderr": ""}),
        ])
        reason = ("the verified FTPS transfer did not deliver the fixture payload"
                  if not pos_ok else
                  "a peer presenting a chain from an unrelated CA was not rejected")
    gate = verify_consumer_boundary(entry, ctx, program=program)
    if not gate["ok"]:
        return _gate_reject(gate, transcript)
    return {
        "runtime_ok": pos_ok,
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos_ok else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos_ok else
                                               "runtime-failure"),
        "reason": None if functional else reason,
        "transcript": transcript,
        "workload": f"{entry['family']}: x509 chain verification (trusted CA accept; unrelated "
                    "CA reject)",
        "consumer_evidence": gate["evidence"],
        "local_only": True,
    }


def _signing_fixture(ctx: dict, wl: dict) -> dict:
    """A local signing key pair and ELF input, independent of the consumer."""
    d = ctx["workdir"] / "signing"
    d.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name, bits in (wl.get("keys") or {"psk": 4096, "ssk": 4096}).items():
        path = d / f"{name}.pem"
        res = _openssl(ctx, ["genpkey", "-algorithm", "RSA", "-pkeyopt",
                             f"rsa_keygen_bits:{int(bits)}", "-out", str(path)], d)
        if not res["ok"] or not path.is_file():
            raise RuntimeError(f"could not generate the {name} signing key: "
                               f"{census._error_line(res)}")
        paths[str(name)] = path
    source_text = str(wl.get("payload_source", "int main(void){return 0;}\n"))
    source = d / "payload.c"
    source.write_text(source_text, encoding="utf-8")
    payload = d / "payload.elf"
    build = _run(["cc", "-o", str(payload), str(source)], cwd=d, env=ctx["env"], timeout=60)
    if not build["ok"] or not payload.is_file():
        raise RuntimeError(f"could not build the signing fixture ELF: {census._error_line(build)}")
    paths["payload"] = payload
    bif_text = str(wl.get("bif") or "the_ROM_image:\n{\n [pskfile] {psk}\n [sskfile] {ssk}\n"
                                        " [bootloader, authentication=rsa] {payload}\n}\n")
    for key, path in paths.items():
        bif_text = bif_text.replace("{" + key + "}", str(path))
    bif = d / "image.bif"
    bif.write_text(bif_text, encoding="utf-8")
    paths["bif"] = bif
    return {k: str(v) for k, v in paths.items()}


def _tpl_evp_signing(entry: dict, ctx: dict) -> dict:
    """Sign a fixture with the consumer, verify it, then reject a tampered signature."""
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    fixture = _signing_fixture(ctx, wl)
    signed = ctx["workdir"] / "signed.bin"
    tampered = ctx["workdir"] / "tampered.bin"
    extra = {**fixture, "signed": str(signed), "tampered": str(tampered)}
    program = Path(str(wl.get("program") or ctx["program"]))
    sign = _run([str(program), *_expand_wl(wl["sign_argv"], b, extra=extra)], cwd=ctx["workdir"],
                env=ctx["env"], timeout=120)
    sign_expect = str(wl.get("sign_expect", ""))
    sign_ok = bool(sign["ok"] and signed.is_file() and
                   (not sign_expect or re.search(sign_expect, sign["stdout"] + sign["stderr"],
                                                 re.MULTILINE)))
    verify = _run([str(program), *_expand_wl(wl["verify_argv"], b, extra=extra)],
                  cwd=ctx["workdir"], env=ctx["env"], timeout=120) if sign_ok else {
                      "exit_code": -1, "stdout": "", "stderr": "sign failed"}
    verify_expect = str(wl.get("verify_expect", ""))
    verified = bool(sign_ok and verify_expect and
                    re.search(verify_expect, verify["stdout"] + verify["stderr"], re.MULTILINE))
    if sign_ok:
        tampered.write_bytes(signed.read_bytes())
        blob = bytearray(tampered.read_bytes())
        offset = int(wl.get("tamper_offset", -100))
        index = offset if offset >= 0 else len(blob) + offset
        index = max(0, min(index, len(blob) - 1))
        blob[index] ^= 0x01
        tampered.write_bytes(bytes(blob))
    negative = _run([str(program), *_expand_wl(wl["verify_argv"], b,
                                              extra=dict(extra, signed=str(tampered)))],
                    cwd=ctx["workdir"], env=ctx["env"], timeout=120) if sign_ok else {
                        "exit_code": -1, "stdout": "", "stderr": "sign failed"}
    negative_expect = str(wl.get("negative_expect", ""))
    negative_output = negative["stdout"] + negative["stderr"]
    tamper_rejected = bool(
        (negative_expect and re.search(negative_expect, negative_output, re.MULTILINE)) or
        (not negative_expect and negative["exit_code"] != 0 and
         not (verify_expect and re.search(verify_expect, negative_output, re.MULTILINE))))
    if verify_expect and re.search(verify_expect, negative_output, re.MULTILINE):
        tamper_rejected = False
    functional = bool(sign_ok and verified and tamper_rejected)
    transcript = _transcript([("sign", sign), ("verify signed artifact", verify),
                              ("verify tampered signature (must fail)", negative),
                              ("fixture", {"exit_code": 0, "stdout": str(fixture["bif"]),
                                            "stderr": ""})])
    reason = ("the consumer did not sign the fixture" if not sign_ok else
              "the consumer did not verify its own valid signature" if not verified else
              "a tampered signature was not rejected")
    gate = verify_consumer_boundary(entry, ctx, program=program)
    if not gate["ok"]:
        return _gate_reject(gate, transcript)
    return {
        "runtime_ok": sign_ok,
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if sign_ok else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if sign_ok else
                                               "runtime-failure"),
        "reason": None if functional else reason,
        "transcript": transcript,
        "workload": f"{entry['family']}: sign -> verify -> tampered signature reject",
        "consumer_evidence": gate["evidence"],
        "local_only": True,
    }


def _tpl_aead_roundtrip(entry: dict, ctx: dict) -> dict:
    """Encrypt/decrypt round trip through the consumer, then reject a modified tag.

    A typed library harness (``workload.harness``) is used for a library-only
    family: the harness object is compiled by the runtime and this handler runs
    its positive and ``--tamper`` modes.  The consumer gate then proves that the
    harness imports no OpenSSL symbol and that it references the named consumer
    library.  A CLI family may instead name ``encrypt_argv``/``decrypt_argv``.
    """
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    program = Path(str(wl.get("program") or ctx["program"]))
    h = wl.get("harness")
    if h:
        pos = _run([str(program), *_expand_wl(h.get("argv") or [], b)], cwd=ctx["workdir"],
                   env=ctx["env"], timeout=120)
        neg = _run([str(program), *_expand_wl(h.get("negative_argv") or [], b)],
                   cwd=ctx["workdir"], env=ctx["env"], timeout=120)
        pos_expect = str(h.get("expect", "aead_roundtrip=ok"))
        neg_expect = str(h.get("negative_expect", "aead_tamper=rejected"))
        pos_ok = bool(pos["ok"] and re.search(pos_expect, pos["stdout"] + pos["stderr"],
                                              re.MULTILINE))
        neg_ok = bool(re.search(neg_expect, neg["stdout"] + neg["stderr"], re.MULTILINE))
        gate = verify_consumer_boundary(entry, ctx, program=program, harness_obj=program)
        transcript = _transcript([("round trip", pos), ("modified tag (must fail)", neg)])
    else:
        payload = b["files"]["payload"]
        artifact = ctx["workdir"] / str(wl.get("artifact", "ciphertext.bin"))
        plain = ctx["workdir"] / str(wl.get("plaintext", "plaintext.out"))
        extra = {"artifact": str(artifact), "plaintext": str(plain)}
        enc = _run([str(program), *_expand_wl(wl["encrypt_argv"], b, extra=extra)],
                   cwd=ctx["workdir"], env=ctx["env"], timeout=120)
        dec = _run([str(program), *_expand_wl(wl["decrypt_argv"], b, extra=extra)],
                   cwd=ctx["workdir"], env=ctx["env"], timeout=120) if enc["ok"] else {
                       "exit_code": -1, "stdout": "", "stderr": "encrypt failed"}
        pos_ok = bool(enc["ok"] and artifact.is_file() and dec["ok"] and plain.is_file() and
                      plain.read_bytes() == payload.read_bytes())
        if artifact.is_file():
            blob = bytearray(artifact.read_bytes())
            offset = int(wl.get("tamper_offset", -1))
            index = offset if offset >= 0 else len(blob) + offset
            index = max(0, min(index, len(blob) - 1))
            blob[index] ^= 0x01
            artifact.write_bytes(bytes(blob))
        if plain.is_file():
            plain.unlink()
        neg = _run([str(program), *_expand_wl(wl["decrypt_argv"], b, extra=extra)],
                   cwd=ctx["workdir"], env=ctx["env"], timeout=120)
        neg_ok = bool(neg["exit_code"] != 0 or not plain.is_file() or
                      plain.read_bytes() != payload.read_bytes())
        gate = verify_consumer_boundary(entry, ctx, program=program)
        transcript = _transcript([("encrypt", enc), ("decrypt round trip", dec),
                                  ("modified tag (must fail)", neg)])
    if not gate["ok"]:
        return _gate_reject(gate, transcript)
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok,
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos_ok else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos_ok else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the encrypt/decrypt round trip did not reproduce the payload" if not pos_ok else
            "a modified authentication tag was not rejected"),
        "transcript": transcript,
        "workload": f"{entry['family']}: AEAD round trip + modified-tag reject",
        "consumer_evidence": gate["evidence"],
        "local_only": True,
    }


def _tpl_hmac_kdf(entry: dict, ctx: dict) -> dict:
    """Reproduce a published keyed-KDF output; a wrong key must produce a different one."""
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    kdf = wl["kdf"]
    fid = str(kdf["fid"])
    expected = str(kdf["expected"])
    vector = ctx["workdir"] / "kdf-positive.txt"
    wrong = ctx["workdir"] / "kdf-wrong-key.txt"
    vector.write_text(
        f"L = {int(kdf.get('bits', 256))}\nKI = {kdf['key']}\n"
        f"FixedInputDataByteLen = {len(fid) // 2}\nFixedInputData = {fid}\nKO = {expected}\n",
        encoding="utf-8")
    wrong.write_text(
        f"L = {int(kdf.get('bits', 256))}\nKI = {kdf['wrong_key']}\n"
        f"FixedInputDataByteLen = {len(fid) // 2}\nFixedInputData = {fid}\n",
        encoding="utf-8")
    program = Path(str(wl.get("program") or ctx["program"]))
    extra = {"vector": str(vector), "wrong_vector": str(wrong)}
    pos = _run([str(program), *_expand_wl(wl["argv"], b, extra=extra)], cwd=ctx["workdir"],
               env=ctx["env"], timeout=120)
    neg = _run([str(program), *_expand_wl(wl.get("negative_argv") or wl["argv"], b, extra=extra)],
               cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    pos_out = pos["stdout"] + pos["stderr"]
    neg_out = neg["stdout"] + neg["stderr"]
    pos_ok = bool(pos["ok"] and re.search(str(wl["expect"]), pos_out, re.MULTILINE) and
                  re.search(re.escape(expected), pos_out, re.IGNORECASE))
    output_re = str(wl.get("output_re", r"KO = ([0-9A-Fa-f]+)"))
    match = re.search(output_re, neg_out, re.MULTILINE)
    wrong_differs = bool(match and match.group(1).lower() != expected.lower())
    neg_ok = bool(wrong_differs or (neg["exit_code"] != 0 and
                                    not re.search(str(wl["expect"]), neg_out, re.MULTILINE)))
    functional = bool(pos_ok and neg_ok)
    transcript = _transcript([("published vector", pos), ("wrong key (must differ)", neg)])
    reason = ("the consumer did not reproduce the published KDF output" if not pos_ok else
              "a wrong key produced the same KDF output")
    gate = verify_consumer_boundary(entry, ctx, program=program)
    if not gate["ok"]:
        return _gate_reject(gate, transcript)
    return {
        "runtime_ok": pos_ok,
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos_ok else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos_ok else
                                               "runtime-failure"),
        "reason": None if functional else reason,
        "transcript": transcript,
        "workload": f"{entry['family']}: keyed-KDF known output + wrong-key differs",
        "consumer_evidence": gate["evidence"],
        "local_only": True,
    }


def _tpl_ssh_client(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    d = ctx["workdir"]
    keygen = ctx["root"] / str(wl.get("keygen", "ssh-keygen"))
    server_bin = ctx["root"] / str(wl.get("server", "sshd"))
    session = ctx["root"] / str(wl.get("session", "sshd-session"))
    ssh = ctx["program"]
    if not (keygen.is_file() and server_bin.is_file() and ssh.is_file()):
        return _fail("the recipe built no ssh/sshd/ssh-keygen to drive", "harness-failure")
    # sshd refuses to start without its compiled privilege-separation directory.
    privsep = ctx["root"] / ".l7-privsep"
    privsep.mkdir(parents=True, exist_ok=True)
    os.chmod(privsep, 0o755)
    host_key, client_key, other_key = d / "hostkey", d / "clientkey", d / "otherhost"
    for key in (host_key, client_key, other_key):
        gen = _run([str(keygen), "-t", "ed25519", "-f", str(key), "-N", "", "-q",
                    "-C", "template"], cwd=d, env=ctx["env"], timeout=40)
        if not gen["ok"]:
            return _fail(f"ssh-keygen failed: {census._error_line(gen)}", "harness-failure")
    authorized = d / "authorized_keys"
    authorized.write_text((d / "clientkey.pub").read_text(encoding="utf-8"), encoding="utf-8")
    known_good, known_bad = d / "known_hosts", d / "known_bad"
    known_good.write_text(f"[127.0.0.1]:{b['port']} " + (d / "hostkey.pub").read_text(
        encoding="utf-8"), encoding="utf-8")
    known_bad.write_text(f"[127.0.0.1]:{b['port']} " + (d / "otherhost.pub").read_text(
        encoding="utf-8"), encoding="utf-8")
    conf = d / "sshd_config"
    conf.write_text(f"Port {b['port']}\nListenAddress 127.0.0.1\nHostKey {host_key}\n"
                    f"PidFile {d}/sshd.pid\nAuthorizedKeysFile {authorized}\n"
                    "StrictModes no\nPasswordAuthentication no\n"
                    "KbdInteractiveAuthentication no\nPubkeyAuthentication yes\n"
                    "PermitRootLogin yes\nLogLevel VERBOSE\n"
                    f"SshdSessionPath {session}\n", encoding="utf-8")
    server = subprocess.Popen([str(server_bin), "-D", "-e", "-f", str(conf)], cwd=str(d),
                              env=ctx["env"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
    common = ["-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
              "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
              "-o", "ConnectTimeout=8", "-o", f"IdentityFile={client_key}",
              "-p", str(b["port"])]
    try:
        if not _wait_tcp(b["port"], timeout=20):
            out, err = server.communicate(timeout=5)
            return _fail(f"sshd did not listen: {(err or out or '')[-300:]}", "runtime-failure")
        pos = _run([str(ssh), *common, "-o", f"UserKnownHostsFile={known_good}",
                    "127.0.0.1", "echo ok"], cwd=d, env=ctx["env"], timeout=40)
        neg = _run([str(ssh), *common, "-o", f"UserKnownHostsFile={known_bad}",
                    "127.0.0.1", "echo ok"], cwd=d, env=ctx["env"], timeout=40)
    finally:
        server.terminate()
        try:
            out, err = server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            out, err = server.communicate()
    exec_ok = pos["ok"] and str(wl.get("expect", "ok")) in pos["stdout"]
    neg_rejected = neg["exit_code"] != 0 and "Host key verification failed" in (
        neg["stdout"] + neg["stderr"])
    functional = exec_ok and neg_rejected
    return {
        "runtime_ok": exec_ok,
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if exec_ok else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if exec_ok else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the verified ssh command did not run" if not exec_ok else
            "a known_hosts entry for a different host key was not rejected"),
        "transcript": _transcript([("ssh exec", pos), ("ssh host-key mismatch (must fail)", neg),
                                   ("sshd", {"exit_code": server.returncode,
                                             "stdout": (out or "")[-1000:],
                                             "stderr": (err or "")[-1000:]})]),
        "workload": f"{entry['family']}: ssh client bucket",
        "local_only": True,
    }

