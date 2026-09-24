#!/usr/bin/env python3
"""openssl-rs — generate `courts/phase8/ct_ml_dsa_vectors.h`, the CT-ML-DSA vector inputs.

Why this court, and what it closes
----------------------------------
Phase 8 requires **two** evidence planes for every primitive-bearing provider row
(`docs/PHASE-8-SUBPHASES.md` §3). The ML-DSA rows have had the *differential* plane since D409
(`RT-KEYMGMT`, `RT-SIGNATURE`: one probe compiled twice, two transcripts diffed) and not the
*correctness* plane. The rule that matters (D400/D406) is that **a differential court only
proves agreement; a published vector closes a derived value**, because two implementations can
agree byte for byte and both be wrong. `CT-ML-DSA` is that second plane.

The expected bytes must come from an **independent statement** — here the authority's own
checked-in FIPS 204 / ACVP vector corpus — never from the candidate and never typed from memory.
This generator reads that corpus out of the pinned authority and writes the **inputs** the
candidate-only probe drives. The **expected** values (a public key, a signature, a verify
verdict) are written to `forensics/atlas/ct-ml-dsa-vectors.json`, the generator's own envelope,
where `forensics/tools/correctness_vectors.py:run_ml_dsa_court` reads them and owns the
comparison — the probe computes and never decides, exactly as `ct_digest.c` does. The split is
deliberate: the subphase vectors carry multi-kilobyte private keys, messages and signatures, so
the probe side is a generated C header (a call file of that size would be a second transcription)
while the small expected side is a JSON record.

Where the vectors come from
---------------------------
Every byte is read back out of the pinned authority's own `evp_test` corpus, in
`forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/`:

  * `evppkey_ml_dsa_keygen.txt` — the **keygen** arm's `(seed, public key)` vectors
    (ACVP `ML-DSA-keyGen-FIPS204`, version 42). `Ctrl = hexseed:` is the 32-byte seed the
    provider's `OSSL_PKEY_PARAM_ML_DSA_SEED` takes; `CtrlOut = hexpub:` is the expected public
    key. The arm expects a **byte-identical public key**.
  * `evppkey_ml_dsa_siggen.txt` — the **signature generation** arm's `(private key, message,
    context, signature)` vectors (ACVP `ML-DSA-sigGen-FIPS204`, version 42). Only the
    `Ctrl = deterministic:1` blocks are taken, so the signing `rnd` is 32 zero bytes and the
    signature is reproducible; the arm expects a **byte-identical signature**.
  * `evppkey_ml_dsa_sigver.txt` — the **signature verification** arm's `(public key, message,
    signature, verdict)` vectors (ACVP `ML-DSA-sigVer-FIPS204`, version 42). A block with
    `Result = VERIFY_ERROR` expects rejection, a block without it expects acceptance, so the arm
    observes both verdicts rather than only the accept.

The authority also carries a cut-down C form of the same corpus at
`test/ml_dsa.inc`, with `test/ml_dsa_test.c` showing how each `ML_DSA_*` item is used. It is not
read here for two reasons: its `siggen` items carry only `sha256(signature)` rather than the
signature, so it cannot close the byte-identity the spec plane is for; and its items are driven
with `message-encoding:0` (the "does not encode the message" test mode) where the `evp_test`
corpus uses the pure FIPS 204 encoding. The `evp_test` files are the same corpus at full width.

What is checked rather than assumed
-----------------------------------
* Every field length is checked against the parameter sizes the authority's own
  `include/crypto/ml_dsa.h` declares (`ML_DSA_<n>_PRIV/PUB/SIG_LEN`, `ML_DSA_SEED_BYTES`,
  `ML_DSA_MAX_CONTEXT_STRING_LEN`), read from that header rather than typed. The parsed sizes are
  additionally required to equal FIPS 204 Table 1/2's published values.
* A keygen seed seen twice must carry the same public key (the corpus repeats one vector per set
  for the `Security-Category` assertion); the duplicate is recorded, not silently dropped.
* Every vector id is unique, and every arm is non-empty.
* Each vector's expected value is a digest of the exact bytes the authority's file carries: the
  generator computes `sha256(pub)` / `sha256(sig)`, and the verdict is read, never typed.
* The mirror files' sha256 are committed in the envelope's `inputs[]`, so a changed corpus is
  detectable.

Usage: `python3 forensics/tools/gen_ct_ml_dsa_vectors.py`

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/gen_ct_ml_dsa_vectors.py"
AUTHORITY = "openssl-3.6.4-production"

DATA_REL = "test/recipes/30-test_evp_data"
SIZES_REL = "include/crypto/ml_dsa.h"
HDR_REL = "test/ml_dsa.inc"
TEST_REL = "test/ml_dsa_test.c"

KEYGEN_FILE = "evppkey_ml_dsa_keygen.txt"
SIGGEN_FILE = "evppkey_ml_dsa_siggen.txt"
SIGVER_FILE = "evppkey_ml_dsa_sigver.txt"

OUT_H = REPO_ROOT / "courts" / "phase8" / "ct_ml_dsa_vectors.h"
OUT_ATLAS = REPO_ROOT / "forensics" / "atlas" / "ct-ml-dsa-vectors.json"

# The three parameter sets, in the authority's `deflt_keymgmt[]` order.
ALGS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

# The selection bounds. A keygen input is a 32-byte seed, so **every** distinct keygen vector is
# taken; a siggen/sigver input carries a multi-kilobyte key, message and signature, so a bounded,
# order-stable representative set per parameter set is taken and the bound is stated here rather
# than left to the reader. `None` means "all".
KEYGEN_PER_SET: int | None = None
SIGGEN_PER_SET = 2
SIGVER_ACCEPT_PER_SET = 1
SIGVER_REJECT_PER_SET = 2

# FIPS 204 Table 1/2. The parsed `include/crypto/ml_dsa.h` sizes are *required* to equal these,
# the way `gen_ml_dsa_tables.py` requires `ML_DSA_Q == 8380417`: a value the authority defines is
# checked against the standard it claims, not merely copied.
FIPS_204_SIZES = {
    "ML-DSA-44": (2560, 1312, 2420),
    "ML-DSA-65": (4032, 1952, 3309),
    "ML-DSA-87": (4896, 2592, 4627),
}
FIPS_204_SEED_BYTES = 32
FIPS_204_MAX_CONTEXT = 255

PRIMARY_SOURCE = (
    "NIST ACVP-Server ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json, version "
    "42 (mirrored by the authority in test/recipes/30-test_evp_data/evppkey_ml_dsa_*.txt)"
)


class VectorError(SystemExit):
    """The authority corpus is not the shape this generator evaluates."""


@dataclass(frozen=True)
class Sizes:
    seed_bytes: int
    max_context: int
    # algorithm -> (priv_len, pub_len, sig_len)
    per_alg: dict[str, tuple[int, int, int]]


@dataclass(frozen=True)
class KeygenVec:
    id: str
    alg: str
    seed: bytes
    pub: bytes
    line: int


@dataclass(frozen=True)
class SiggenVec:
    id: str
    alg: str
    priv: bytes
    msg: bytes
    ctx: bytes
    sig: bytes
    line: int


@dataclass(frozen=True)
class SigverVec:
    id: str
    alg: str
    pub: bytes
    msg: bytes
    sig: bytes
    ctx: bytes
    expected: int
    line: int


# ---------------------------------------------------------------------------
# Reading the authority
# ---------------------------------------------------------------------------


def parse_sizes(text: str) -> Sizes:
    """The parameter sizes the authority's own `include/crypto/ml_dsa.h` declares."""
    seed = re.search(r"#define\s+ML_DSA_SEED_BYTES\s+(\d+)", text)
    ctx = re.search(r"#define\s+ML_DSA_MAX_CONTEXT_STRING_LEN\s+(\d+)", text)
    if seed is None or ctx is None:
        raise VectorError(f"{SIZES_REL}: cannot find ML_DSA_SEED_BYTES / MAX_CONTEXT_STRING_LEN")
    per_alg: dict[str, tuple[int, int, int]] = {}
    for alg in ALGS:
        n = alg.rsplit("-", 1)[1]
        found = {}
        for field in ("PRIV", "PUB", "SIG"):
            m = re.search(rf"#define\s+ML_DSA_{n}_{field}_LEN\s+(\d+)", text)
            if m is None:
                raise VectorError(f"{SIZES_REL}: cannot find ML_DSA_{n}_{field}_LEN")
            found[field] = int(m.group(1))
        per_alg[alg] = (found["PRIV"], found["PUB"], found["SIG"])
    sizes = Sizes(int(seed.group(1)), int(ctx.group(1)), per_alg)
    if sizes.seed_bytes != FIPS_204_SEED_BYTES or sizes.max_context != FIPS_204_MAX_CONTEXT:
        raise VectorError(
            f"{SIZES_REL}: seed/context sizes {sizes.seed_bytes}/{sizes.max_context} are not "
            f"FIPS 204's {FIPS_204_SEED_BYTES}/{FIPS_204_MAX_CONTEXT}"
        )
    for alg, want in FIPS_204_SIZES.items():
        if sizes.per_alg[alg] != want:
            raise VectorError(
                f"{SIZES_REL}: {alg} sizes {sizes.per_alg[alg]} are not FIPS 204 Table 1/2's {want}"
            )
    return sizes


def parse_blocks(path: Path) -> list[list[tuple[str, str, int]]]:
    """An `evp_test` file as blocks of ordered `(key, value, lineno)` entries."""
    blocks: list[list[tuple[str, str, int]]] = []
    current: list[tuple[str, str, int]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if line == "":
            if current:
                blocks.append(current)
                current = []
            continue
        if line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        current.append((key.strip(), value.strip(), lineno))
    if current:
        blocks.append(current)
    return blocks


def first(entries: list[tuple[str, str, int]], key: str) -> str | None:
    for k, v, _ in entries:
        if k == key:
            return v
    return None


def all_of(entries: list[tuple[str, str, int]], key: str) -> list[str]:
    return [v for k, v, _ in entries if k == key]


def line_of(entries: list[tuple[str, str, int]], key: str) -> int:
    for k, _v, lineno in entries:
        if k == key:
            return lineno
    return 0


def hex_tail(value: str, tag: str) -> bytes:
    """`<tag>:<hex>` -> bytes, refusing anything else."""
    if not value.startswith(tag + ":"):
        raise VectorError(f"expected `{tag}:<hex>`, got {value[:32]!r}")
    try:
        return bytes.fromhex(value[len(tag) + 1:])
    except ValueError as exc:
        raise VectorError(f"{value[:32]!r}: not hex ({exc})") from exc


# ---------------------------------------------------------------------------
# The three arms
# ---------------------------------------------------------------------------


def build_keygen(path: Path, sizes: Sizes) -> list[KeygenVec]:
    out: list[KeygenVec] = []
    seen: dict[tuple[str, bytes], bytes] = {}
    duplicates = 0
    for entries in parse_blocks(path):
        alg = first(entries, "KeyGen")
        if alg is None:
            continue
        if alg not in sizes.per_alg:
            raise VectorError(f"{path.name}: unknown KeyGen algorithm {alg!r}")
        seeds = [v for v in all_of(entries, "Ctrl") if v.startswith("hexseed:")]
        pubs = [v for v in all_of(entries, "CtrlOut") if v.startswith("hexpub:")]
        if len(seeds) != 1 or len(pubs) != 1:
            raise VectorError(f"{path.name}:{line_of(entries, 'KeyGen')}: malformed keygen block")
        seed = hex_tail(seeds[0], "hexseed")
        pub = hex_tail(pubs[0], "hexpub")
        if len(seed) != sizes.seed_bytes:
            raise VectorError(f"{path.name}: seed is {len(seed)} bytes, not {sizes.seed_bytes}")
        if len(pub) != sizes.per_alg[alg][1]:
            raise VectorError(
                f"{path.name}: {alg} public key is {len(pub)} bytes, "
                f"not {sizes.per_alg[alg][1]}"
            )
        key = (alg, seed)
        if key in seen:
            # The corpus repeats one vector per set under a `Security-Category` block; the
            # repeat must carry the same public key, and is recorded rather than dropped.
            if seen[key] != pub:
                raise VectorError(f"{path.name}: duplicate seed for {alg} carries a different key")
            duplicates += 1
            continue
        seen[key] = pub
        keyname = first(entries, "KeyName") or "?"
        out.append(KeygenVec(id=f"keygen-{alg}-{keyname}", alg=alg, seed=seed, pub=pub,
                             line=line_of(entries, "KeyGen")))
    if duplicates:
        print(f"[ct-ml-dsa] keygen: {duplicates} duplicate seed block(s) recorded and skipped")
    return _bound_by_set(out, KEYGEN_PER_SET)


def build_siggen(path: Path, sizes: Sizes) -> list[SiggenVec]:
    blocks = parse_blocks(path)
    keys: dict[str, tuple[str, bytes]] = {}
    for entries in blocks:
        raw = first(entries, "PrivateKeyRaw")
        if raw is None:
            continue
        parts = raw.split(":", 2)
        if len(parts) != 3:
            raise VectorError(f"{path.name}:{line_of(entries, 'PrivateKeyRaw')}: malformed key")
        name, alg, hexs = parts
        keys[name] = (alg, bytes.fromhex(hexs))
    out: list[SiggenVec] = []
    per: Counter[str] = Counter()
    seen_inputs: set[tuple[str, bytes, bytes, bytes]] = set()
    for entries in blocks:
        sig = first(entries, "Sign-Message")
        if sig is None:
            continue
        alg, _, name = sig.partition(":")
        if name not in keys or keys[name][0] != alg:
            raise VectorError(f"{path.name}:{line_of(entries, 'Sign-Message')}: unknown key {name!r}")
        priv = keys[name][1]
        ctrls = all_of(entries, "Ctrl")
        # Only the deterministic (`rnd` all-zero) blocks close a byte-identical signature. The
        # randomised blocks carry a `test-entropy` `rnd` and are simply not taken: a court that
        # printed a value from a non-deterministic input would not be reproducible.
        if not any(c == "deterministic:1" for c in ctrls):
            continue
        # The external-`mu` blocks take the 32-byte representative as the message; this probe
        # drives the pure (raw-message) interface, so they are out of scope (named in the probe's
        # header as not observed).
        if any(c == "mu:1" for c in ctrls):
            continue
        ctx = b""
        for c in ctrls:
            if c.startswith("hexcontext-string:"):
                ctx = bytes.fromhex(c.split(":", 1)[1])
        msg = bytes.fromhex(first(entries, "Input") or "")
        out_sig = bytes.fromhex(first(entries, "Output") or "")
        # The corpus emits each `deterministic:1` test twice, once with `Ctrl = mu:0` and once
        # without it; `mu`'s default is already 0, so the two are the same operation and the
        # second is a duplicate of the first. Deduplicate on the exact input before counting the
        # per-set bound, so the bound is distinct tests rather than repeated lines.
        if (alg, priv, msg, ctx) in seen_inputs:
            continue
        seen_inputs.add((alg, priv, msg, ctx))
        if SIGGEN_PER_SET is not None and per[alg] >= SIGGEN_PER_SET:
            continue
        per[alg] += 1
        if len(priv) != sizes.per_alg[alg][0]:
            raise VectorError(f"{path.name}: {alg} private key is {len(priv)} bytes")
        if len(out_sig) != sizes.per_alg[alg][2]:
            raise VectorError(f"{path.name}: {alg} signature is {len(out_sig)} bytes")
        if len(ctx) > sizes.max_context:
            raise VectorError(f"{path.name}: context is {len(ctx)} bytes")
        out.append(SiggenVec(id=f"siggen-{alg}-{name}@{line_of(entries, 'Sign-Message')}",
                             alg=alg, priv=priv, msg=msg, ctx=ctx, sig=out_sig,
                             line=line_of(entries, "Sign-Message")))
    return out


def build_sigver(path: Path, sizes: Sizes) -> list[SigverVec]:
    blocks = parse_blocks(path)
    keys: dict[str, tuple[str, bytes]] = {}
    for entries in blocks:
        raw = first(entries, "PublicKeyRaw")
        if raw is None:
            continue
        parts = raw.split(":", 2)
        if len(parts) != 3:
            raise VectorError(f"{path.name}:{line_of(entries, 'PublicKeyRaw')}: malformed key")
        name, alg, hexs = parts
        keys[name] = (alg, bytes.fromhex(hexs))
    out: list[SigverVec] = []
    accept: Counter[str] = Counter()
    reject: Counter[str] = Counter()
    seen_inputs: set[tuple[str, bytes, bytes, bytes, int]] = set()
    for entries in blocks:
        ver = first(entries, "Verify-Message-Public")
        if ver is None:
            continue
        alg, _, name = ver.partition(":")
        if name not in keys or keys[name][0] != alg:
            raise VectorError(
                f"{path.name}:{line_of(entries, 'Verify-Message-Public')}: unknown key {name!r}"
            )
        pub = keys[name][1]
        ctrls = all_of(entries, "Ctrl")
        if any(c == "mu:1" for c in ctrls):
            continue
        expects_reject = any(x == "VERIFY_ERROR" for x in all_of(entries, "Result"))
        ctx = b""
        for c in ctrls:
            if c.startswith("hexcontext-string:"):
                ctx = bytes.fromhex(c.split(":", 1)[1])
        msg = bytes.fromhex(first(entries, "Input") or "")
        sig = bytes.fromhex(first(entries, "Output") or "")
        # As for siggen: the `mu:0`/default pair is one operation, so deduplicate on the exact
        # input before counting the bound.
        dedup_key = (alg, pub, msg, sig, 0 if expects_reject else 1)
        if dedup_key in seen_inputs:
            continue
        seen_inputs.add(dedup_key)
        if not expects_reject and SIGVER_ACCEPT_PER_SET is not None \
                and accept[alg] >= SIGVER_ACCEPT_PER_SET:
            continue
        if expects_reject and SIGVER_REJECT_PER_SET is not None \
                and reject[alg] >= SIGVER_REJECT_PER_SET:
            continue
        (reject if expects_reject else accept)[alg] += 1
        if len(pub) != sizes.per_alg[alg][1]:
            raise VectorError(f"{path.name}: {alg} public key is {len(pub)} bytes")
        if len(sig) != sizes.per_alg[alg][2]:
            raise VectorError(f"{path.name}: {alg} signature is {len(sig)} bytes")
        if len(ctx) > sizes.max_context:
            raise VectorError(f"{path.name}: context is {len(ctx)} bytes")
        out.append(SigverVec(id=f"sigver-{alg}-{name}@{line_of(entries, 'Verify-Message-Public')}",
                             alg=alg, pub=pub, msg=msg, sig=sig,
                             ctx=ctx, expected=0 if expects_reject else 1,
                             line=line_of(entries, "Verify-Message-Public")))
    return out


def _bound_by_set(vecs: list[KeygenVec], per_set: int | None) -> list[KeygenVec]:
    if per_set is None:
        return vecs
    per: Counter[str] = Counter()
    out = []
    for v in vecs:
        if per[v.alg] >= per_set:
            continue
        per[v.alg] += 1
        out.append(v)
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_bytes(prefix: str, data: bytes) -> str:
    lines = [f"static const unsigned char {prefix}[{len(data)}] = {{"]
    for i in range(0, len(data), 16):
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in data[i:i + 16]) + ",")
    lines.append("};")
    return "\n".join(lines)


def render_header(keygen: list[KeygenVec], siggen: list[SiggenVec], sigver: list[SigverVec],
                  sizes: Sizes) -> str:
    o: list[str] = []
    o.append("/*")
    o.append(" * openssl-rs — the CT-ML-DSA vector inputs, generated, never transcribed.")
    o.append(" *")
    o.append(" *")
    o.append(" * Read out of the pinned authority's own FIPS 204 / ACVP `evp_test` corpus by")
    o.append(" * `forensics/tools/gen_ct_ml_dsa_vectors.py`; **do not edit by hand.** The")
    o.append(" * *expected* values (public keys, signatures, verify verdicts) are not here: they")
    o.append(" * are the generator's atlas record `forensics/atlas/ct-ml-dsa-vectors.json`, and")
    o.append(" * `forensics/tools/correctness_vectors.py:run_ml_dsa_court` owns the comparison.")
    o.append(" * This header carries only what the candidate-only probe must *drive*.")
    o.append(" *")
    o.append(" *   keygen  `evppkey_ml_dsa_keygen.txt`  seed -> expected byte-identical public key")
    o.append(" *   siggen  `evppkey_ml_dsa_siggen.txt`  priv+msg+ctx -> expected byte-identical sig")
    o.append(" *   sigver  `evppkey_ml_dsa_sigver.txt`  pub+msg+sig+ctx -> expected verdict")
    o.append(" *")
    o.append(" * SPDX-License-Identifier: Apache-2.0")
    o.append(" */")
    o.append("#ifndef OSSL_RS_CT_ML_DSA_VECTORS_H")
    o.append("#define OSSL_RS_CT_ML_DSA_VECTORS_H")
    o.append("")
    o.append("#include <stddef.h>")
    o.append("")
    o.append("struct ct_mldsa_keygen {")
    o.append("    const char *id;")
    o.append("    const char *alg;")
    o.append("    const unsigned char *seed;")
    o.append("    size_t seedlen;")
    o.append("};")
    o.append("")
    o.append("struct ct_mldsa_siggen {")
    o.append("    const char *id;")
    o.append("    const char *alg;")
    o.append("    const unsigned char *priv;")
    o.append("    size_t privlen;")
    o.append("    const unsigned char *msg;")
    o.append("    size_t msglen;")
    o.append("    const unsigned char *ctx;")
    o.append("    size_t ctxlen;")
    o.append("};")
    o.append("")
    o.append("struct ct_mldsa_sigver {")
    o.append("    const char *id;")
    o.append("    const char *alg;")
    o.append("    const unsigned char *pub;")
    o.append("    size_t publen;")
    o.append("    const unsigned char *msg;")
    o.append("    size_t msglen;")
    o.append("    const unsigned char *sig;")
    o.append("    size_t siglen;")
    o.append("    const unsigned char *ctx;")
    o.append("    size_t ctxlen;")
    o.append("};")
    o.append("")
    o.append("/* The shared zero-length context string, so an empty context is not a NULL idiom. */")
    o.append("static const unsigned char ct_mldsa_empty[1] = { 0 };")
    o.append("")

    for i, v in enumerate(keygen):
        o.append(f"/* {v.id} ({v.alg}) */")
        o.append(render_bytes(f"kg_{i}_seed", v.seed))
    o.append("")
    for i, v in enumerate(siggen):
        o.append(f"/* {v.id} ({v.alg}) */")
        o.append(render_bytes(f"sg_{i}_priv", v.priv))
        o.append(render_bytes(f"sg_{i}_msg", v.msg))
        if v.ctx:
            o.append(render_bytes(f"sg_{i}_ctx", v.ctx))
    o.append("")
    for i, v in enumerate(sigver):
        o.append(f"/* {v.id} ({v.alg}) */")
        o.append(render_bytes(f"sv_{i}_pub", v.pub))
        o.append(render_bytes(f"sv_{i}_msg", v.msg))
        o.append(render_bytes(f"sv_{i}_sig", v.sig))
        if v.ctx:
            o.append(render_bytes(f"sv_{i}_ctx", v.ctx))
    o.append("")

    o.append(f"static const struct ct_mldsa_keygen ct_mldsa_keygen[{len(keygen)}] = {{")
    for i, v in enumerate(keygen):
        o.append(f'    {{ "{v.id}", "{v.alg}", kg_{i}_seed, {len(v.seed)} }},')
    o.append("};")
    o.append(f"static const struct ct_mldsa_siggen ct_mldsa_siggen[{len(siggen)}] = {{")
    for i, v in enumerate(siggen):
        ctx = f"sg_{i}_ctx, {len(v.ctx)}" if v.ctx else "ct_mldsa_empty, 0"
        o.append(
            f'    {{ "{v.id}", "{v.alg}", sg_{i}_priv, {len(v.priv)}, '
            f'sg_{i}_msg, {len(v.msg)}, {ctx} }},'
        )
    o.append("};")
    o.append(f"static const struct ct_mldsa_sigver ct_mldsa_sigver[{len(sigver)}] = {{")
    for i, v in enumerate(sigver):
        ctx = f"sv_{i}_ctx, {len(v.ctx)}" if v.ctx else "ct_mldsa_empty, 0"
        o.append(
            f'    {{ "{v.id}", "{v.alg}", sv_{i}_pub, {len(v.pub)}, sv_{i}_msg, {len(v.msg)}, '
            f'sv_{i}_sig, {len(v.sig)}, {ctx} }},'
        )
    o.append("};")
    o.append("")
    o.append("#endif /* OSSL_RS_CT_ML_DSA_VECTORS_H */")
    return "\n".join(o) + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)

    auth = resolve_authority(AUTHORITY)
    src = auth.source
    data = src / DATA_REL
    keygen_path = data / KEYGEN_FILE
    siggen_path = data / SIGGEN_FILE
    sigver_path = data / SIGVER_FILE
    for p in (keygen_path, siggen_path, sigver_path, src / SIZES_REL):
        if not p.is_file():
            raise VectorError(f"{rel(p)} is absent; --emit needs the pinned authority source tree")

    sizes = parse_sizes((src / SIZES_REL).read_text(encoding="utf-8"))

    keygen = build_keygen(keygen_path, sizes)
    siggen = build_siggen(siggen_path, sizes)
    sigver = build_sigver(sigver_path, sizes)
    if not keygen or not siggen or not sigver:
        raise VectorError("an arm is empty; a court with no vectors checks nothing")

    ids = [v.id for v in (*keygen, *siggen, *sigver)]
    if len(ids) != len(set(ids)):
        raise VectorError("vector ids are not unique")

    OUT_H.write_text(render_header(keygen, siggen, sigver, sizes), encoding="utf-8")

    mirrors = {
        "keygen": (keygen_path, KEYGEN_FILE),
        "siggen": (siggen_path, SIGGEN_FILE),
        "sigver": (sigver_path, SIGVER_FILE),
    }
    sha = {arm: hashlib.sha256(path.read_bytes()).hexdigest()
           for arm, (path, _name) in mirrors.items()}

    def corpus_prov(arm: str, line: int) -> dict:
        path, name = mirrors[arm]
        return {
            "primary_source": PRIMARY_SOURCE,
            "derivation": "corpus",
            "file": rel(path),
            "line": line,
            "authority": auth.id,
            "mirror_sha256": sha[arm],
        }

    vectors: list[dict] = []
    for v in keygen:
        vectors.append({
            "arm": "keygen",
            "id": v.id,
            "alg": v.alg,
            "expected_sha256": hashlib.sha256(v.pub).hexdigest(),
            "provenance": corpus_prov("keygen", v.line),
        })
    for v in siggen:
        vectors.append({
            "arm": "siggen",
            "id": v.id,
            "alg": v.alg,
            "expected_sha256": hashlib.sha256(v.sig).hexdigest(),
            "provenance": corpus_prov("siggen", v.line),
        })
    for v in sigver:
        vectors.append({
            "arm": "sigver",
            "id": v.id,
            "alg": v.alg,
            "expected": v.expected,
            "provenance": corpus_prov("sigver", v.line),
        })

    body = {
        "court": "CT-ML-DSA",
        "standard": "FIPS 204 (ML-DSA)",
        "primary_source": PRIMARY_SOURCE,
        "probe": "courts/phase8/ct_ml_dsa.c",
        "inputs_header": rel(OUT_H),
        "selection": {
            "keygen": "all distinct (seed, public key) vectors"
                      if KEYGEN_PER_SET is None else f"{KEYGEN_PER_SET} per set",
            "siggen": f"first {SIGGEN_PER_SET} `deterministic:1`, non-external-mu per set",
            "sigver": f"first {SIGVER_ACCEPT_PER_SET} accept and "
                      f"{SIGVER_REJECT_PER_SET} reject, non-external-mu, per set",
            "not_taken": [
                "siggen blocks without `deterministic:1` (their signature depends on a "
                "test-entropy `rnd` and is not reproducible from the vector alone)",
                "external-mu (`Ctrl = mu:1`) blocks: this probe drives the pure raw-message "
                "interface, and the `mu` representative interface is named as not observed",
                "the `test/ml_dsa.inc` cut-down corpus: its siggen items carry only a signature "
                "digest, and it is driven with `message-encoding:0`",
            ],
        },
        "sizes": {
            "seed_bytes": sizes.seed_bytes,
            "max_context": sizes.max_context,
            "per_alg": {a: list(t) for a, t in sorted(sizes.per_alg.items())},
            "note": "read from the authority's own include/crypto/ml_dsa.h and required to equal "
                    "FIPS 204 Table 1/2",
        },
        "provenance": {
            "note": (
                "Candidate-only construction verification: the expected bytes are the pinned "
                "authority's checked-in FIPS 204 / ACVP vectors, mirrored above with each "
                "source file's sha256 in `inputs[]` and each vector's line recorded. This does "
                "NOT establish that the mirror is faithful to a standard nobody here has read, "
                "and a CT pass is not formal validation (docs/DECISIONS.md D201/D208)."
            ),
        },
        "arms": {
            "keygen": len(keygen),
            "siggen": len(siggen),
            "sigver": len(sigver),
        },
        "vectors": vectors,
    }

    inputs = [
        InputRef(name="corpus-keygen", path=keygen_path),
        InputRef(name="corpus-siggen", path=siggen_path),
        InputRef(name="corpus-sigver", path=sigver_path),
        InputRef(name="ml-dsa-sizes", path=src / SIZES_REL),
        InputRef(name="ml-dsa-cutdown-corpus", path=src / HDR_REL,
                 note="the authority's cut-down C form of the same corpus; not read by this "
                      "generator (see the selection.not_taken note) but named so the omission "
                      "is auditable"),
        InputRef(name="ml-dsa-cutdown-driver", path=src / TEST_REL,
                 note="how each `ml_dsa.inc` item is used"),
    ]
    doc = envelope(kind="ct-ml-dsa-vectors", generator=GENERATOR, inputs=inputs,
                   body=body, authority=auth.id)
    write_json(OUT_ATLAS, doc)

    print(
        f"[ct-ml-dsa] keygen={len(keygen)} siggen={len(siggen)} sigver={len(sigver)} "
        f"(algs {', '.join(ALGS)}); wrote {rel(OUT_H)} and {rel(OUT_ATLAS)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
