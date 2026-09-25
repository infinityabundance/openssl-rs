#!/usr/bin/env python3
"""openssl-rs — the CT-BN-RAND construction vectors for `crypto/bn/bn_rand.c`'s DSA nonce.

Why this court
--------------
`crypto/bn/bn_rand.c`'s exports are *draws*: `BN_rand`, `BN_rand_range` and their `priv`/`ex`
spellings fill a caller's buffer from a seeding pool, so two machines never agree and the
differential court (`RT-BN-RAND`) is forced to observe each arm's *contract* -- a return code,
`BN_num_bits(rnd) <= bits`, the pinned bits, `BN_cmp(rnd, range) < 0` -- and never a value. That
leaves one function in the file whose body is a **construction rather than a draw**:

    ossl_bn_gen_dsa_nonce_fixed_top   crypto/bn/bn_rand.c:293-395
    BN_generate_dsa_nonce             crypto/bn/bn_rand.c:397-412

Each candidate is `SHA512(i || priv || message || random)` chained into `BN_num_bytes(range)+1`
bytes, masked to `BN_num_bits(range)` and rejected until it is below `range`. The `random` stream
is *injectable* -- it is whatever `RAND_priv_bytes_ex` reaches, and the default provider publishes
`TEST-RAND`, whose `generate` returns exactly the octet string a caller set as `test_entropy` --
so the whole output is a pure function of `(range, priv, message, entropy)`.

That is what makes this a `CT-*` court rather than an `RT-*` one. The expected bytes are **not**
read out of the authority's own test corpus (there is none for this function) and are **not**
obtained by running the authority or the crate: they are re-derived here, in Python, from the
construction alone. Nothing the crate transcribes -- not the byte order of `private_bytes`, not
the `i` counter, not the `min(num_k_bytes - done, 64)` split, not the mask's interaction with the
`0xff` top byte -- can move the expected value, because the value is computed from the source's
stated arithmetic rather than from any implementation of it. That independence is the same
`derivation: independent` class `forensics/tools/correctness_vectors.py`'s header describes, and
the oracle string recorded per vector names this generator as the oracle.

What the fixed-seed mechanism is, and where it is checked
--------------------------------------------------------
`providers/implementations/rands/test_rng.c.in`'s `test_rng_set_ctx_params` accepts
`OSSL_RAND_PARAM_TEST_ENTROPY` (the key string `"test_entropy"`, `:236`) as an octet string, and
with `generate` unset `test_rng_generate` (`:88-105`) copies exactly those bytes out in order,
refusing (`return 0`) only when fewer than `outlen` remain. `test/rand_test.c`'s `test_rand`
(`:20-50`) is the pattern the probe follows: `RAND_set_DRBG_type(NULL, "TEST-RAND", ...)` before the
first draw, `RAND_get0_private(NULL)`, `EVP_RAND_CTX_set_params(privctx, params)`, then
`RAND_priv_bytes`. Both the seed-settability and the row's presence in the candidate are
*measured*, not assumed: `courts/phase9/rt_drbg_probe.c` prints `settable.TEST-RAND.0=test_entropy:5`
and `bytes.TEST-RAND=000102...3f` identically on both sides, and `artifacts/phase9/COURTS.json`
carries that court's zero-residual transcript.

The committed stream is consumed **sequentially** across the vectors, in file order: the probe
installs it once and each `RAND_priv_bytes_ex(..., 64, 0)` advances `entropy_pos` by exactly 64
bytes. This generator models that consumption exactly -- a vector needing `ceil((num_k_bytes-1)/64)`
draws per outer attempt times the number of attempts -- and it is made several kilobytes long
because `test_rng_generate` refuses a draw that runs past the end.

Where the task sketch and the source disagree
---------------------------------------------
The brief's sketch says a range whose byte length makes the digest chain need two iterations is
"so `num_k_bytes > 64`, i.e. a range over 63 bytes wide". The source's inner loop is
`for (done = 1; done < num_k_bytes;)`, so **one** SHA-512 call already advances `done` from 1 to
`1 + min(num_k_bytes - 1, 64)`; a second call is needed only when `num_k_bytes - 1 > 64`, i.e.
`num_k_bytes >= 66`, i.e. `BN_num_bytes(range) >= 65`, i.e. `range >= 2^512`. A 64-byte range
(`num_k_bytes == 65`) is still one call, and a 63-byte range (`num_k_bytes == 64`) is one call with
one byte to spare. The `wide_range_two_digest` vector below is 80 bytes wide (`num_k_bytes == 81`,
two calls) and the generator asserts `draws_per_attempt == 2` for it, so the arm the brief asked
for is present; the brief's threshold is recorded here rather than reproduced.

What is checked rather than assumed
-----------------------------------
* `num_k_bytes`, `draws_per_attempt` and the mask are taken from the source's arithmetic and
  asserted. In particular the `w >= a->top` refusal of `ossl_bn_mask_bits_fixed_top`
  (`crypto/bn/bn_lib.c:863-880`) **cannot trigger** for a value built this way -- the `0xff` top
  byte gives `out` `ceil(num_k_bytes/8)` limbs and `BN_num_bits(range)/64 <= num_k_bytes/8 - 1`
  for every `num_k_bytes >= 2` -- so the mask is exactly `value mod 2^BN_num_bits(range)`, and the
  generator raises rather than assume if that inequality ever fails.
* Every expected value is non-zero, so the probe's minimal `BN_bn2bin` encoding is non-empty.
  The expected string is that encoding's hex -- `value.to_bytes((bit_length+7)//8, "big").hex()`
  -- which is what `BN_bn2bin` writes and is always **even-length**: a value whose top nibble is
  zero still leads with a `0` nibble there, where Python's `format(value, "x")` would drop it. A
  zero would print nothing and could not be told from an error; the generator refuses one.
* The reject vector's first candidate is asserted to be `>= range` and its second `< range`, so
  the outer loop's second iteration is exercised rather than hoped for.
* After the stream is built, every vector is re-derived from the committed stream in order and
  compared with the recorded value and byte count.

Usage: `python3 forensics/tools/gen_bn_rand_nonce_vectors.py`

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    rel,
    resolve_authority,
    write_json,
    write_text,
)

GENERATOR = "forensics/tools/gen_bn_rand_nonce_vectors.py"

OUT_JSON = REPO_ROOT / "forensics" / "vectors" / "bn_rand_nonce.json"
OUT_H = REPO_ROOT / "courts" / "phase9" / "ct_bn_rand_vectors.h"

BN_RAND = "crypto/bn/bn_rand.c"
BN_LIB = "crypto/bn/bn_lib.c"
TEST_RNG = "providers/implementations/rands/test_rng.c.in"
RAND_TEST = "test/rand_test.c"
BN_H = "include/openssl/bn.h"

# The source's constants, by their authority lines.
PRIV_PAD = 96       # `unsigned char private_bytes[96]`            bn_rand.c:308
DRAW_BYTES = 64     # `unsigned char random_bytes[64]`             bn_rand.c:303
SHA512_LEN = 64     # `SHA512_DIGEST_LENGTH`
MAX_N = 64          # `const int max_n = 64`                       bn_rand.c:310
TOP_BYTE = 0xFF     # `k_bytes[0] = 0xff;`                         bn_rand.c:323

# The committed stream's floor. `test_rng_generate` refuses a draw past the end, so the stream is
# generously longer than the vectors consume; the tail is never read.
STREAM_TARGET = 4096
STREAM_CHUNK = 8192  # a per-attempt search block, rolled back when it does not satisfy the arm

PRIMARY_SOURCE = (
    "crypto/bn/bn_rand.c:293-395 (ossl_bn_gen_dsa_nonce_fixed_top) and :397-412 "
    "(BN_generate_dsa_nonce); the mask is crypto/bn/bn_lib.c:863-880 "
    "(ossl_bn_mask_bits_fixed_top); the injectable draw is TEST-RAND, "
    "providers/implementations/rands/test_rng.c.in:88-105 / :234-281"
)
ORACLE = (
    "independent Python re-derivation from the construction in "
    "forensics/tools/gen_bn_rand_nonce_vectors.py: SHA-512 over (i || BN_bn2binpad(priv,96) || "
    "message || 64 entropy bytes) chained into BN_num_bytes(range)+1 bytes (k_bytes[0]=0xff) and "
    "masked to BN_num_bits(range), rejected until < range. Neither the crate nor the pinned "
    "authority build is run to obtain these bytes."
)


def _bn_num_bits(value: int) -> int:
    """`BN_num_bits`: the index of the highest set bit plus one (0 for zero)."""
    return value.bit_length()


def _bn_num_bytes(value: int) -> int:
    """`BN_num_bytes`: `(BN_num_bits(value) + 7) / 8`."""
    return (_bn_num_bits(value) + 7) // 8


def _num_k_bytes(range_int: int) -> int:
    """`const unsigned num_k_bytes = BN_num_bytes(range) + 1;` — bn_rand.c:307."""
    return _bn_num_bytes(range_int) + 1


def _draws_per_attempt(range_int: int) -> int:
    """SHA-512 calls per outer attempt: `while (done < num_k_bytes)` from `done = 1`."""
    return (_num_k_bytes(range_int) - 1 + DRAW_BYTES - 1) // DRAW_BYTES


def _mask_limbs(num_k_bytes: int) -> int:
    """`out`'s limb count after `BN_bin2bn` of a buffer whose top byte is `0xff`."""
    return (num_k_bytes + 7) // 8


def derive(range_int: int, priv_int: int, message: bytes, stream: bytes, offset: int) -> dict:
    """Re-derive `ossl_bn_gen_dsa_nonce_fixed_top` from the stream's bytes at `offset`.

    Returns `{accepted, candidates, draws, consumed}`: the accepted value (or `None` after
    `max_n` attempts), every candidate the outer loop produced, the 64-byte draws it consumed and
    the byte length consumed. The body is statement for statement the authority's, with the
    mask's `w >= a->top` refusal asserted away rather than silently dropped.
    """
    nbits = _bn_num_bits(range_int)
    num_k = _num_k_bytes(range_int)
    per = _draws_per_attempt(range_int)
    private_bytes = priv_int.to_bytes(PRIV_PAD, "big")
    mask = (1 << nbits) - 1

    # `ossl_bn_mask_bits_fixed_top(out, nbits)` with `w = nbits / 64` and `out->top` (limb count)
    # `_mask_limbs(num_k)`: the authority returns 0 *without masking* when `w >= out->top`, and
    # the caller ignores that answer, so if it could happen the expected value would not be a
    # simple `mod 2^nbits`. It cannot, for a buffer whose top byte is 0xff.
    if nbits // 64 >= _mask_limbs(num_k):
        raise SystemExit(
            f"{GENERATOR}: mask would refuse for a {nbits}-bit range "
            f"(num_k_bytes={num_k}, limbs={_mask_limbs(num_k)})"
        )

    consumed = 0
    candidates: list[int] = []
    for _outer in range(MAX_N):
        k = bytearray(num_k)
        k[0] = TOP_BYTE
        done = 1
        i = 0
        for _inner in range(per):
            rb = stream[offset + consumed: offset + consumed + DRAW_BYTES]
            if len(rb) != DRAW_BYTES:
                raise SystemExit(f"{GENERATOR}: entropy stream exhausted at offset {offset}")
            consumed += DRAW_BYTES
            digest = hashlib.sha512(bytes([i]) + private_bytes + message + rb).digest()
            todo = min(num_k - done, SHA512_LEN)
            k[done:done + todo] = digest[:todo]
            done += todo
            i += 1
        value = int.from_bytes(k, "big") & mask
        candidates.append(value)
        if value < range_int:
            return {
                "accepted": value,
                "candidates": candidates,
                "draws": consumed // DRAW_BYTES,
                "consumed": consumed,
            }
    return {"accepted": None, "candidates": candidates, "draws": consumed // DRAW_BYTES,
            "consumed": consumed}


def _minimal_hex(value: int) -> str:
    """The hex `BN_bn2bin` produces for `value`: the minimal big-endian byte encoding.

    Always even-length, unlike `format(value, "x")`, which drops a leading zero nibble. The
    probe prints bytes, so the two must agree on the encoding and not only on the number.
    """
    if value == 0:
        return ""
    return value.to_bytes((value.bit_length() + 7) // 8, "big").hex()


def _stream_bytes(seed: str, index: int, length: int) -> bytes:
    """A deterministic byte block, so nothing here depends on time, PID or the platform."""
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out += hashlib.sha512(f"CT-BN-RAND|{seed}|{index}|{ctr}".encode("ascii")).digest()
        ctr += 1
    return bytes(out[:length])


def _specs() -> list[dict]:
    """The vectors, in the order the probe drives them and the stream is consumed."""

    def seq(start: int, n: int) -> bytes:
        return bytes(range(start, start + n))

    return [
        {
            "label": "wide_range_two_digest",
            # 80 bytes wide: BN_num_bytes(range)=80, num_k_bytes=81, and the inner chain needs
            # two SHA-512 calls (1 + 64 = 65 < 81, then +16).
            "range": b"\x01" + seq(0x02, 79),
            "priv": seq(0x01, 32),
            "message": b"openssl-rs CT-BN-RAND",
            "arm": "wide",
            "note": "80-byte range: num_k_bytes=81, so one outer attempt makes two SHA-512 calls "
                    "(the brief's 'two iterations' arm, at the source's real threshold)",
        },
        {
            "label": "reject_once",
            # 2^127 + 1: nbits=128, so the first candidate is >= range about half the time; the
            # committed stream is searched until it is, and the second is below it.
            "range": bytes.fromhex("80000000000000000000000000000001"),
            "priv": seq(0x21, 32),
            "message": b"reject-this-candidate",
            "arm": "reject",
            "note": "16-byte range chosen so the first candidate is rejected and the second is "
                    "accepted: the outer loop's second iteration is exercised on purpose",
        },
        {
            "label": "tiny_range",
            # 0x0f4240 = 1000000: nbits=20, BN_num_bytes=3, num_k_bytes=4, mask to 20 bits.
            "range": bytes.fromhex("0f4240"),
            "priv": seq(0x41, 20),
            "message": b"tiny",
            "arm": "plain",
            "note": "3-byte range: the mask to 20 bits is the whole reduction, and the top byte "
                    "of k_bytes (0xff) is entirely above the mask",
        },
        {
            "label": "empty_message",
            # 32-byte range, top byte 0x80: nbits=256, num_k_bytes=33.
            "range": seq(0x80, 32),
            "priv": seq(0x60, 32),
            "message": b"",
            "arm": "plain",
            "note": "zero-length message: EVP_DigestUpdate over (i || priv ||  || random)",
        },
        {
            "label": "plain_message",
            # 20-byte range, top byte 0x20: nbits=158, num_k_bytes=21.
            "range": seq(0x20, 20),
            "priv": seq(0xA0, 32),
            "message": b"nonce",
            "arm": "plain",
            "note": "an ordinary non-empty message and a 20-byte range",
        },
    ]


def build() -> tuple[bytes, list[dict]]:
    """Build the committed stream and every vector's expected value, self-checked."""
    vectors = _specs()
    for v in vectors:
        v["range_int"] = int.from_bytes(v["range"], "big")
        v["priv_int"] = int.from_bytes(v["priv"], "big")
        if v["range_int"] <= 0:
            raise SystemExit(f"{GENERATOR}: {v['label']} has a non-positive range")
        if v["priv_int"].bit_length() > PRIV_PAD * 8:
            raise SystemExit(f"{GENERATOR}: {v['label']} has a private key wider than 96 bytes")
        if v["arm"] == "wide" and _draws_per_attempt(v["range_int"]) != 2:
            raise SystemExit(f"{GENERATOR}: {v['label']} does not need two SHA-512 calls")
        if len(v["message"]) > 255:
            raise SystemExit(f"{GENERATOR}: {v['label']} has a message that overflows the counter")

    stream = bytearray()
    for v in vectors:
        offset = len(stream)
        for index in range(4096):
            stream.extend(_stream_bytes(v["label"], index, STREAM_CHUNK))
            r = derive(v["range_int"], v["priv_int"], v["message"], bytes(stream), offset)
            ok = r["accepted"] is not None and r["accepted"] != 0
            if v["arm"] == "reject":
                ok = ok and len(r["candidates"]) == 2 and r["candidates"][0] >= v["range_int"]
            if ok:
                del stream[offset + r["consumed"]:]
                v["expected_int"] = r["accepted"]
                v["attempts"] = len(r["candidates"])
                v["draws"] = r["draws"]
                break
            del stream[offset:]
        else:
            raise SystemExit(f"{GENERATOR}: no entropy window satisfied {v['label']}")

    if len(stream) < STREAM_TARGET:
        stream.extend(_stream_bytes("padding", 0, STREAM_TARGET - len(stream)))
    stream = bytes(stream)

    # Re-derive every vector from the committed stream, in order, and require the same answer.
    offset = 0
    for v in vectors:
        r = derive(v["range_int"], v["priv_int"], v["message"], stream, offset)
        if r["accepted"] != v["expected_int"] or r["consumed"] != v["draws"] * DRAW_BYTES:
            raise SystemExit(f"{GENERATOR}: {v['label']} does not re-derive from the stream")
        offset += r["consumed"]
    if offset > len(stream):
        raise SystemExit(f"{GENERATOR}: vectors consume past the committed stream")
    return stream, vectors


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _render_bytes(name: str, data: bytes) -> str:
    lines = [f"static const unsigned char {name}[{len(data)}] = {{"]
    for i in range(0, len(data), 16):
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in data[i:i + 16]) + ",")
    lines.append("};")
    return "\n".join(lines)


def render_header(stream: bytes, vectors: list[dict]) -> str:
    o: list[str] = []
    o.append("/*")
    o.append(" * openssl-rs — the CT-BN-RAND vector inputs, generated, never transcribed.")
    o.append(" *")
    o.append(" * Produced by `forensics/tools/gen_bn_rand_nonce_vectors.py`; **do not edit by")
    o.append(" * hand.** This header carries only what the candidate-only probe must *drive* --")
    o.append(" * each vector's `range`, `priv` and `message`, and the committed TEST-RAND")
    o.append(" * `test_entropy` stream, consumed sequentially in array order. The *expected*")
    o.append(" * values are not here: they live in `forensics/vectors/bn_rand_nonce.json` and the")
    o.append(" * runner owns the comparison, so the probe computes and never decides.")
    o.append(" *")
    o.append(" * SPDX-License-Identifier: Apache-2.0")
    o.append(" */")
    o.append("#ifndef OSSL_RS_CT_BN_RAND_VECTORS_H")
    o.append("#define OSSL_RS_CT_BN_RAND_VECTORS_H")
    o.append("")
    o.append("#include <stddef.h>")
    o.append("")
    o.append("struct ct_bn_rand_vector {")
    o.append("    const char *label;")
    o.append("    const unsigned char *range;")
    o.append("    size_t range_len;")
    o.append("    const unsigned char *priv;")
    o.append("    size_t priv_len;")
    o.append("    const unsigned char *message;")
    o.append("    size_t message_len;")
    o.append("};")
    o.append("")
    o.append("/* A zero-length message, so an empty message is not a NULL idiom. */")
    o.append("static const unsigned char ct_bn_rand_empty[1] = { 0 };")
    o.append("")
    o.append("/* The committed TEST-RAND `test_entropy` stream, in consumption order. */")
    o.append(_render_bytes("ct_bn_rand_entropy", stream))
    o.append("")
    for i, v in enumerate(vectors):
        o.append(f"/* {v['label']} */")
        o.append(_render_bytes(f"v{i}_range", v["range"]))
        o.append(_render_bytes(f"v{i}_priv", v["priv"]))
        if v["message"]:
            o.append(_render_bytes(f"v{i}_message", v["message"]))
    o.append("")
    o.append(f"static const struct ct_bn_rand_vector ct_bn_rand_vectors[{len(vectors)}] = {{")
    for i, v in enumerate(vectors):
        msg = f"v{i}_message, {len(v['message'])}" if v["message"] else "ct_bn_rand_empty, 0"
        o.append(
            f'    {{ "{v["label"]}", v{i}_range, {len(v["range"])}, '
            f'v{i}_priv, {len(v["priv"])}, {msg} }},'
        )
    o.append("};")
    o.append("")
    o.append("#endif /* OSSL_RS_CT_BN_RAND_VECTORS_H */")
    return "\n".join(o) + "\n"


def render_body(stream: bytes, vectors: list[dict]) -> dict:
    return {
        "court": "CT-BN-RAND",
        "algorithm": "bn-rand-nonce",
        "primary_source": PRIMARY_SOURCE,
        "provenance": {
            "note": (
                "Candidate-only construction verification. The expected bytes are re-derived from "
                "the construction in Python (" + ORACLE + "). This is the "
                "`derivation: independent` class: the values are independent of the "
                "implementation *code*, so a transcription error in the crate cannot move them. "
                "It is NOT OpenSSL parity (that is RT-BN-RAND's question) and it is NOT formal "
                "validation. See docs/DECISIONS.md D201/D208."
            ),
            "derivation": "independent",
            "oracle": ORACLE,
        },
        "entropy_mechanism": (
            "TEST-RAND installed as the private DRBG by RAND_set_DRBG_type(NULL, \"TEST-RAND\", "
            "NULL, NULL, NULL) before the first draw, then EVP_RAND_CTX_set_params(privctx, "
            "OSSL_RAND_PARAM_TEST_ENTROPY). The probe prints ct.drbg_type and ct.entropy_set so a "
            "failure of this mechanism is a named line rather than a cascade of wrong values."
        ),
        "entropy_hex": stream.hex(),
        "entropy_len": len(stream),
        "inputs_header": rel(OUT_H),
        "vectors": [
            {
                "label": v["label"],
                "range_hex": v["range"].hex(),
                "priv_hex": v["priv"].hex(),
                "message_hex": v["message"].hex(),
                "expected": _minimal_hex(v["expected_int"]),
                "note": v["note"],
            }
            for v in vectors
        ],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    src = auth.source
    for rel_path in (BN_RAND, BN_LIB, TEST_RNG, RAND_TEST, BN_H):
        if not (src / rel_path).is_file():
            raise SystemExit(f"{GENERATOR}: {rel_path} is absent from {auth.id}")

    stream, vectors = build()
    write_text(OUT_H, render_header(stream, vectors))

    inputs = [
        InputRef(name="authority-source-bn-rand", path=src / BN_RAND,
                 note="ossl_bn_gen_dsa_nonce_fixed_top (:293-395) and BN_generate_dsa_nonce "
                      "(:397-412) — the construction these vectors re-derive"),
        InputRef(name="authority-source-bn-lib", path=src / BN_LIB,
                 note="ossl_bn_mask_bits_fixed_top (:863-880) — the mask"),
        InputRef(name="authority-source-test-rng", path=src / TEST_RNG,
                 note="test_rng_set_ctx_params (:234-281) and test_rng_generate (:88-105) — the "
                      "fixed-seed mechanism"),
        InputRef(name="authority-source-rand-test", path=src / RAND_TEST,
                 note="test_rand (:20-50) — the RAND_set_DRBG_type / RAND_get0_private / "
                      "test_entropy pattern the probe follows"),
        InputRef(name="authority-declaration-bn", path=src / BN_H,
                 note="the declaration of BN_generate_dsa_nonce and the BIGNUM API the probe uses"),
    ]

    doc = {
        "schema": "openssl-rs/correctness-vectors/v1",
        "kind": "correctness-vectors",
        "generator": GENERATOR,
        "authority": auth.id,
        "inputs": [i.resolved() for i in inputs],
        "body": render_body(stream, vectors),
    }
    write_json(OUT_JSON, doc)

    print(
        f"[ct-bn-rand] authority={auth.id} vectors={len(vectors)} "
        f"entropy={len(stream)}B draws={sum(v['draws'] for v in vectors)}"
    )
    print(f"  -> {rel(OUT_H)}")
    print(f"  -> {rel(OUT_JSON)}")
    for v in vectors:
        print(f"     {v['label']:<24} expected={_minimal_hex(v['expected_int'])[:24]}... "
              f"({v['draws']} draws, {v['attempts']} attempt(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
