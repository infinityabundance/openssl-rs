#!/usr/bin/env python3
"""harden.py -- one strict JSON reader for received evidence, and a differential.

Why this tool exists
--------------------
Every record this project admits is parsed by something.  Python's ``json.loads``
is permissive in ways that silently change meaning rather than fail:

* a duplicate key is last-wins, so two different documents parse to one object;
* ``NaN``, ``Infinity`` and ``-Infinity`` are accepted although they are not JSON;
* a BOM and trailing data are accepted by some readers and readers configured to
  ignore them;
* integers are unbounded in one reader and IEEE-754 doubles in another, so a value
  above 2**53 is exact in the first and changed in the second;
* an integral value written as a float (``1.0``, ``1e3``) changes its type;
* deep nesting and huge inputs turn a parser into a denial-of-service surface.

The failure that matters is not only a crash.  It is a reader that returns a
value while having read a different document.  This module therefore provides
one strict reader for received evidence (``loads``), an explicitly named
permissive reference used only by the differential (``loads_permissive``), and a
differential that records where the two disagree.

The safe reading rules
----------------------
* input is bytes, decoded as UTF-8 strictly; a BOM is refused;
* size is bounded before parsing, and depth is bounded while parsing;
* a duplicate key at any depth is refused, not last-wins;
* only object, array, string, number, ``true``, ``false`` and ``null`` are
  accepted; ``NaN``/``Infinity``/``-Infinity`` and any other bare literal are
  refused;
* an integer literal must be canonical (``0`` or ``-?[1-9][0-9]*``) and its
  magnitude must fit ``integer_bits``; a float that overflows to infinity is
  refused;
* a leading ``+``, a leading zero, ``-0``, ``1.`` or ``.5`` is refused;
* a lone surrogate escape and a raw control character in a string are refused;
* every object key must be a string;
* trailing data after the top-level value is refused.

What this tool does not do
--------------------------
It does not harden the Rust parsers in ``src/`` and it makes no claim that the C
or Rust parser is safe.  It reads evidence files; the module above it decides
what an evidence record means.  The bound and the scan population are stated,
not assumed.

Usage
-----
    python3 forensics/tools/harden.py parse <path>
    python3 forensics/tools/harden.py differential <path>
    python3 forensics/tools/harden.py scan --live 'evidence/*.json'
    python3 forensics/tools/harden.py scan --frozen evidence/a11/SCAN.json

``scan --live`` reports the current glob and labels the result ``population:
LIVE``; it is a measurement of the tree now and is not comparable to a frozen
record.  ``scan --frozen`` rebuilds a record's explicit member list, re-hashing
every member, and reports a glob match that is not a member as
``NEW_SINCE_RECORD`` with the frozen count unchanged.  A removed or changed
member is refused with ``PH_REFUSED_POPULATION_DRIFT``.

Exit status: 0 for an accepted parse / a scan with no refusal, 1 for a refusal,
2 for a usage or I/O error.  The code is always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import fnmatch
import hashlib
import json
import math
import os
import subprocess
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/harden.py"

CODE_OK = "PH_OK"
CODE_USAGE = "PH_USAGE"

PH_REFUSED_ENCODING = "PH_REFUSED_ENCODING"
PH_REFUSED_BOM = "PH_REFUSED_BOM"
PH_REFUSED_DUPLICATE_KEY = "PH_REFUSED_DUPLICATE_KEY"
PH_REFUSED_DEPTH = "PH_REFUSED_DEPTH"
PH_REFUSED_SIZE = "PH_REFUSED_SIZE"
PH_REFUSED_NONFINITE = "PH_REFUSED_NONFINITE"
PH_REFUSED_TRAILING_DATA = "PH_REFUSED_TRAILING_DATA"
PH_REFUSED_INTEGER_RANGE = "PH_REFUSED_INTEGER_RANGE"
PH_REFUSED_NUMBER_FORM = "PH_REFUSED_NUMBER_FORM"
PH_REFUSED_LONE_SURROGATE = "PH_REFUSED_LONE_SURROGATE"
PH_REFUSED_CONTROL_CHARACTER = "PH_REFUSED_CONTROL_CHARACTER"
PH_REFUSED_KEY_NOT_TEXT = "PH_REFUSED_KEY_NOT_TEXT"
PH_REFUSED_SYNTAX = "PH_REFUSED_SYNTAX"

# Defaults for the command line and the recorded scan.  They are parameters, not
# properties of JSON: a consumer that needs IEEE-754 exactness passes
# integer_bits=53, and a larger record passes a larger max_bytes.  The values are
# recorded in evidence/a11/SCAN.json so the population and the bound travel
# together.
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_DEPTH = 64
DEFAULT_INTEGER_BITS = 64

# The scan population is tracked JSON evidence, excluding the records this item
# emits: including them would make the record depend on its own bytes and never
# be reproducible once committed.
SCAN_GLOB = "evidence/*.json"
SCAN_EXCLUDED_PREFIXES = ("evidence/a11/",)

# The population a record covers is frozen as an explicit member list, not as
# "whatever the glob matches now".  A record was once produced from a live glob
# and presented as fixed, so every item that added JSON evidence silently
# changed the population while the record still claimed the old count.  The
# count is now bound to a member list; a live glob remains available but is
# labelled ``population: LIVE`` and is refused by the frozen-record verifier.
POPULATION_FROZEN = "FROZEN"
POPULATION_LIVE = "LIVE"
RESULT_NEW_SINCE_RECORD = "NEW_SINCE_RECORD"

# This is a record-verification refusal, not one of the 13 reader refusals in
# ``REFUSALS``: it is raised while rebuilding a frozen population, never by
# ``loads`` on an input.  Keeping it out of ``REFUSALS`` preserves the reader's
# 13 codes and their one-per-code controls.
PH_REFUSED_POPULATION_DRIFT = "PH_REFUSED_POPULATION_DRIFT"

# A frozen member is re-hashed in bounded chunks so binding a large record to its
# digest does not turn the whole file into one allocation.
HASH_CHUNK_BYTES = 1024 * 1024

REFUSALS: dict[str, dict[str, str]] = {
    PH_REFUSED_ENCODING: {
        "condition": "the input bytes are not valid UTF-8",
        "prevents": (
            "that a reader's fallback encoding turns the same bytes into a "
            "different string, so an identity digest over the bytes and the text "
            "the rule was applied to disagree"
        ),
    },
    PH_REFUSED_BOM: {
        "condition": "the input begins with a UTF-8, UTF-16 or UTF-32 byte-order mark",
        "prevents": (
            "that a BOM is accepted by one reader and treated as document content "
            "or rejected by another, so two readings of one file disagree about "
            "the first key or fail differently"
        ),
    },
    PH_REFUSED_DUPLICATE_KEY: {
        "condition": "an object repeats a key at any depth",
        "prevents": (
            "that two distinct documents collapse to one value, so the later value "
            "silently replaces the one a record was read as"
        ),
    },
    PH_REFUSED_DEPTH: {
        "condition": "containers are nested more deeply than max_depth",
        "prevents": (
            "that a deeply nested input consumes the reader's stack and its "
            "behaviour depends on the interpreter's recursion limit"
        ),
    },
    PH_REFUSED_SIZE: {
        "condition": "the input is larger than max_bytes",
        "prevents": (
            "that a huge record is read in full before anything decides whether it "
            "is admissible, turning a reader into a memory denial-of-service"
        ),
    },
    PH_REFUSED_NONFINITE: {
        "condition": "a NaN or Infinity literal, or a number that overflows to infinity",
        "prevents": (
            "that a value that is not JSON, or a finite literal whose value became "
            "infinite, is read as a number"
        ),
    },
    PH_REFUSED_TRAILING_DATA: {
        "condition": "non-whitespace bytes follow the top-level value",
        "prevents": (
            "that a second document appended to a record is ignored while the first "
            "is read and reported"
        ),
    },
    PH_REFUSED_INTEGER_RANGE: {
        "condition": "an integer's magnitude does not fit integer_bits",
        "prevents": (
            "that an integer is exact in one reader and rounded to a double or "
            "silently truncated in another"
        ),
    },
    PH_REFUSED_NUMBER_FORM: {
        "condition": (
            "a number is not in the canonical form this reader writes: a leading "
            "zero, a leading plus, -0, a missing fraction digit, or a bare .5"
        ),
        "prevents": (
            "that one value has several accepted spellings, so two byte strings "
            "parse to one number and a rewrite is invisible"
        ),
    },
    PH_REFUSED_LONE_SURROGATE: {
        "condition": "an escape encodes a high or low surrogate that is not paired",
        "prevents": (
            "that a string Python holds as an unpaired surrogate is emitted to a "
            "UTF-8 sink, where it fails or is replaced by a different character"
        ),
    },
    PH_REFUSED_CONTROL_CHARACTER: {
        "condition": "a string contains a raw character below U+0020",
        "prevents": (
            "that an unescaped newline or NUL is read as string content, so a "
            "record's text and the bytes that carry it are read differently"
        ),
    },
    PH_REFUSED_KEY_NOT_TEXT: {
        "condition": "an object member name is not a JSON string",
        "prevents": (
            "that a non-text key (a number, a bare word) is read as an object key "
            "by a reader that coerces it"
        ),
    },
    PH_REFUSED_SYNTAX: {
        "condition": "the input is not JSON at all",
        "prevents": (
            "that an empty, truncated or malformed document is read as an empty or "
            "partial value"
        ),
    },
}


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _as_bytes(data: Any) -> bytes:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"harden.loads takes bytes, not {type(data).__name__}")


_BOMS = (
    b"\xef\xbb\xbf",      # UTF-8
    b"\xff\xfe\x00\x00",  # UTF-32 little-endian
    b"\x00\x00\xfe\xff",  # UTF-32 big-endian
    b"\xff\xfe",          # UTF-16 little-endian
    b"\xfe\xff",          # UTF-16 big-endian
)


def _is_digit(character: str) -> bool:
    return "0" <= character <= "9"


_WHITESPACE = " \t\n\r"
_HEX = frozenset("0123456789abcdefABCDEF")


class _Parser:
    """A recursive-descent reader for the strict subset described above."""

    def __init__(self, text: str, max_depth: int, integer_bits: int) -> None:
        self.text = text
        self.length = len(text)
        self.index = 0
        self.max_depth = max_depth
        self.integer_limit = 1 << integer_bits
        self.integer_bits = integer_bits

    # -- primitives ---------------------------------------------------------

    def _skip_whitespace(self) -> None:
        text, length, index = self.text, self.length, self.index
        while index < length and text[index] in _WHITESPACE:
            index += 1
        self.index = index

    def _peek(self) -> str:
        return self.text[self.index] if self.index < self.length else ""

    def parse(self) -> Any:
        self._skip_whitespace()
        if self.index >= self.length:
            _fail(PH_REFUSED_SYNTAX, "the input is empty")
        value = self._value(0)
        self._skip_whitespace()
        if self.index != self.length:
            _fail(
                PH_REFUSED_TRAILING_DATA,
                f"{self.length - self.index} byte(s) after the top-level value",
            )
        return value

    # -- values -------------------------------------------------------------

    def _value(self, depth: int) -> Any:
        character = self._peek()
        if character == "":
            _fail(PH_REFUSED_SYNTAX, "a value was expected but the input ended")
        if character == "{":
            if depth + 1 > self.max_depth:
                _fail(
                    PH_REFUSED_DEPTH,
                    f"an object at depth {depth + 1} exceeds max_depth={self.max_depth}",
                )
            return self._object(depth + 1)
        if character == "[":
            if depth + 1 > self.max_depth:
                _fail(
                    PH_REFUSED_DEPTH,
                    f"an array at depth {depth + 1} exceeds max_depth={self.max_depth}",
                )
            return self._array(depth + 1)
        if character == '"':
            return self._string()
        if character == "t":
            return self._literal("true", True)
        if character == "f":
            return self._literal("false", False)
        if character == "n":
            return self._literal("null", None)
        if character == "N" or character == "I" or character == "+":
            _fail(
                PH_REFUSED_NONFINITE if character in "NI" else PH_REFUSED_NUMBER_FORM,
                f"{character!r} does not begin a JSON value",
            )
        if character == "-":
            if self.text.startswith("-Infinity", self.index):
                _fail(PH_REFUSED_NONFINITE, "-Infinity is not a JSON number")
            return self._number()
        if _is_digit(character) or character == ".":
            return self._number()
        _fail(PH_REFUSED_SYNTAX, f"{character!r} does not begin a JSON value")

    def _literal(self, word: str, value: Any) -> Any:
        if not self.text.startswith(word, self.index):
            _fail(PH_REFUSED_SYNTAX, f"{word!r} was expected")
        end = self.index + len(word)
        if end < self.length and (
            self.text[end].isalnum() or self.text[end] == "_"
        ):
            _fail(PH_REFUSED_SYNTAX, f"{self.text[self.index:end + 1]!r} is not a JSON literal")
        self.index = end
        return value

    # -- containers ---------------------------------------------------------

    def _object(self, depth: int) -> dict[str, Any]:
        self.index += 1  # '{'
        members: dict[str, Any] = {}
        self._skip_whitespace()
        if self._peek() == "}":
            self.index += 1
            return members
        while True:
            self._skip_whitespace()
            if self._peek() == "}":
                _fail(PH_REFUSED_SYNTAX, "a trailing comma is not a JSON object member")
            if self._peek() != '"':
                _fail(
                    PH_REFUSED_KEY_NOT_TEXT,
                    "an object member name must be a JSON string",
                )
            key = self._string()
            if key in members:
                _fail(
                    PH_REFUSED_DUPLICATE_KEY,
                    f"the object repeats the key {key!r}; a later value would "
                    "silently replace the earlier one",
                )
            self._skip_whitespace()
            if self._peek() != ":":
                _fail(PH_REFUSED_SYNTAX, "a member name must be followed by ':'")
            self.index += 1
            self._skip_whitespace()
            members[key] = self._value(depth)
            self._skip_whitespace()
            character = self._peek()
            if character == ",":
                self.index += 1
                continue
            if character == "}":
                self.index += 1
                return members
            _fail(PH_REFUSED_SYNTAX, "an object must continue with ',' or '}'")

    def _array(self, depth: int) -> list[Any]:
        self.index += 1  # '['
        values: list[Any] = []
        self._skip_whitespace()
        if self._peek() == "]":
            self.index += 1
            return values
        while True:
            self._skip_whitespace()
            values.append(self._value(depth))
            self._skip_whitespace()
            character = self._peek()
            if character == ",":
                self.index += 1
                continue
            if character == "]":
                self.index += 1
                return values
            _fail(PH_REFUSED_SYNTAX, "an array must continue with ',' or ']'")

    # -- strings ------------------------------------------------------------

    def _hex4(self) -> int:
        end = self.index + 4
        if end > self.length:
            _fail(PH_REFUSED_SYNTAX, "a \\u escape needs four hexadecimal digits")
        digits = self.text[self.index:end]
        if any(character not in _HEX for character in digits):
            _fail(PH_REFUSED_SYNTAX, f"{digits!r} is not four hexadecimal digits")
        self.index = end
        return int(digits, 16)

    def _string(self) -> str:
        self.index += 1  # '"'
        pieces: list[str] = []
        while True:
            if self.index >= self.length:
                _fail(PH_REFUSED_SYNTAX, "the string is not terminated")
            character = self.text[self.index]
            if character == '"':
                self.index += 1
                return "".join(pieces)
            if character == "\\":
                self.index += 1
                if self.index >= self.length:
                    _fail(PH_REFUSED_SYNTAX, "the string ends inside an escape")
                escape = self.text[self.index]
                self.index += 1
                if escape in '"\\/':
                    pieces.append(escape)
                elif escape == "b":
                    pieces.append("\b")
                elif escape == "f":
                    pieces.append("\f")
                elif escape == "n":
                    pieces.append("\n")
                elif escape == "r":
                    pieces.append("\r")
                elif escape == "t":
                    pieces.append("\t")
                elif escape == "u":
                    code = self._hex4()
                    if 0xD800 <= code <= 0xDBFF:
                        if self.text[self.index:self.index + 2] != "\\u":
                            _fail(
                                PH_REFUSED_LONE_SURROGATE,
                                f"the high surrogate U+{code:04X} is not followed by "
                                "a low surrogate",
                            )
                        self.index += 2
                        low = self._hex4()
                        if not 0xDC00 <= low <= 0xDFFF:
                            _fail(
                                PH_REFUSED_LONE_SURROGATE,
                                f"the high surrogate U+{code:04X} is followed by "
                                f"U+{low:04X}, not a low surrogate",
                            )
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                    elif 0xDC00 <= code <= 0xDFFF:
                        _fail(
                            PH_REFUSED_LONE_SURROGATE,
                            f"the low surrogate U+{code:04X} has no high surrogate",
                        )
                    pieces.append(chr(code))
                else:
                    _fail(PH_REFUSED_SYNTAX, f"\\{escape} is not a JSON escape")
            else:
                if ord(character) < 0x20:
                    _fail(
                        PH_REFUSED_CONTROL_CHARACTER,
                        f"U+{ord(character):04X} is a raw control character in a "
                        "string, not an escape",
                    )
                pieces.append(character)
                self.index += 1

    # -- numbers ------------------------------------------------------------

    def _number(self) -> Any:
        start = self.index
        if self._peek() == "-":
            self.index += 1
        character = self._peek()
        if character == "":
            _fail(PH_REFUSED_SYNTAX, "the input ends inside a number")
        if character == "0":
            self.index += 1
            if self._peek() and _is_digit(self._peek()):
                _fail(
                    PH_REFUSED_NUMBER_FORM,
                    "an integer with a leading zero is not the canonical form",
                )
        elif _is_digit(character):
            while self._peek() and _is_digit(self._peek()):
                self.index += 1
        else:
            _fail(
                PH_REFUSED_NUMBER_FORM,
                f"a number must have a digit here, not {character!r}",
            )
        is_float = False
        if self._peek() == ".":
            is_float = True
            self.index += 1
            if not (self._peek() and _is_digit(self._peek())):
                _fail(
                    PH_REFUSED_NUMBER_FORM,
                    "a fraction needs at least one digit after the '.'",
                )
            while self._peek() and _is_digit(self._peek()):
                self.index += 1
        if self._peek() in ("e", "E"):
            is_float = True
            self.index += 1
            if self._peek() in ("+", "-"):
                self.index += 1
            if not (self._peek() and _is_digit(self._peek())):
                _fail(
                    PH_REFUSED_NUMBER_FORM,
                    "an exponent needs at least one digit",
                )
            while self._peek() and _is_digit(self._peek()):
                self.index += 1
        token = self.text[start:self.index]
        if not is_float:
            if token == "-0":
                _fail(
                    PH_REFUSED_NUMBER_FORM,
                    "-0 is not the canonical form of the integer zero",
                )
            value = int(token)
            if abs(value) >= self.integer_limit:
                _fail(
                    PH_REFUSED_INTEGER_RANGE,
                    f"{token} does not fit integer_bits={self.integer_bits} "
                    "(the magnitude must be below 2**integer_bits)",
                )
            return value
        value = float(token)
        if not math.isfinite(value):
            _fail(
                PH_REFUSED_NONFINITE,
                f"{token} overflows to a non-finite double",
            )
        return value


def loads(
    data: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    integer_bits: int = DEFAULT_INTEGER_BITS,
) -> Any:
    """Parse ``data`` as strict JSON or raise :class:`Refusal`.

    The bounds are parameters.  ``max_bytes`` refuses an input larger than the
    bound *before* decoding; ``max_depth`` bounds the number of nested
    containers; ``integer_bits`` bounds an integer's magnitude (``abs(v) <
    2**integer_bits``).  Passing ``integer_bits=53`` refuses any integer a
    double cannot hold exactly.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    if integer_bits < 1:
        raise ValueError("integer_bits must be at least 1")
    raw = _as_bytes(data)
    if len(raw) > max_bytes:
        _fail(
            PH_REFUSED_SIZE,
            f"{len(raw)} bytes exceeds max_bytes={max_bytes}",
        )
    for bom in _BOMS:
        if raw.startswith(bom):
            _fail(
                PH_REFUSED_BOM,
                f"the input begins with the byte-order mark {bom.hex()}",
            )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(PH_REFUSED_ENCODING, f"the input is not UTF-8: {error}")
    return _Parser(text, max_depth, integer_bits).parse()


# ---------------------------------------------------------------------------
# The permissive reference.  It is used *only* by `differential`, so that the
# comparison is visible and not an accidental property of `loads`.
# ---------------------------------------------------------------------------


def _permissive_parse(data: bytes) -> tuple[Any, list[str]]:
    """Read the first JSON value the way a permissive reader would.

    ``utf-8-sig`` strips a BOM; ``raw_decode`` ignores trailing bytes; the
    decoder's default ``parse_constant`` accepts ``NaN``/``Infinity``; no
    object hook is installed, so a duplicate key is last-wins; ``strict=False``
    permits raw control characters; integers are unbounded and floats are
    doubles.
    """
    raw = _as_bytes(data)
    text = raw.decode("utf-8-sig")
    duplicates: list[str] = []

    def record(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                duplicates.append(key)
            seen[key] = value
        return seen

    decoder = json.JSONDecoder(object_pairs_hook=record, strict=False)
    stripped = text.lstrip(_WHITESPACE)
    value, _end = decoder.raw_decode(stripped)
    return value, duplicates


def loads_permissive(data: bytes) -> Any:
    """The explicitly named permissive reference used only by the differential.

    Never use this to admit an evidence record.  It exists so the strict reader's
    advantage can be measured against a named behaviour rather than asserted.
    """
    value, _duplicates = _permissive_parse(data)
    return value


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _number_changes(
    strict_value: Any, permissive_value: Any, path: str = "$"
) -> list[dict[str, Any]]:
    """Every leaf where the two readers disagree about a number's type or value."""
    changes: list[dict[str, Any]] = []
    if isinstance(strict_value, dict) and isinstance(permissive_value, dict):
        for key in sorted(set(strict_value) & set(permissive_value)):
            changes.extend(
                _number_changes(
                    strict_value[key], permissive_value[key], f"{path}.{key}"
                )
            )
        return changes
    if isinstance(strict_value, list) and isinstance(permissive_value, list):
        for index, (left, right) in enumerate(zip(strict_value, permissive_value)):
            changes.extend(_number_changes(left, right, f"{path}[{index}]"))
        return changes
    if isinstance(strict_value, bool) or isinstance(permissive_value, bool):
        return changes
    if isinstance(strict_value, (int, float)) and isinstance(
        permissive_value, (int, float)
    ):
        if type(strict_value) is not type(permissive_value):
            changes.append(
                {
                    "path": path,
                    "kind": "type",
                    "left": f"{_type_name(strict_value)}:{strict_value!r}",
                    "right": f"{_type_name(permissive_value)}:{permissive_value!r}",
                }
            )
        elif strict_value != permissive_value or (
            isinstance(strict_value, float)
            and not math.isfinite(strict_value)
        ):
            changes.append(
                {
                    "path": path,
                    "kind": "value",
                    "left": repr(strict_value),
                    "right": repr(permissive_value),
                }
            )
    return changes


def _same_value(left: Any, right: Any) -> bool:
    """Deep equality that also requires the same number types."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        if type(left) is not type(right):
            return False
        if isinstance(left, float) and not math.isfinite(left):
            return repr(left) == repr(right)
        return left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return set(left) == set(right) and all(
            _same_value(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _same_value(a, b) for a, b in zip(left, right)
        )
    return type(left) is type(right) and left == right


def _canonical_text(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=True
    )


def differential(
    data: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    integer_bits: int = DEFAULT_INTEGER_BITS,
) -> dict[str, Any]:
    """Parse one input with both readers and record exactly where they differ.

    The result names the permissive reader's value, the strict reader's value or
    code, whether the permissive reader collapsed a duplicate key, every number
    whose type or value moved, and which reader (if either) accepted the input.
    """
    raw = _as_bytes(data)
    record: dict[str, Any] = {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
    }

    strict_accepted = False
    strict_value: Any = None
    strict_record: dict[str, Any]
    try:
        strict_value = loads(
            raw,
            max_bytes=max_bytes,
            max_depth=max_depth,
            integer_bits=integer_bits,
        )
        strict_accepted = True
        strict_record = {"status": "ACCEPTED", "code": CODE_OK, "type": _type_name(strict_value)}
    except Refusal as refusal:
        strict_record = {
            "status": "REFUSED",
            "code": refusal.code,
            "message": refusal.message,
        }
    record["strict"] = strict_record

    permissive_accepted = False
    permissive_value: Any = None
    permissive_record: dict[str, Any]
    duplicates: list[str] = []
    try:
        permissive_value, duplicates = _permissive_parse(raw)
        permissive_accepted = True
        permissive_record = {
            "status": "ACCEPTED",
            "type": _type_name(permissive_value),
            "canonical": _canonical_text(permissive_value),
            "canonicalSha256": sha256_bytes(
                _canonical_text(permissive_value).encode("utf-8")
            ),
            "duplicateKeys": sorted(set(duplicates)),
        }
    except Exception as error:  # the reference reader is not the subject
        permissive_record = {
            "status": "REFUSED",
            "error": type(error).__name__,
            "message": str(error),
            "duplicateKeys": sorted(set(duplicates)),
        }
    record["permissive"] = permissive_record

    record["duplicateKeyCollapsed"] = bool(duplicates) and not strict_accepted
    record["acceptedOnlyByPermissive"] = permissive_accepted and not strict_accepted
    record["acceptedOnlyByStrict"] = strict_accepted and not permissive_accepted
    if strict_accepted and permissive_accepted:
        changes = _number_changes(strict_value, permissive_value)
    else:
        changes = []
    record["numberChanges"] = changes
    record["numberChangeOrder"] = "left=strict, right=permissive"
    if strict_accepted and permissive_accepted:
        record["agree"] = not changes and _same_value(strict_value, permissive_value)
    else:
        record["agree"] = strict_accepted == permissive_accepted
    return record


def differential_pair(
    first: bytes,
    second: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    integer_bits: int = DEFAULT_INTEGER_BITS,
) -> dict[str, Any]:
    """Two inputs, each compared with both readers, and whether they collapse.

    ``samePermissiveValue`` is the decisive field: distinct byte strings whose
    permissive canonical forms are equal have been read as one document.
    """
    left = differential(
        first, max_bytes=max_bytes, max_depth=max_depth, integer_bits=integer_bits
    )
    right = differential(
        second, max_bytes=max_bytes, max_depth=max_depth, integer_bits=integer_bits
    )
    left_value, _left_duplicates = _permissive_parse(first)
    right_value, _right_duplicates = _permissive_parse(second)
    same = _same_value(left_value, right_value)
    same_canonical = _canonical_text(left_value) == _canonical_text(right_value)
    changes = _number_changes(left_value, right_value)
    return {
        "distinctBytes": first != second,
        "firstSha256": left["sha256"],
        "secondSha256": right["sha256"],
        "samePermissiveValue": same,
        "samePermissiveCanonical": same_canonical,
        "crossNumberChanges": changes,
        "crossNumberChangeOrder": "left=first, right=second",
        "permissiveCanonical": (
            _canonical_text(left_value) if same_canonical else None
        ),
        "first": left,
        "second": right,
    }


# ---------------------------------------------------------------------------
# The bounded scan.
# ---------------------------------------------------------------------------


def tracked_files(
    glob: str = SCAN_GLOB,
    *,
    repo_root: Path | str = REPO_ROOT,
    excluded_prefixes: Iterable[str] = SCAN_EXCLUDED_PREFIXES,
) -> list[str]:
    """Tracked files whose repository-relative path matches ``glob``.

    The glob is matched with :func:`fnmatch.fnmatchcase`, so ``*`` matches across
    ``/``; ``evidence/*.json`` covers the whole subtree.  Only tracked files are
    returned, and ``excluded_prefixes`` is removed before matching so the record
    this item emits cannot be part of its own population.
    """
    root = Path(repo_root)
    result = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        _fail(
            CODE_USAGE,
            f"git ls-files failed in {root}: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}",
        )
    tracked = [
        entry.decode("utf-8")
        for entry in result.stdout.split(b"\x00")
        if entry
    ]
    excluded = tuple(excluded_prefixes)
    selected = [
        path
        for path in tracked
        if fnmatch.fnmatchcase(path, glob)
        and not any(path.startswith(prefix) for prefix in excluded)
    ]
    return sorted(selected)


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def scan(
    paths: Iterable[str],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    integer_bits: int = DEFAULT_INTEGER_BITS,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Read every ``path`` under ``repo_root`` under the same bounds.

    A path is never followed outside ``repo_root`` and a symlink is not followed
    at all.  A file larger than ``max_bytes`` is reported ``SKIPPED_SIZE`` rather
    than omitted.  Each examined file records ``STRICT_OK`` or its refusal code.
    """
    root = Path(repo_root)
    rows: list[dict[str, Any]] = []
    examined = 0
    skipped_size = 0
    skipped_other = 0
    refused = 0
    for relative in sorted(paths):
        absolute = root / relative
        row: dict[str, Any] = {"path": relative}
        if absolute.is_symlink():
            row.update({"result": "SKIPPED_SYMLINK", "code": CODE_OK})
            skipped_other += 1
            rows.append(row)
            continue
        if not _inside(root, absolute):
            row.update({"result": "SKIPPED_OUTSIDE", "code": CODE_OK})
            skipped_other += 1
            rows.append(row)
            continue
        try:
            size = os.lstat(absolute).st_size
        except OSError as error:
            row.update(
                {"result": "SKIPPED_MISSING", "code": CODE_OK, "detail": str(error)}
            )
            skipped_other += 1
            rows.append(row)
            continue
        row["bytes"] = size
        if size > max_bytes:
            row.update({"result": "SKIPPED_SIZE", "code": CODE_OK})
            skipped_size += 1
            rows.append(row)
            continue
        try:
            raw = absolute.read_bytes()
        except OSError as error:
            row.update(
                {"result": "SKIPPED_MISSING", "code": CODE_OK, "detail": str(error)}
            )
            skipped_other += 1
            rows.append(row)
            continue
        row["sha256"] = sha256_bytes(raw)
        examined += 1
        try:
            value = loads(
                raw,
                max_bytes=max_bytes,
                max_depth=max_depth,
                integer_bits=integer_bits,
            )
        except Refusal as refusal:
            refused += 1
            row.update(
                {
                    "result": refusal.code,
                    "code": refusal.code,
                    "message": refusal.message,
                }
            )
        else:
            row.update(
                {"result": "STRICT_OK", "code": CODE_OK, "type": _type_name(value)}
            )
        rows.append(row)
    return {
        "parameters": {
            "max_bytes": max_bytes,
            "max_depth": max_depth,
            "integer_bits": integer_bits,
        },
        "files": len(rows),
        "examined": examined,
        "skippedSize": skipped_size,
        "skippedOther": skipped_other,
        "refused": refused,
        "strictOk": examined - refused,
        "results": rows,
    }


# ---------------------------------------------------------------------------
# The frozen population.
# ---------------------------------------------------------------------------


def hash_file(absolute: Path) -> tuple[str, int]:
    """Return ``(sha256, bytes)`` for a file, read in bounded chunks.

    Hashing streams the bytes; it does not build a parse tree, so binding a record
    larger than ``max_bytes`` to its digest is not the denial-of-service surface
    the parser bound exists for.
    """
    digest = hashlib.sha256()
    total = 0
    with absolute.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def freeze_population(
    paths: Iterable[str],
    *,
    repo_root: Path | str = REPO_ROOT,
) -> list[dict[str, Any]]:
    """Bind every population member to its digest and size at this tree.

    The result is the explicit member list a record stores instead of a bare
    glob count: ``[{"path", "sha256", "bytes"}, ...]``, sorted by path.
    """
    root = Path(repo_root)
    members: list[dict[str, Any]] = []
    for relative in sorted(paths):
        absolute = root / relative
        if absolute.is_symlink() or not _inside(root, absolute):
            _fail(
                PH_REFUSED_POPULATION_DRIFT,
                f"{relative}: not a regular file inside {root}",
            )
        try:
            digest, size = hash_file(absolute)
        except OSError as error:
            _fail(PH_REFUSED_POPULATION_DRIFT, f"{relative}: {error}")
            raise AssertionError("unreachable")  # pragma: no cover
        members.append({"path": relative, "sha256": digest, "bytes": size})
    return members


def scan_frozen_population(
    members: Iterable[dict[str, Any]],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    integer_bits: int = DEFAULT_INTEGER_BITS,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Rebuild the per-file results from a frozen member list.

    Every member is re-hashed and compared with its frozen digest.  A member that
    is missing, is no longer a regular file inside ``repo_root``, or whose bytes
    changed is refused with ``PH_REFUSED_POPULATION_DRIFT``; that refusal is a
    record-verification result, not one of the reader's 13 input refusals.  The
    population and its count come from the frozen list only, so a file that now
    matches the glob but is not a member cannot enlarge it (see
    :func:`population_growth`).
    """
    root = Path(repo_root)
    rows: list[dict[str, Any]] = []
    examined = 0
    skipped_size = 0
    skipped_other = 0
    refused = 0
    for member in members:
        relative = member["path"]
        frozen_digest = member["sha256"]
        absolute = root / relative
        row: dict[str, Any] = {"path": relative}
        if absolute.is_symlink() or not _inside(root, absolute):
            _fail(
                PH_REFUSED_POPULATION_DRIFT,
                f"{relative}: a frozen member is no longer a regular file",
            )
        try:
            digest, size = hash_file(absolute)
        except OSError as error:
            _fail(PH_REFUSED_POPULATION_DRIFT, f"removed: {relative}: {error}")
            raise AssertionError("unreachable")  # pragma: no cover
        if digest != frozen_digest:
            _fail(
                PH_REFUSED_POPULATION_DRIFT,
                f"changed: {relative}: sha256 {digest} != frozen {frozen_digest}",
            )
        row["bytes"] = size
        row["sha256"] = digest
        if size > max_bytes:
            row.update({"result": "SKIPPED_SIZE", "code": CODE_OK})
            skipped_size += 1
            rows.append(row)
            continue
        try:
            raw = absolute.read_bytes()
        except OSError as error:
            _fail(PH_REFUSED_POPULATION_DRIFT, f"removed: {relative}: {error}")
            raise AssertionError("unreachable")  # pragma: no cover
        examined += 1
        try:
            value = loads(
                raw,
                max_bytes=max_bytes,
                max_depth=max_depth,
                integer_bits=integer_bits,
            )
        except Refusal as refusal:
            refused += 1
            row.update(
                {
                    "result": refusal.code,
                    "code": refusal.code,
                    "message": refusal.message,
                }
            )
        else:
            row.update(
                {"result": "STRICT_OK", "code": CODE_OK, "type": _type_name(value)}
            )
        rows.append(row)
    return {
        "parameters": {
            "max_bytes": max_bytes,
            "max_depth": max_depth,
            "integer_bits": integer_bits,
        },
        "files": len(rows),
        "examined": examined,
        "skippedSize": skipped_size,
        "skippedOther": skipped_other,
        "refused": refused,
        "strictOk": examined - refused,
        "results": rows,
    }


def population_growth(
    members: Iterable[dict[str, Any]],
    *,
    glob: str = SCAN_GLOB,
    repo_root: Path | str = REPO_ROOT,
    excluded_prefixes: Iterable[str] = SCAN_EXCLUDED_PREFIXES,
    live_paths: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Files that match ``glob`` now but are not in the frozen member list.

    Each is reported as ``NEW_SINCE_RECORD`` with its digest and size and is
    counted separately; the frozen population and its count are unchanged.  A
    frozen member that has left the live population is a removal and is refused
    rather than absorbed.

    ``live_paths`` overrides live-population discovery; a control uses it to
    verify a temporary mirror of the tree instead of the real one.
    """
    root = Path(repo_root)
    frozen = [member["path"] for member in members]
    frozen_set = set(frozen)
    if len(frozen_set) != len(frozen):
        _fail(PH_REFUSED_POPULATION_DRIFT, "the frozen population repeats a path")
    if live_paths is None:
        live = tracked_files(
            glob, repo_root=repo_root, excluded_prefixes=excluded_prefixes
        )
    else:
        live = sorted(live_paths)
    live_set = set(live)
    removed = [path for path in frozen if path not in live_set]
    if removed:
        shown = ", ".join(removed[:5])
        if len(removed) > 5:
            shown += f" (+{len(removed) - 5} more)"
        _fail(PH_REFUSED_POPULATION_DRIFT, f"removed since the record: {shown}")
    entries: list[dict[str, Any]] = []
    for relative in sorted(live_set - frozen_set):
        absolute = root / relative
        if absolute.is_symlink() or not _inside(root, absolute):
            _fail(
                PH_REFUSED_POPULATION_DRIFT,
                f"{relative}: not a regular file inside {root}",
            )
        try:
            digest, size = hash_file(absolute)
        except OSError as error:
            _fail(PH_REFUSED_POPULATION_DRIFT, f"{relative}: {error}")
            raise AssertionError("unreachable")  # pragma: no cover
        entries.append(
            {
                "path": relative,
                "sha256": digest,
                "bytes": size,
                "result": RESULT_NEW_SINCE_RECORD,
            }
        )
    return entries


def verify_record(
    record: dict[str, Any],
    *,
    repo_root: Path | str = REPO_ROOT,
    live_paths: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Reproduce a frozen scan record at this tree and report growth separately.

    A record that does not declare ``population.binding == "FROZEN"`` is refused:
    a live scan is a measurement of the current glob and is not comparable to a
    frozen record.  ``matchesRecord`` compares the rebuilt results and summary
    with the recorded ones; it is never compared against a live count.
    """
    population = record.get("population")
    if not isinstance(population, dict) or population.get("binding") != POPULATION_FROZEN:
        _fail(
            PH_REFUSED_POPULATION_DRIFT,
            "the record does not declare population: FROZEN, so it is not comparable",
        )
    members = population.get("members")
    if not isinstance(members, list):
        _fail(PH_REFUSED_POPULATION_DRIFT, "the frozen record has no member list")
    parameters = record.get("parameters") or {}
    rebuilt = scan_frozen_population(
        members,
        max_bytes=parameters.get("max_bytes", DEFAULT_MAX_BYTES),
        max_depth=parameters.get("max_depth", DEFAULT_MAX_DEPTH),
        integer_bits=parameters.get("integer_bits", DEFAULT_INTEGER_BITS),
        repo_root=repo_root,
    )
    growth = population_growth(
        members,
        glob=population.get("glob", SCAN_GLOB),
        repo_root=repo_root,
        excluded_prefixes=tuple(
            population.get("excludedPrefixes", SCAN_EXCLUDED_PREFIXES)
        ),
        live_paths=live_paths,
    )
    summary = {
        key: rebuilt[key]
        for key in (
            "files",
            "examined",
            "strictOk",
            "skippedSize",
            "skippedOther",
            "refused",
        )
    }
    matches = rebuilt["results"] == record.get("results") and summary == record.get(
        "summary"
    )
    return {
        "population": len(members),
        "parameters": rebuilt["parameters"],
        "summary": summary,
        "results": rebuilt["results"],
        "newSinceRecord": growth,
        "matchesRecord": matches,
    }


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def _read_path(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as error:
        _fail(CODE_USAGE, f"{path}: {error}")


def _command_parse(arguments: argparse.Namespace) -> int:
    raw = _read_path(arguments.path)
    try:
        value = loads(
            raw,
            max_bytes=arguments.max_bytes,
            max_depth=arguments.max_depth,
            integer_bits=arguments.integer_bits,
        )
    except Refusal as refusal:
        print(f"parse: code={refusal.code} {refusal.message}", file=sys.stderr)
        return 1
    print(
        f"parse: code={CODE_OK} type={_type_name(value)} bytes={len(raw)} "
        f"sha256={sha256_bytes(raw)}"
    )
    return 0


def _command_differential(arguments: argparse.Namespace) -> int:
    raw = _read_path(arguments.path)
    record = differential(
        raw,
        max_bytes=arguments.max_bytes,
        max_depth=arguments.max_depth,
        integer_bits=arguments.integer_bits,
    )
    print(json.dumps(record, indent=2, sort_keys=True))
    code = record["strict"]["code"]
    print(
        f"differential: code={code} agree={record['agree']} "
        f"sha256={record['sha256']}",
        file=sys.stderr,
    )
    return 0 if code == CODE_OK else 1


def _print_scan_refusals(rows: Iterable[dict[str, Any]]) -> None:
    for row in rows:
        if row["result"] != "STRICT_OK" and row["result"] != "SKIPPED_SIZE":
            print(
                f"scan: {row['path']} {row['result']} "
                f"{(row.get('message') or '')}".rstrip(),
                file=sys.stderr,
            )


def _command_scan(arguments: argparse.Namespace) -> int:
    if arguments.frozen:
        raw = _read_path(arguments.frozen)
        try:
            record = loads(
                raw,
                max_bytes=arguments.max_bytes,
                max_depth=arguments.max_depth,
                integer_bits=arguments.integer_bits,
            )
        except Refusal as refusal:
            print(f"scan: code={refusal.code} {refusal.message}", file=sys.stderr)
            return 1
        try:
            result = verify_record(record)
        except Refusal as refusal:
            print(f"scan: code={refusal.code} {refusal.message}", file=sys.stderr)
            return 1
        _print_scan_refusals(result["results"])
        for entry in result["newSinceRecord"]:
            print(
                f"scan: {entry['path']} {RESULT_NEW_SINCE_RECORD} "
                f"sha256={entry['sha256']} bytes={entry['bytes']}",
                file=sys.stderr,
            )
        summary = result["summary"]
        codes = [
            row["result"]
            for row in result["results"]
            if row["result"] not in ("STRICT_OK", "SKIPPED_SIZE")
        ]
        if codes:
            code = codes[0]
        elif not result["matchesRecord"]:
            code = PH_REFUSED_POPULATION_DRIFT
        else:
            code = CODE_OK
        print(
            f"scan: code={code} population={POPULATION_FROZEN} "
            f"glob={record['population']['glob']} files={result['population']} "
            f"examined={summary['examined']} strictOk={summary['strictOk']} "
            f"skippedSize={summary['skippedSize']} refused={summary['refused']} "
            f"newSinceRecord={len(result['newSinceRecord'])}"
        )
        return 0 if code == CODE_OK else 1
    if not arguments.glob:
        print(
            f"scan: code={CODE_USAGE} a glob or --frozen RECORD is required",
            file=sys.stderr,
        )
        return 2
    paths = tracked_files(arguments.glob)
    result = scan(
        paths,
        max_bytes=arguments.max_bytes,
        max_depth=arguments.max_depth,
        integer_bits=arguments.integer_bits,
    )
    _print_scan_refusals(result["results"])
    print(
        f"scan: code={CODE_OK if result['refused'] == 0 else 'PH_REFUSED_SCAN'} "
        f"population={POPULATION_LIVE} glob={arguments.glob} "
        f"files={result['files']} "
        f"examined={result['examined']} strictOk={result['strictOk']} "
        f"skippedSize={result['skippedSize']} refused={result['refused']}"
    )
    return 0 if result["refused"] == 0 else 1


def _add_bounds(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--integer-bits", type=int, default=DEFAULT_INTEGER_BITS)


class _ArgumentParser(argparse.ArgumentParser):
    """An argument parser whose usage errors still print a stable code."""

    def error(self, message: str) -> None:  # type: ignore[override]
        print(f"harden: code={CODE_USAGE} {message}", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(
        prog="harden.py", description="strict JSON for received evidence"
    )
    commands = parser.add_subparsers(dest="command")
    parse_command = commands.add_parser("parse", help="strictly parse one file")
    parse_command.add_argument("path")
    _add_bounds(parse_command)
    differential_command = commands.add_parser(
        "differential", help="compare the strict and permissive readers on one file"
    )
    differential_command.add_argument("path")
    _add_bounds(differential_command)
    scan_command = commands.add_parser(
        "scan", help="scan tracked files under a glob, or verify a frozen record"
    )
    scan_command.add_argument("glob", nargs="?")
    scan_command.add_argument(
        "--live",
        action="store_true",
        help="report the current glob as population: LIVE (not a frozen record)",
    )
    scan_command.add_argument(
        "--frozen",
        metavar="RECORD",
        help="rebuild and verify a frozen SCAN record, reporting growth separately",
    )
    _add_bounds(scan_command)
    arguments = parser.parse_args(argv)

    if arguments.command == "parse":
        return _command_parse(arguments)
    if arguments.command == "differential":
        return _command_differential(arguments)
    if arguments.command == "scan":
        return _command_scan(arguments)
    print(
        f"harden: code={CODE_USAGE} a subcommand is required "
        "(parse, differential or scan)",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as refusal:
        print(f"harden: code={refusal.code} {refusal.message}", file=sys.stderr)
        raise SystemExit(2)
