#!/usr/bin/env python3
"""openssl-rs -- a lossless, deterministic columnar codec for the Phase-25 evidence.

Why this exists
---------------
The Phase-25 measurement artefacts repeat the same strings per record: every site
carries a file path, a module, a kind, a method, a compiler clause and a commit, and
every context carries a file, a kind and a contract. Written as one JSON object per
record, `source-census.json` is 120 MB, the seven Phase-25 artefacts are 267 MB, and
GitHub's pre-receive hook -- which rejects any file over 100 MB -- refuses the commit
that lands them. The bytes are almost entirely repetition, so the fix is an encoding
change, never an information change.

The scheme
----------
`encode` rewrites a JSON value into `ms-columnar-v1`:

  * a list of records becomes a **columnar** block `{"e": "cols", ...}`: the field
    names once (`columns`), each repeated string once (`tables`), and each record as a
    short array of indices/integers (`rows`);
  * a dict whose values are all records becomes the same block with the dict's keys
    carried in an extra key column, so the keys are stored once and the dict is rebuilt
    on decode;
  * strings that name a census site or context id are replaced by a small integer
    reference into the census's own ordered id lists (`refcols`), so the id is stored
    once in the census and referenced everywhere else;
  * a list of strings is stored as one pool plus per-cell index lists.

`decode` inverts all of it exactly. `decode(encode(x)) == x` for every JSON value in
the artefacts, so nothing -- not a count, not an id, not an ordering -- is lost; only
the spelling on disk changes. The scheme is named by `body.encoding`, so a reader knows
how to decode without reading this module.

This module is pure: it reads no file and runs no tool. It is imported by the census
and every derived plane, and by their courts, so one implementation of the scheme
serves every reader.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# The scheme name a body carries in `body.encoding`. A reader that sees an unknown
# encoding must refuse rather than guess.
ENCODING = "ms-columnar-v1"

# The field name that carries a record's map key inside a `cols` block's rows. A NUL
# prefix cannot collide with a real record field, and it sorts before every printable
# column name.
KEY_COLUMN = "\u0000key"

# The sentinel for a record that does not carry a column another record in the same list
# does. It is a JSON object so it survives inline storage, and decode drops the key rather
# than emitting it. No real cell in the Phase-25 evidence is this object.
_MISSING = {"$m": 1}


@dataclass(frozen=True)
class Refs:
    """The ordered census id lists an encoded body references by index.

    `site_ids` and `context_ids` are the census's own records in census order; an
    encoded string that names one of them is stored as its index into the matching
    list. Both sides (writer and reader) build this from the same committed census, so
    the indices mean the same thing to both.
    """

    site_ids: tuple[str, ...] = ()
    context_ids: tuple[str, ...] = ()

    def site_index(self) -> dict[str, int]:
        return {s: i for i, s in enumerate(self.site_ids)}

    def context_index(self) -> dict[str, int]:
        return {c: i for i, c in enumerate(self.context_ids)}


def refs_from_census(view: dict) -> Refs:
    """The ordered id lists of a *decoded* census view."""
    return Refs(
        site_ids=tuple(s["site_id"] for s in view.get("sites") or []),
        context_ids=tuple(c["context_id"] for c in view.get("unsafe_contexts") or []),
    )


def encode_body(view: dict, refs: Refs | None = None) -> dict:
    """The on-disk form of an artefact body: `encode` plus the scheme marker."""
    encoded = encode(view, refs)
    if isinstance(encoded, dict):
        encoded = dict(encoded)
        encoded["encoding"] = ENCODING
    return encoded


def decode_body(stored: dict, refs: Refs | None = None) -> dict:
    """Invert `encode_body`. An unencoded (view) body is returned unchanged, so a caller
    may pass either form -- a fresh measurement's view or a committed artefact's blob --
    to the same function."""
    if not isinstance(stored, dict) or stored.get("encoding") != ENCODING:
        return stored
    stripped = {k: v for k, v in stored.items() if k != "encoding"}
    return decode(stripped, refs)


# --------------------------------------------------------------------------------------------
# encoding
# --------------------------------------------------------------------------------------------

def _scalar_ref(value, refs, site_idx, ctx_idx):
    """A string that names a census id becomes a `{"$s": i}` / `{"$c": i}` reference."""
    if isinstance(value, str):
        i = site_idx.get(value)
        if i is not None:
            return {"$s": i}
        i = ctx_idx.get(value)
        if i is not None:
            return {"$c": i}
    return value


def encode(node, refs: Refs | None = None):
    """Rewrite `node` into its `ms-columnar-v1` form (see the module docstring)."""
    site_idx = refs.site_index() if refs else {}
    ctx_idx = refs.context_index() if refs else {}

    def rec(value):
        if isinstance(value, dict):
            vals = list(value.values())
            if value and all(isinstance(v, dict) for v in vals):
                records = []
                for k in sorted(value.keys(), key=str):
                    r = dict(value[k])
                    r[KEY_COLUMN] = k
                    records.append(r)
                return _encode_records(records, rec, site_idx, ctx_idx, kind="map")
            return {k: rec(v) for k, v in value.items()}
        if isinstance(value, list):
            if value and all(isinstance(v, dict) for v in value):
                return _encode_records(value, rec, site_idx, ctx_idx, kind="list")
            return [rec(v) for v in value]
        return _scalar_ref(value, refs, site_idx, ctx_idx)

    return rec(node)


def _encode_records(records, rec, site_idx, ctx_idx, kind):
    columns = sorted(set().union(*(r.keys() for r in records)))
    tables: dict[str, object] = {}
    refcols: dict[str, str] = {}
    consts: dict[str, object] = {}
    varying: list[str] = []
    col_values: dict[str, list] = {}
    for col in columns:
        cells = [rec(r[col]) if col in r else _MISSING for r in records]
        first = cells[0]
        if first is not _MISSING and all(c == first for c in cells):
            # A constant column (the same compiler clause, commit or evidence on every row) is stored
            # once, not as an index on every row. Decode restores it to every record.
            consts[col] = first
            continue
        table, encoded, reftype = _encode_column(cells, site_idx, ctx_idx)
        if table is not None:
            tables[col] = table
        if reftype is not None:
            refcols[col] = reftype
        col_values[col] = encoded
        varying.append(col)
    rows = [[col_values[c][i] for c in varying] for i in range(len(records))]
    out: dict = {"e": "cols", "kind": kind, "columns": varying, "rows": rows}
    if consts:
        out["consts"] = consts
    if tables:
        out["tables"] = tables
    if refcols:
        out["refcols"] = refcols
    return out


def _encode_column(cells, site_idx, ctx_idx):
    """Encode one column's cells. Returns `(table, encoded_cells, reftype)`.

    At most one of `table`/`reftype` is set; when both are `None` the cells are stored
    inline (an already-encoded scalar, nested block or mixed value). A cell absent from a
    record is `_MISSING`: it becomes index `-1` in a table/reference column, and is
    dropped on decode.
    """
    present = [c for c in cells if c is not _MISSING]
    if not present:
        return None, cells, None

    non_null = [c for c in present if c is not None]
    if all(isinstance(c, str) for c in non_null):
        distinct = sorted(set(non_null))
        idx = {v: i for i, v in enumerate(distinct)}
        n_missing = len(cells) - len(present)
        table_cost = _jlen(distinct) + len(distinct)
        inline_cost = sum(_jlen(c) for c in cells)
        if table_cost + 2 * len(cells) + n_missing < inline_cost:
            out = []
            for c in cells:
                if c is _MISSING:
                    out.append(-1)
                elif c is None:
                    out.append(-2)
                else:
                    out.append(idx[c])
            return distinct, out, None
        return None, cells, None

    if all(isinstance(c, bool) for c in present):
        return None, [(-1 if c is _MISSING else (1 if c else 0)) for c in cells], "bool"

    if all(isinstance(c, dict) and set(c) == {"$s"} for c in present):
        return None, [(-1 if c is _MISSING else c["$s"]) for c in cells], "site"
    if all(isinstance(c, dict) and set(c) == {"$c"} for c in present):
        return None, [(-1 if c is _MISSING else c["$c"]) for c in cells], "context"

    if all(isinstance(c, list) for c in present):
        if all(all(isinstance(x, dict) and set(x) == {"$s"} for x in c) for c in present):
            return None, [(-1 if c is _MISSING else [x["$s"] for x in c]) for c in cells], \
                "site-list"
        if all(all(isinstance(x, dict) and set(x) == {"$c"} for x in c) for c in present):
            return None, [(-1 if c is _MISSING else [x["$c"] for x in c]) for c in cells], \
                "context-list"
        if all(all(isinstance(x, str) for x in c) for c in present):
            pool = sorted({x for c in present for x in c})
            pidx = {x: i for i, x in enumerate(pool)}
            pairs = [tuple(pidx[x] for x in c) for c in present]
            distinct = sorted(set(pairs))
            didx = {p: i for i, p in enumerate(distinct)}
            table_cost = (_jlen(pool) + len(pool)
                          + _jlen([list(p) for p in distinct]) + len(distinct))
            inline_cost = sum(_jlen(c) for c in cells) + _jlen(pool) + len(pool)
            if table_cost + 2 * len(cells) < inline_cost:
                return ({"p": pool, "c": [list(p) for p in distinct]},
                        [(-1 if c is _MISSING else didx[p]) for c, p in _zip_present(cells, pairs)],
                        None)
    return None, cells, None


def _zip_present(cells, pairs):
    it = iter(pairs)
    for c in cells:
        if c is _MISSING:
            yield c, None
        else:
            yield c, next(it)


def _jlen(value) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False))


# --------------------------------------------------------------------------------------------
# decoding
# --------------------------------------------------------------------------------------------

def decode(node, refs: Refs | None = None):
    """Invert `encode`. `refs` must be the same census id lists the encoder used."""
    site_list = list(refs.site_ids) if refs else []
    ctx_list = list(refs.context_ids) if refs else []

    def rec(value):
        if isinstance(value, dict):
            if set(value) == {"$s"}:
                return site_list[value["$s"]]
            if set(value) == {"$c"}:
                return ctx_list[value["$c"]]
            if value.get("e") == "cols":
                return _decode_records(value, rec, site_list, ctx_list)
            return {k: rec(v) for k, v in value.items()}
        if isinstance(value, list):
            return [rec(v) for v in value]
        return value

    return rec(node)


def _decode_records(block, rec, site_list, ctx_list):
    columns = block["columns"]
    rows = block["rows"]
    tables = block.get("tables", {})
    refcols = block.get("refcols", {})

    def cell(col, value):
        if col in refcols:
            if value == -1:
                return _MISSING
            kind = refcols[col]
            if kind == "bool":
                return bool(value)
            if kind == "site":
                return site_list[value]
            if kind == "context":
                return ctx_list[value]
            if kind == "site-list":
                return [site_list[i] for i in value]
            if kind == "context-list":
                return [ctx_list[i] for i in value]
            raise ValueError(f"unknown ref kind {kind!r}")
        if col in tables:
            if value == -2:
                return None
            if value == -1:
                return _MISSING
            table = tables[col]
            if isinstance(table, dict):
                pool, cells = table["p"], table["c"]
                return [pool[j] for j in cells[value]]
            return table[value]
        return rec(value)

    records = []
    consts = block.get("consts", {})
    for row in rows:
        record = {c: rec(v) for c, v in consts.items()}
        for c, v in zip(columns, row):
            decoded = cell(c, v)
            if decoded == _MISSING:
                continue
            record[c] = decoded
        records.append(record)

    if block.get("kind") == "map":
        out = {}
        for r in records:
            key = r.pop(KEY_COLUMN)
            out[key] = r
        return out
    return records
