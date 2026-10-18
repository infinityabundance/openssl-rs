# Per-file obligation audit — pointer

**Purpose.** This file was the cumulative per-file obligation audit for the
`safe-c33` campaign. Its content has been split into one record per audited file
so the audit can grow without one unbounded document. The split preserved every
section, table row, residual and candidate-identity statement; only the
inter-section `---` separators and their surrounding blank padding were removed.

**Records live in [`per-file/`](per-file/).** Each record is named by replacing
`/` with `__`:

| File | Record |
|---|---|
| `src/evp/digest.rs` | [`per-file/src__evp__digest.rs.md`](per-file/src__evp__digest.rs.md) |
| `src/evp/pkey_ctx.rs` | [`per-file/src__evp__pkey_ctx.rs.md`](per-file/src__evp__pkey_ctx.rs.md) |
| `src/provider/cipher.rs` | [`per-file/src__provider__cipher.rs.md`](per-file/src__provider__cipher.rs.md) |
| `src/evp/cipher_ctx.rs` | [`per-file/src__evp__cipher_ctx.rs.md`](per-file/src__evp__cipher_ctx.rs.md) |
| `src/provider/kdf.rs` | [`per-file/src__provider__kdf.rs.md`](per-file/src__provider__kdf.rs.md) |
| `src/evp/pkey.rs` | [`per-file/src__evp__pkey.rs.md`](per-file/src__evp__pkey.rs.md) |

**Index.** The reusable template, the lifecycle/state definitions, the per-file
counts and the machine-readable pointer live in
[`PERFILE-INDEX.md`](PERFILE-INDEX.md) and
[`atlas-refresh/perfile-index.json`](atlas-refresh/perfile-index.json).

> **Non-discharge statement.** These records are file-level obligation audits,
> **not `SAFETY_DISCHARGED`**. A record enumerates and attributes a file's
> production unsafe sites; it does not establish whole-file safety, does not
> discharge its residual obligations, and is not an `INDEPENDENTLY_CHECKED`
> result. A file graduates only through the AGENTS.md §7 dependency-closure and
> independent-evidence gates. Campaign progress is **6 of 761 PARTIAL files
> audited**; no file in this set has graduated.

The old cumulative content was split without modification. To compare against
the pre-split document, use the campaign commit that introduced this pointer; the
records are the authoritative copies of each section.
