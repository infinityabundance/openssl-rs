//! Phase 14.3 — `ssl/ssl_ciph.c`: the cipher and ciphersuite tables and their readers.
//!
//! `docs/PHASE-14-SUBPHASES.md` gives 14.3 `ssl_ciph.c` (25 open rows) and `ssl_conf.c` (11). This
//! module lands the first unit: the three built-in ciphersuite tables (`ssl/s3_lib.c`'s
//! `tls13_ciphers`, `ssl3_ciphers` and `ssl3_scsvs`, in the generated `ssl_ciph_table.rs`), the
//! four mask->NID lookup tables, the alias table, the `SSL_CIPHER_*` readers, the `OSSL_default_*`
//! lists, the `SSL_CTX_set_ciphersuites`/`SSL_set_ciphersuites` setters, the `SSL_COMP_*`
//! compression surface, and the rule engine `ssl_create_cipher_list` that `ssl_lib.rs`'s
//! `SSL_CTX_set_cipher_list`/`SSL_set_cipher_list` drive.
//!
//! The authority here is `ssl/ssl_ciph.c` (the readers, the rule engine, the aliases and the two
//! `OSSL_default_*` lists), plus `ssl/s3_lib.c`'s three tables and its four `ssl3_get_cipher*`
//! lookups. `ssl_lib.c`'s five cipher-list accessors are landed beside this module in
//! `src/ssl/ssl_lib.rs`, because that is the unit that defines them; `docs/PHASE-14-SUBPHASES.md`
//! already names them 14.3's ("the cipher tables and parser, 14.3") and the ledger's module label
//! is that unit.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The `SSL_CTX` records the disabled masks, not the fetched method pointers.** The authority's
//!   `ssl_load_ciphers` (`ssl_ciph.c:326-446`) stores each fetched `EVP_CIPHER`/`EVP_MD` in
//!   `ctx->ssl_cipher_methods[]`/`ssl_digest_methods[]` and reads them back in the record layer.
//!   Those arrays are 14.4's to consume; this module performs the same fetches to compute the four
//!   `disabled_*_mask` words (so the default cipher list the parser builds matches the authority's)
//!   and frees the fetched objects, rather than retaining them.
//! * **The `decrypt_only` property check is not reproduced.** `ssl_evp_cipher_fetch` disables a
//!   fetched cipher that reports `OSSL_CIPHER_PARAM_DECRYPT_ONLY`; the crate's provider does not
//!   publish that parameter, so a cipher the authority would disable on it stays enabled here. No
//!   default-provider algorithm carries the flag, so the observable default list is unchanged.
//! * **`ERR` raises are not performed.** The candidate DSO duplicates the crate's error state
//!   (`src/ssl/mod.rs`), so a libssl raise is invisible to a consumer's `ERR_peek_error` anyway;
//!   the return values the authority's raises accompany are reproduced, the raises are not.
//! * **The GOST ciphersuites are present but disabled, as in the authority.** The table is
//!   transcribed with the authority's `OPENSSL_NO_GOST`-undefined build, and `ssl_load_ciphers`
//!   disables their `SSL_kGOST`/`SSL_aGOST12` masks because no provider publishes GOST, exactly as
//!   the authority's default build does.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::context::OSSL_LIB_CTX_get_data;
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EvpCipher};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EvpMd};
use crate::evp::exchange::{EVP_KEYEXCH_fetch, EVP_KEYEXCH_free};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::signature::{EVP_SIGNATURE_fetch, EVP_SIGNATURE_free};
use crate::ffi::guard_ffi;
use crate::runtime::bio::comp::{COMP_get_name, COMP_get_type, CompMethod};
use crate::runtime::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::{NID_undef, OBJ_nid2sn};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_push, OPENSSL_sk_set_cmp_func, OPENSSL_sk_sort, OPENSSL_sk_unshift,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_ciph_table::SslCipher;
use crate::ssl::ssl_lib::{Cert, SSL_get_ciphers, Ssl, SslCtx};

/// `OSSL_LIB_CTX_COMP_METHODS` — `ssl_ciph.c:1986` reads the compression-method slot at index 21.
const OSSL_LIB_CTX_COMP_METHODS: c_int = 21;

// The rule verbs `ssl_cipher_apply_rule` switches on (`ssl_ciph.c:144-153`).
const CIPHER_ADD: c_int = 1;
const CIPHER_KILL: c_int = 2;
const CIPHER_DEL: c_int = 3;
const CIPHER_ORD: c_int = 4;
const CIPHER_SPECIAL: c_int = 5;
const CIPHER_BUMP: c_int = 6;

/// `SSL3_NUM_CIPHERS` — `s3_lib.c:28`.
fn ssl3_num_ciphers() -> c_int {
    t::SSL3_CIPHERS.len() as c_int
}

/// `ssl_protocol_to_string` — `ssl_lib.c:5038-5064`.
pub(crate) fn ssl_protocol_to_string(version: c_int) -> *const c_char {
    let s: &[u8] = match version as u64 {
        t::TLS1_3_VERSION => b"TLSv1.3\0",
        t::TLS1_2_VERSION => b"TLSv1.2\0",
        t::TLS1_1_VERSION => b"TLSv1.1\0",
        t::TLS1_VERSION => b"TLSv1\0",
        t::SSL3_VERSION => b"SSLv3\0",
        t::DTLS1_BAD_VER => b"DTLSv0.9\0",
        t::DTLS1_VERSION => b"DTLSv1\0",
        t::DTLS1_2_VERSION => b"DTLSv1.2\0",
        _ => b"unknown\0",
    };
    s.as_ptr().cast::<c_char>()
}

/// `ssl3_get_cipher` — `s3_lib.c:3781-3787`. The reversal is the authority's.
///
/// # Safety
/// No precondition; the returned pointer is into a process-lifetime static.
unsafe fn ssl3_get_cipher(u: c_uint) -> *const SslCipher {
    let n = t::SSL3_CIPHERS.len();
    if (u as usize) < n {
        &t::SSL3_CIPHERS[n - 1 - u as usize]
    } else {
        ptr::null()
    }
}

/// `ssl3_get_cipher_by_id` — `s3_lib.c:4715-4728`, as a linear search over the three tables (the
/// authority binary-searches sorted copies; the answer is the same).
///
/// # Safety
/// No precondition; the returned pointer is into a process-lifetime static.
pub(crate) unsafe fn ssl3_get_cipher_by_id(id: u32) -> *const SslCipher {
    for tbl in [
        &t::TLS13_CIPHERS[..],
        &t::SSL3_CIPHERS[..],
        &t::SSL3_SCSVS[..],
    ] {
        for c in tbl {
            if c.id == id {
                return c;
            }
        }
    }
    ptr::null()
}

/// `ssl3_get_cipher_by_char` — `s3_lib.c:4753-4758`.
///
/// # Safety
/// `p` must point at two readable bytes.
pub(crate) unsafe fn ssl3_get_cipher_by_char(p: *const u8) -> *const SslCipher {
    // SAFETY: the caller guarantees two readable bytes.
    let id = (t::SSL3_CK_CIPHERSUITE_FLAG as u32)
        | ((unsafe { *p } as u32) << 8)
        | (unsafe { *p.add(1) } as u32);
    // SAFETY: no precondition on the lookup.
    unsafe { ssl3_get_cipher_by_id(id) }
}

/// `ssl3_get_cipher_by_std_name` — `s3_lib.c:4730-4747`.
///
/// # Safety
/// `stdname` must be a NUL-terminated string.
unsafe fn ssl3_get_cipher_by_std_name(stdname: *const c_char) -> *const SslCipher {
    if stdname.is_null() {
        return ptr::null();
    }
    // SAFETY: `stdname` is NUL-terminated per the caller's contract.
    let name = unsafe { core::ffi::CStr::from_ptr(stdname) }.to_bytes();
    for tbl in [
        &t::TLS13_CIPHERS[..],
        &t::SSL3_CIPHERS[..],
        &t::SSL3_SCSVS[..],
    ] {
        for c in tbl {
            if c.stdname.len() > 1 && &c.stdname[..c.stdname.len() - 1] == name {
                return c;
            }
        }
    }
    ptr::null()
}

/// The C string a table row's name slice holds (`&[u8]` with its terminator).
fn row_str(bytes: &[u8]) -> *const c_char {
    bytes.as_ptr().cast::<c_char>()
}

/// True when `bytes` (terminator included) equals the `buflen`-byte buffer `buf` exactly.
fn name_matches(bytes: &[u8], buf: &[u8], buflen: usize) -> bool {
    bytes.len() == buflen + 1 && bytes[buflen] == 0 && &bytes[..buflen] == buf
}

// ---------------------------------------------------------------------------------------------
// The rule engine: `ssl_cipher_collect_ciphers`, `ssl_cipher_collect_aliases`,
// `ssl_cipher_apply_rule`, `ssl_cipher_strength_sort`, `ssl_cipher_process_rulestr`.
// ---------------------------------------------------------------------------------------------

/// `CIPHER_ORDER` (`ssl_ciph.c:155-160`) as an index list. `order` is the linked list's head-to-tail
/// sequence of positions into `co`; `active` is the per-position flag.
struct CipherOrder {
    co: Vec<*const SslCipher>,
    order: Vec<usize>,
    active: Vec<bool>,
}

impl CipherOrder {
    fn move_to_end(&mut self, id: usize) {
        if let Some(pos) = self.order.iter().position(|&x| x == id) {
            self.order.remove(pos);
            self.order.push(id);
        }
    }

    fn move_to_front(&mut self, id: usize) {
        if let Some(pos) = self.order.iter().position(|&x| x == id) {
            self.order.remove(pos);
            self.order.insert(0, id);
        }
    }

    fn remove(&mut self, id: usize) {
        if let Some(pos) = self.order.iter().position(|&x| x == id) {
            self.order.remove(pos);
        }
    }

    /// `ssl_cipher_apply_rule` — `ssl_ciph.c:777-919`.
    #[allow(clippy::too_many_arguments)] // the authority's positional signature
    fn apply_rule(
        &mut self,
        cipher_id: u32,
        alg_mkey: u32,
        alg_auth: u32,
        alg_enc: u32,
        alg_mac: u32,
        min_tls: c_int,
        algo_strength: u32,
        rule: c_int,
        strength_bits: i32,
    ) {
        let reverse = rule == CIPHER_DEL || rule == CIPHER_BUMP;
        let snapshot: Vec<usize> = if reverse {
            self.order.iter().rev().copied().collect()
        } else {
            self.order.clone()
        };
        for id in snapshot {
            let cp = self.co[id];
            // SAFETY: every `co` pointer is a process-lifetime table row.
            let cp = unsafe { &*cp };
            if strength_bits >= 0 {
                if strength_bits != cp.strength_bits {
                    continue;
                }
            } else {
                if cipher_id != 0 && cipher_id != cp.id {
                    continue;
                }
                if alg_mkey != 0 && (alg_mkey & cp.algorithm_mkey) == 0 {
                    continue;
                }
                if alg_auth != 0 && (alg_auth & cp.algorithm_auth) == 0 {
                    continue;
                }
                if alg_enc != 0 && (alg_enc & cp.algorithm_enc) == 0 {
                    continue;
                }
                if alg_mac != 0 && (alg_mac & cp.algorithm_mac) == 0 {
                    continue;
                }
                if min_tls != 0 && min_tls != cp.min_tls {
                    continue;
                }
                let strong = t::SSL_STRONG_MASK as u32;
                if (algo_strength & strong) != 0 && (algo_strength & strong & cp.algo_strength) == 0
                {
                    continue;
                }
                let default = t::SSL_DEFAULT_MASK as u32;
                if (algo_strength & default) != 0
                    && (algo_strength & default & cp.algo_strength) == 0
                {
                    continue;
                }
            }
            match rule {
                CIPHER_ADD if !self.active[id] => {
                    self.move_to_end(id);
                    self.active[id] = true;
                }
                CIPHER_ORD if self.active[id] => {
                    self.move_to_end(id);
                }
                CIPHER_DEL if self.active[id] => {
                    self.move_to_front(id);
                    self.active[id] = false;
                }
                CIPHER_BUMP if self.active[id] => {
                    self.move_to_front(id);
                }
                CIPHER_KILL => {
                    self.remove(id);
                    self.active[id] = false;
                }
                _ => {}
            }
        }
    }
}

/// `ssl_cipher_collect_ciphers` — `ssl_ciph.c:650-713`.
///
/// # Safety
/// `ctx` and `method` must be live.
unsafe fn ssl_cipher_collect_ciphers(
    method: *const crate::ssl::ssl_lib::SslMethod,
    ctx: *const SslCtx,
) -> CipherOrder {
    let mut co: Vec<*const SslCipher> = Vec::new();
    // SAFETY: `ctx`/`method` are live per the caller's contract.
    let (dmkey, dauth, denc, dmac, dtls) = unsafe {
        (
            (*ctx).disabled_mkey_mask,
            (*ctx).disabled_auth_mask,
            (*ctx).disabled_enc_mask,
            (*ctx).disabled_mac_mask,
            ((*method).enc_flags as u64 & t::SSL_ENC_FLAG_DTLS) != 0,
        )
    };
    let n = ssl3_num_ciphers();
    for i in 0..n {
        // SAFETY: `i` is in range for the reversal.
        let c = unsafe { ssl3_get_cipher(i as c_uint) };
        if c.is_null() {
            continue;
        }
        // SAFETY: `c` is a process-lifetime table row.
        let c = unsafe { &*c };
        if c.valid == 0 {
            continue;
        }
        if (c.algorithm_mkey & dmkey) != 0
            || (c.algorithm_auth & dauth) != 0
            || (c.algorithm_enc & denc) != 0
            || (c.algorithm_mac & dmac) != 0
        {
            continue;
        }
        if !dtls && c.min_tls == 0 {
            continue;
        }
        if dtls && c.min_dtls == 0 {
            continue;
        }
        co.push(c);
    }
    let len = co.len();
    CipherOrder {
        co,
        order: (0..len).collect(),
        active: vec![false; len],
    }
}

/// `ssl_cipher_collect_aliases` — `ssl_ciph.c:715-775`, returning the searchable list.
///
/// # Safety
/// `ctx` must be live.
unsafe fn ssl_cipher_collect_aliases(
    order: &CipherOrder,
    ctx: *const SslCtx,
) -> Vec<*const SslCipher> {
    let mut ca: Vec<*const SslCipher> = Vec::new();
    for &id in &order.order {
        ca.push(order.co[id]);
    }
    // SAFETY: `ctx` is live per the caller's contract.
    let (dmkey, dauth, denc, dmac) = unsafe {
        (
            (*ctx).disabled_mkey_mask,
            (*ctx).disabled_auth_mask,
            (*ctx).disabled_enc_mask,
            (*ctx).disabled_mac_mask,
        )
    };
    for a in t::CIPHER_ALIASES.iter() {
        if a.algorithm_mkey != 0 && (a.algorithm_mkey & !dmkey) == 0 {
            continue;
        }
        if a.algorithm_auth != 0 && (a.algorithm_auth & !dauth) == 0 {
            continue;
        }
        if a.algorithm_enc != 0 && (a.algorithm_enc & !denc) == 0 {
            continue;
        }
        if a.algorithm_mac != 0 && (a.algorithm_mac & !dmac) == 0 {
            continue;
        }
        ca.push(a);
    }
    ca
}

/// `ssl_cipher_strength_sort` — `ssl_ciph.c:921-965`.
fn ssl_cipher_strength_sort(order: &mut CipherOrder) {
    let mut max_strength_bits: i32 = 0;
    for &id in &order.order {
        // SAFETY: every `co` pointer is a process-lifetime table row.
        let sb = unsafe { (*order.co[id]).strength_bits };
        if order.active[id] && sb > max_strength_bits {
            max_strength_bits = sb;
        }
    }
    let mut number_uses = vec![0i32; (max_strength_bits + 1) as usize];
    for &id in &order.order {
        if order.active[id] {
            // SAFETY: every `co` pointer is a process-lifetime table row.
            let sb = unsafe { (*order.co[id]).strength_bits };
            number_uses[sb as usize] += 1;
        }
    }
    for i in (0..=max_strength_bits).rev() {
        if number_uses[i as usize] > 0 {
            order.apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ORD, i);
        }
    }
}

/// `ITEM_SEP` — `ssl_ciph.c:613-614`.
fn item_sep(ch: u8) -> bool {
    matches!(ch, b':' | b' ' | b';' | b',')
}

/// True for the bytes the token scanner accepts (`ssl_ciph.c:1019`).
fn token_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_' | b'.' | b'=')
}

/// `ssl_cipher_process_rulestr` — `ssl_ciph.c:967-1223`.
///
/// # Safety
/// `cert` must be NULL or live; its `sec_level` is written for an `@SECLEVEL=` token.
unsafe fn ssl_cipher_process_rulestr(
    rule: &[u8],
    order: &mut CipherOrder,
    ca_list: &[*const SslCipher],
    cert: *mut Cert,
) -> bool {
    let mut retval = true;
    let mut l = 0usize;
    loop {
        let ch = *rule.get(l).unwrap_or(&0);
        if ch == 0 {
            break;
        }
        let rule_kind = match ch {
            b'-' => {
                l += 1;
                CIPHER_DEL
            }
            b'+' => {
                l += 1;
                CIPHER_ORD
            }
            b'!' => {
                l += 1;
                CIPHER_KILL
            }
            b'@' => {
                l += 1;
                CIPHER_SPECIAL
            }
            _ => CIPHER_ADD,
        };

        if item_sep(ch) {
            l += 1;
            continue;
        }

        let mut alg_mkey: u32 = 0;
        let mut alg_auth: u32 = 0;
        let mut alg_enc: u32 = 0;
        let mut alg_mac: u32 = 0;
        let mut min_tls: c_int = 0;
        let mut algo_strength: u32 = 0;
        let mut cipher_id: u32 = 0;
        let mut found: bool;
        let mut buflen: usize;
        let mut buf_start: usize;

        loop {
            let mut ch = *rule.get(l).unwrap_or(&0);
            buf_start = l;
            buflen = 0;
            while token_char(ch) {
                l += 1;
                buflen += 1;
                ch = *rule.get(l).unwrap_or(&0);
            }
            if buflen == 0 {
                return false; // SSL_R_INVALID_COMMAND
            }
            if rule_kind == CIPHER_SPECIAL {
                found = false;
                break;
            }
            let multi = if ch == b'+' {
                l += 1;
                true
            } else {
                false
            };

            let buf = &rule[buf_start..buf_start + buflen];
            let mut j = 0usize;
            found = false;
            cipher_id = 0;
            while j < ca_list.len() {
                let cp = ca_list[j];
                if cp.is_null() {
                    break;
                }
                // SAFETY: `cp` is a live table row.
                let cp = unsafe { &*cp };
                if name_matches(cp.name, buf, buflen)
                    || (cp.stdname.len() > 1 && name_matches(cp.stdname, buf, buflen))
                {
                    found = true;
                    break;
                }
                j += 1;
            }
            if !found {
                break;
            }
            // SAFETY: `ca_list[j]` is live.
            let cp = unsafe { &*ca_list[j] };

            if cp.algorithm_mkey != 0 {
                if alg_mkey != 0 {
                    alg_mkey &= cp.algorithm_mkey;
                    if alg_mkey == 0 {
                        found = false;
                        break;
                    }
                } else {
                    alg_mkey = cp.algorithm_mkey;
                }
            }
            if cp.algorithm_auth != 0 {
                if alg_auth != 0 {
                    alg_auth &= cp.algorithm_auth;
                    if alg_auth == 0 {
                        found = false;
                        break;
                    }
                } else {
                    alg_auth = cp.algorithm_auth;
                }
            }
            if cp.algorithm_enc != 0 {
                if alg_enc != 0 {
                    alg_enc &= cp.algorithm_enc;
                    if alg_enc == 0 {
                        found = false;
                        break;
                    }
                } else {
                    alg_enc = cp.algorithm_enc;
                }
            }
            if cp.algorithm_mac != 0 {
                if alg_mac != 0 {
                    alg_mac &= cp.algorithm_mac;
                    if alg_mac == 0 {
                        found = false;
                        break;
                    }
                } else {
                    alg_mac = cp.algorithm_mac;
                }
            }
            let strong = t::SSL_STRONG_MASK as u32;
            if (cp.algo_strength & strong) != 0 {
                if (algo_strength & strong) != 0 {
                    algo_strength &= (cp.algo_strength & strong) | !strong;
                    if (algo_strength & strong) == 0 {
                        found = false;
                        break;
                    }
                } else {
                    algo_strength = cp.algo_strength & strong;
                }
            }
            let default = t::SSL_DEFAULT_MASK as u32;
            if (cp.algo_strength & default) != 0 {
                if (algo_strength & default) != 0 {
                    algo_strength &= (cp.algo_strength & default) | !default;
                    if (algo_strength & default) == 0 {
                        found = false;
                        break;
                    }
                } else {
                    algo_strength |= cp.algo_strength & default;
                }
            }
            if cp.valid != 0 {
                cipher_id = cp.id;
            } else if cp.min_tls != 0 {
                if min_tls != 0 && min_tls != cp.min_tls {
                    found = false;
                    break;
                } else {
                    min_tls = cp.min_tls;
                }
            }
            if !multi {
                break;
            }
        }

        if rule_kind == CIPHER_SPECIAL {
            let buf = &rule[buf_start..buf_start + buflen];
            let mut ok = false;
            if buflen == 8 && buf.starts_with(b"STRENGTH") {
                ssl_cipher_strength_sort(order);
                ok = true;
            } else if buflen == 10 && buf.starts_with(b"SECLEVEL=") {
                let level = (buf[9] - b'0') as c_int;
                if !(0..=5).contains(&level) {
                    ok = false;
                } else if !cert.is_null() {
                    // SAFETY: `cert` is live per the caller's contract.
                    unsafe { (*cert).sec_level = level };
                    ok = true;
                }
            }
            if !ok {
                retval = false;
            }
            while *rule.get(l).unwrap_or(&0) != 0 && !item_sep(*rule.get(l).unwrap_or(&0)) {
                l += 1;
            }
        } else if found {
            order.apply_rule(
                cipher_id,
                alg_mkey,
                alg_auth,
                alg_enc,
                alg_mac,
                min_tls,
                algo_strength,
                rule_kind,
                -1,
            );
        } else {
            while *rule.get(l).unwrap_or(&0) != 0 && !item_sep(*rule.get(l).unwrap_or(&0)) {
                l += 1;
            }
        }
        if *rule.get(l).unwrap_or(&0) == 0 {
            break;
        }
    }
    retval
}

/// `check_suiteb_cipher_list` — `ssl_ciph.c:1225-1271`, returning the (possibly replaced) rule.
///
/// # Safety
/// `method` and `cert` must be live.
unsafe fn check_suiteb_cipher_list(
    method: *const crate::ssl::ssl_lib::SslMethod,
    cert: *mut Cert,
    rule_str: &[u8],
) -> Option<Vec<u8>> {
    let mut suiteb_flags: u64 = 0;
    let mut suiteb_comb2 = false;
    if rule_str.starts_with(b"SUITEB128ONLY") {
        suiteb_flags = t::SSL_CERT_FLAG_SUITEB_128_LOS_ONLY;
    } else if rule_str.starts_with(b"SUITEB128C2") {
        suiteb_comb2 = true;
        suiteb_flags = t::SSL_CERT_FLAG_SUITEB_128_LOS;
    } else if rule_str.starts_with(b"SUITEB128") {
        suiteb_flags = t::SSL_CERT_FLAG_SUITEB_128_LOS;
    } else if rule_str.starts_with(b"SUITEB192") {
        suiteb_flags = t::SSL_CERT_FLAG_SUITEB_192_LOS;
    }
    // SAFETY: `cert`/`method` are live per the caller's contract.
    unsafe {
        let c = &mut *cert;
        if suiteb_flags != 0 {
            c.cert_flags &= !(t::SSL_CERT_FLAG_SUITEB_128_LOS as i64);
            c.cert_flags |= suiteb_flags as i64;
        } else {
            suiteb_flags = (c.cert_flags as u64) & t::SSL_CERT_FLAG_SUITEB_128_LOS;
        }
        if suiteb_flags == 0 {
            return Some(rule_str.to_vec());
        }
        if ((*method).enc_flags as u64 & t::SSL_ENC_FLAG_TLS1_2_CIPHERS) == 0 {
            return None;
        }
        let replacement: &[u8] = match suiteb_flags {
            x if x == t::SSL_CERT_FLAG_SUITEB_128_LOS => {
                if suiteb_comb2 {
                    b"ECDHE-ECDSA-AES256-GCM-SHA384"
                } else {
                    b"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"
                }
            }
            x if x == t::SSL_CERT_FLAG_SUITEB_128_LOS_ONLY => b"ECDHE-ECDSA-AES128-GCM-SHA256",
            x if x == t::SSL_CERT_FLAG_SUITEB_192_LOS => b"ECDHE-ECDSA-AES256-GCM-SHA384",
            _ => rule_str,
        };
        Some(replacement.to_vec())
    }
}

// ---------------------------------------------------------------------------------------------
// update_cipher_list / set_ciphersuites (`ssl_ciph.c:1304-1421`)
// ---------------------------------------------------------------------------------------------

/// `ssl_cipher_ptr_id_cmp` — `ssl_lib.c:3239-3247`, the `cipher_list_by_id` comparator.
unsafe extern "C" fn ssl_cipher_ptr_id_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack comparator receives pointers to the elements, so each argument is a
    // `*const *const SslCipher`.
    let (ap, bp) = unsafe {
        (
            *(a as *const *const SslCipher),
            *(b as *const *const SslCipher),
        )
    };
    if ap.is_null() {
        // SAFETY: the same.
        return if bp.is_null() { 0 } else { -1 };
    }
    // SAFETY: `ap`/`bp` are table rows or NULL (handled above).
    let (ai, bi) = unsafe { ((*ap).id, if bp.is_null() { 0 } else { (*bp).id }) };
    if ai > bi {
        1
    } else if ai < bi {
        -1
    } else {
        0
    }
}

/// `update_cipher_list_by_id` — `ssl_ciph.c:1325-1341`.
unsafe fn update_cipher_list_by_id(
    cipher_list_by_id: *mut *mut OpenSslStack,
    cipherstack: *mut OpenSslStack,
) -> bool {
    // SAFETY: the stack functions take/return live stacks per their contracts.
    let tmp = unsafe { OPENSSL_sk_dup(cipherstack) };
    if tmp.is_null() {
        return false;
    }
    // SAFETY: same.
    unsafe {
        OPENSSL_sk_free(*cipher_list_by_id);
        *cipher_list_by_id = tmp;
        OPENSSL_sk_set_cmp_func(tmp, Some(ssl_cipher_ptr_id_cmp));
        OPENSSL_sk_sort(tmp);
    }
    true
}

fn mac_table_mask_ok(algorithm2: u32) -> bool {
    let idx = (algorithm2 & t::SSL_HANDSHAKE_MAC_MASK as u32) as usize;
    idx < t::SSL_CIPHER_TABLE_MAC.len()
}

/// `update_cipher_list` — `ssl_ciph.c:1343-1387`.
unsafe fn update_cipher_list(
    ctx: *mut SslCtx,
    cipher_list: *mut *mut OpenSslStack,
    cipher_list_by_id: *mut *mut OpenSslStack,
    tls13_ciphersuites: *mut OpenSslStack,
) -> bool {
    // SAFETY: live stacks per the caller's contract.
    let tmp = unsafe { OPENSSL_sk_dup(*cipher_list) };
    if tmp.is_null() {
        return false;
    }
    // SAFETY: `tmp` is the duplicate.
    unsafe {
        loop {
            let n = OPENSSL_sk_num(tmp);
            if n <= 0 {
                break;
            }
            let c0 = OPENSSL_sk_value(tmp, 0) as *const SslCipher;
            if c0.is_null() || (*c0).min_tls != t::TLS1_3_VERSION as c_int {
                break;
            }
            OPENSSL_sk_delete(tmp, 0);
        }
        let num_tls13 = OPENSSL_sk_num(tls13_ciphersuites);
        for i in (0..num_tls13).rev() {
            let sslc = OPENSSL_sk_value(tls13_ciphersuites, i) as *const SslCipher;
            if sslc.is_null() {
                continue;
            }
            let (enc, a2) = ((*sslc).algorithm_enc, (*sslc).algorithm2);
            if (enc & (*ctx).disabled_enc_mask) == 0
                && mac_table_mask_ok(a2)
                && (t::SSL_CIPHER_TABLE_MAC[(a2 & t::SSL_HANDSHAKE_MAC_MASK as u32) as usize].0
                    & (*ctx).disabled_mac_mask)
                    == 0
            {
                OPENSSL_sk_unshift(tmp, sslc.cast());
            }
        }
        if !update_cipher_list_by_id(cipher_list_by_id, tmp) {
            OPENSSL_sk_free(tmp);
            return false;
        }
        OPENSSL_sk_free(*cipher_list);
        *cipher_list = tmp;
    }
    true
}

/// `ciphersuite_cb` — `ssl_ciph.c:1273-1302`.
unsafe extern "C" fn ciphersuite_cb(elem: *const c_char, len: c_int, arg: *mut c_void) -> c_int {
    let ciphersuites = arg as *mut OpenSslStack;
    if elem.is_null() || len == 0 || len > 79 {
        return 1;
    }
    let mut name = [0u8; 80];
    // SAFETY: the caller gives `elem` at least `len` readable bytes.
    unsafe { ptr::copy_nonoverlapping(elem as *const u8, name.as_mut_ptr(), len as usize) };
    name[len as usize] = 0;
    // SAFETY: `name` is NUL-terminated.
    let cipher = unsafe { ssl3_get_cipher_by_std_name(name.as_ptr().cast::<c_char>()) };
    if cipher.is_null() {
        return 1;
    }
    // SAFETY: `ciphersuites` is a live stack.
    unsafe { OPENSSL_sk_push(ciphersuites, cipher.cast::<c_void>()) };
    1
}

/// `set_ciphersuites` — `ssl_ciph.c:1304-1323`.
unsafe fn set_ciphersuites(currciphers: *mut *mut OpenSslStack, str_: *const c_char) -> bool {
    // SAFETY: a fresh empty stack.
    let newciphers = OPENSSL_sk_new_null();
    if newciphers.is_null() {
        return false;
    }
    // SAFETY: `str_` is NULL or NUL-terminated per the caller's contract.
    let nonzero = !str_.is_null() && unsafe { *str_ } != 0;
    if nonzero {
        // SAFETY: `str_` is NUL-terminated; `newciphers` is live; the callback is this module's.
        let rc = unsafe {
            crate::runtime::conf::modparse::CONF_parse_list(
                str_,
                b':' as c_int,
                1,
                Some(ciphersuite_cb),
                newciphers.cast::<c_void>(),
            )
        };
        // SAFETY: `newciphers` is live.
        if rc <= 0 || unsafe { OPENSSL_sk_num(newciphers) } == 0 {
            // SAFETY: `newciphers` is live and owned here.
            unsafe { OPENSSL_sk_free(newciphers) };
            return false;
        }
    }
    // SAFETY: live pointers per the caller's contract.
    unsafe {
        OPENSSL_sk_free(*currciphers);
        *currciphers = newciphers;
    }
    true
}

// ---------------------------------------------------------------------------------------------
// ssl_load_ciphers — the disabled masks (`ssl_ciph.c:326-446`)
// ---------------------------------------------------------------------------------------------

/// Fetch one cipher by NID name, returning NULL when the provider has none.
///
/// This is the authority's `ssl_evp_cipher_fetch` without its engine arm (the
/// crate's profile has no engine cipher), and the `ERR_set_mark`/`ERR_pop_to_mark`
/// pair is the whole point: `ssl_lib.c:7496-7513` wraps the explicit fetch in a
/// mark because "this may fail and that could be ok", so a cipher no provider
/// publishes is disabled by [`ssl_load_ciphers`] **without** leaving an error in
/// the queue. Omitting it left one fetch error per unavailable legacy cipher in
/// libssl's queue (`evp_fetch.c:376`), which the shared-state court would then
/// read through libcrypto.
///
/// # Safety
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
unsafe fn fetch_cipher(libctx: *mut c_void, propq: *const c_char, nid: c_int) -> *mut EvpCipher {
    // SAFETY: `OBJ_nid2sn` takes any NID.
    let sn = OBJ_nid2sn(nid);
    if sn.is_null() {
        return ptr::null_mut();
    }
    // The mark and its rollback are the authority's (`ssl_lib.c:7496-7513`): the
    // fetch may push an error that must not survive a miss.
    let _ = ERR_set_mark();
    // SAFETY: `sn` is a static string; `libctx`/`propq` are per the caller's contract.
    let c = unsafe { EVP_CIPHER_fetch(libctx, sn, propq) };
    // Consumes the mark set above; the fetched cipher, if any, is kept.
    let _ = ERR_pop_to_mark();
    c
}

/// `ssl_load_ciphers` — `ssl_ciph.c:326-446`, setting the four disabled masks.
///
/// # Safety
/// `ctx` must be live.
pub(crate) unsafe fn ssl_load_ciphers(ctx: *mut SslCtx) {
    // SAFETY: `ctx` is live per the caller's contract.
    let (libctx, propq) = unsafe { ((*ctx).libctx, (*ctx).propq) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).disabled_enc_mask = 0 };
    for (mask, nid) in t::SSL_CIPHER_TABLE_CIPHER.iter() {
        if *nid == NID_undef {
            continue;
        }
        // SAFETY: the fetch arguments are per `fetch_cipher`'s contract.
        let c = unsafe { fetch_cipher(libctx, propq, *nid) };
        if c.is_null() {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).disabled_enc_mask |= *mask };
        } else {
            // SAFETY: `c` was returned by the fetch and is owned here.
            unsafe { EVP_CIPHER_free(c) };
        }
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).disabled_mac_mask = 0 };
    for (mask, nid) in t::SSL_CIPHER_TABLE_MAC.iter() {
        // SAFETY: `OBJ_nid2sn` takes any NID.
        let sn = OBJ_nid2sn(*nid);
        // SAFETY: `sn` is a static string; the fetch arguments are per its contract.
        let md = if sn.is_null() {
            ptr::null_mut()
        } else {
            // `ssl_evp_md_fetch` (`ssl_lib.c:7543-7558`) marks before the explicit
            // fetch and rolls back to the mark after, so an unavailable digest is
            // disabled without leaving the fetch's error in the queue.
            let _ = ERR_set_mark();
            // SAFETY: `sn` is a static string; the fetch arguments are per its contract.
            let md = unsafe { EVP_MD_fetch(libctx, sn, propq) };
            let _ = ERR_pop_to_mark();
            md
        };
        if md.is_null() {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).disabled_mac_mask |= *mask };
        } else {
            // SAFETY: `md` was returned by the fetch and is owned here.
            unsafe { EVP_MD_free(md) };
        }
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).disabled_mkey_mask = 0;
        (*ctx).disabled_auth_mask = 0;
    }
    // The four probe fetches below are each checked for presence and freed. The
    // authority wraps the whole group in one mark: "We ignore any errors from the
    // fetches below. They are expected to fail if these algorithms are not
    // available" (`ssl_ciph.c:365-394`), so an absent signature/key-exchange must
    // not leave its error in the queue.
    let _ = ERR_set_mark();
    // SAFETY: the fetch arguments are per the fetch contracts.
    unsafe {
        let sig = EVP_SIGNATURE_fetch(libctx, c"DSA".as_ptr(), propq);
        if sig.is_null() {
            (*ctx).disabled_auth_mask |= t::SSL_aDSS as u32;
        } else {
            EVP_SIGNATURE_free(sig);
        }
        let kex = EVP_KEYEXCH_fetch(libctx, c"DH".as_ptr(), propq);
        if kex.is_null() {
            (*ctx).disabled_mkey_mask |= (t::SSL_kDHE | t::SSL_kDHEPSK) as u32;
        } else {
            EVP_KEYEXCH_free(kex);
        }
        let kex = EVP_KEYEXCH_fetch(libctx, c"ECDH".as_ptr(), propq);
        if kex.is_null() {
            (*ctx).disabled_mkey_mask |= (t::SSL_kECDHE | t::SSL_kECDHEPSK) as u32;
        } else {
            EVP_KEYEXCH_free(kex);
        }
        let sig = EVP_SIGNATURE_fetch(libctx, c"ECDSA".as_ptr(), propq);
        if sig.is_null() {
            (*ctx).disabled_auth_mask |= t::SSL_aECDSA as u32;
        } else {
            EVP_SIGNATURE_free(sig);
        }
        // GOST 34.10 is not published by the crate's default provider; the authority disables the
        // same masks after its own probes miss (`ssl_ciph.c:430-443`).
        (*ctx).disabled_auth_mask |= (t::SSL_aGOST01 | t::SSL_aGOST12) as u32;
        (*ctx).disabled_mkey_mask |= (t::SSL_kGOST | t::SSL_kGOST18) as u32;
    }
    // Consumes the group's mark, rolling back every probe failure above.
    let _ = ERR_pop_to_mark();
}

// ---------------------------------------------------------------------------------------------
// ssl_create_cipher_list (`ssl_ciph.c:1423-1672`)
// ---------------------------------------------------------------------------------------------

/// `ssl_create_cipher_list` — `ssl_ciph.c:1423-1672`.
///
/// # Safety
/// `ctx`/`c` live; the three stack pointers point at live `*mut OpenSslStack` slots; `rule_str`
/// NULL or NUL-terminated.
pub(crate) unsafe fn ssl_create_cipher_list(
    ctx: *mut SslCtx,
    tls13_ciphersuites: *mut OpenSslStack,
    cipher_list: *mut *mut OpenSslStack,
    cipher_list_by_id: *mut *mut OpenSslStack,
    rule_str: *const c_char,
    c: *mut Cert,
) -> *mut OpenSslStack {
    if rule_str.is_null() || cipher_list.is_null() || cipher_list_by_id.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `rule_str` is NUL-terminated per the caller's contract.
    let raw_rule = unsafe { core::ffi::CStr::from_ptr(rule_str) }.to_bytes();
    // SAFETY: `ctx` is live.
    let method = unsafe { (*ctx).method };
    if method.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `method`/`c` are live per the caller's contract.
    let rule: Vec<u8> = match unsafe { check_suiteb_cipher_list(method, c, raw_rule) } {
        Some(r) => r,
        None => return ptr::null_mut(),
    };

    // SAFETY: `method`/`ctx` are live.
    let mut co = unsafe { ssl_cipher_collect_ciphers(method, ctx) };
    // The fixed preference rules, in the authority's order (`ssl_ciph.c:1483-1564`).
    co.apply_rule(
        0,
        t::SSL_kECDHE as u32,
        t::SSL_aECDSA as u32,
        0,
        0,
        0,
        0,
        CIPHER_ADD,
        -1,
    );
    co.apply_rule(0, t::SSL_kECDHE as u32, 0, 0, 0, 0, 0, CIPHER_ADD, -1);
    co.apply_rule(0, t::SSL_kECDHE as u32, 0, 0, 0, 0, 0, CIPHER_DEL, -1);
    co.apply_rule(0, 0, 0, t::SSL_AESGCM as u32, 0, 0, 0, CIPHER_ADD, -1);
    co.apply_rule(0, 0, 0, t::SSL_CHACHA20 as u32, 0, 0, 0, CIPHER_ADD, -1);
    co.apply_rule(
        0,
        0,
        0,
        (t::SSL_AES as u32) ^ (t::SSL_AESGCM as u32),
        0,
        0,
        0,
        CIPHER_ADD,
        -1,
    );
    co.apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ADD, -1);
    co.apply_rule(0, 0, 0, 0, t::SSL_MD5 as u32, 0, 0, CIPHER_ORD, -1);
    co.apply_rule(0, 0, t::SSL_aNULL as u32, 0, 0, 0, 0, CIPHER_ORD, -1);
    co.apply_rule(0, t::SSL_kRSA as u32, 0, 0, 0, 0, 0, CIPHER_ORD, -1);
    co.apply_rule(0, t::SSL_kPSK as u32, 0, 0, 0, 0, 0, CIPHER_ORD, -1);
    co.apply_rule(0, 0, 0, t::SSL_RC4 as u32, 0, 0, 0, CIPHER_ORD, -1);
    ssl_cipher_strength_sort(&mut co);
    co.apply_rule(
        0,
        0,
        0,
        0,
        0,
        t::TLS1_2_VERSION as c_int,
        0,
        CIPHER_BUMP,
        -1,
    );
    co.apply_rule(0, 0, 0, 0, t::SSL_AEAD as u32, 0, 0, CIPHER_BUMP, -1);
    co.apply_rule(
        0,
        (t::SSL_kDHE | t::SSL_kECDHE) as u32,
        0,
        0,
        0,
        0,
        0,
        CIPHER_BUMP,
        -1,
    );
    co.apply_rule(
        0,
        (t::SSL_kDHE | t::SSL_kECDHE) as u32,
        0,
        0,
        t::SSL_AEAD as u32,
        0,
        0,
        CIPHER_BUMP,
        -1,
    );
    co.apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1);

    // SAFETY: `ctx` is live.
    let mut ca_list = unsafe { ssl_cipher_collect_aliases(&co, ctx) };

    // Rule processing: `DEFAULT` folds in OSSL_default_cipher_list first.
    let mut rule_p: usize = 0;
    let mut ok = true;
    if rule.starts_with(b"DEFAULT") {
        // SAFETY: the default list is a static NUL-terminated string.
        let default = unsafe { core::ffi::CStr::from_ptr(OSSL_default_cipher_list()) }.to_bytes();
        // SAFETY: `c` is live per the caller's contract.
        ok = unsafe { ssl_cipher_process_rulestr(default, &mut co, &ca_list, c) };
        rule_p = 7;
        if rule.get(rule_p) == Some(&b':') {
            rule_p += 1;
        }
    }
    if ok && rule.get(rule_p).copied().unwrap_or(0) != 0 {
        // SAFETY: `c` is live.
        ok = unsafe { ssl_cipher_process_rulestr(&rule[rule_p..], &mut co, &ca_list, c) };
    }
    let _ = &mut ca_list;
    if !ok {
        return ptr::null_mut();
    }

    // SAFETY: a fresh empty stack.
    let cipherstack = OPENSSL_sk_new_null();
    if cipherstack.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `tls13_ciphersuites`/`cipherstack` are live.
    unsafe {
        let mut i = 0;
        while i < OPENSSL_sk_num(tls13_ciphersuites) {
            let sslc = OPENSSL_sk_value(tls13_ciphersuites, i) as *const SslCipher;
            if sslc.is_null() {
                i += 1;
                continue;
            }
            let (enc, a2) = ((*sslc).algorithm_enc, (*sslc).algorithm2);
            if (enc & (*ctx).disabled_enc_mask) != 0
                || !mac_table_mask_ok(a2)
                || (t::SSL_CIPHER_TABLE_MAC[(a2 & t::SSL_HANDSHAKE_MAC_MASK as u32) as usize].0
                    & (*ctx).disabled_mac_mask)
                    != 0
            {
                OPENSSL_sk_delete(tls13_ciphersuites, i);
                continue;
            }
            if OPENSSL_sk_push(cipherstack, sslc.cast::<c_void>()) <= 0 {
                OPENSSL_sk_free(cipherstack);
                return ptr::null_mut();
            }
            i += 1;
        }
        for &id in &co.order {
            if co.active[id] && OPENSSL_sk_push(cipherstack, co.co[id].cast::<c_void>()) <= 0 {
                OPENSSL_sk_free(cipherstack);
                return ptr::null_mut();
            }
        }
        if !update_cipher_list_by_id(cipher_list_by_id, cipherstack) {
            OPENSSL_sk_free(cipherstack);
            return ptr::null_mut();
        }
        OPENSSL_sk_free(*cipher_list);
        *cipher_list = cipherstack;
    }
    cipherstack
}

/// `cipher_list_tls12_num` — `ssl_lib.c:3350-3364`.
///
/// # Safety
/// `sk` NULL or a live stack of `const SSL_CIPHER *`.
pub(crate) unsafe fn cipher_list_tls12_num(sk: *mut OpenSslStack) -> c_int {
    if sk.is_null() {
        return 0;
    }
    let mut num = 0;
    // SAFETY: `sk` is live.
    let n = unsafe { OPENSSL_sk_num(sk) };
    for i in 0..n {
        // SAFETY: `i` is in range.
        let c = unsafe { OPENSSL_sk_value(sk, i) as *const SslCipher };
        if c.is_null() {
            continue;
        }
        // SAFETY: `c` is a table row.
        if unsafe { (*c).min_tls } < t::TLS1_3_VERSION as c_int {
            num += 1;
        }
    }
    num
}

// ---------------------------------------------------------------------------------------------
// The `SSL_CIPHER_*` readers and the two `OSSL_default_*` lists (`ssl_ciph.c:1674-2260`)
// ---------------------------------------------------------------------------------------------

/// `char *SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int len)` —
/// `ssl/ssl_ciph.c:1674-1879`.
///
/// # Safety
/// `cipher` live; `buf` NULL or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_description(
    cipher: *const SslCipher,
    buf: *mut c_char,
    len: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if cipher.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `cipher` is live per the caller's contract.
        let c = unsafe { &*cipher };
        let mut out = buf;
        let mut out_len = len;
        if out.is_null() {
            out_len = 128;
            // SAFETY: `CRYPTO_malloc` returns NULL or a block of this size.
            out = CRYPTO_malloc(128, FILE, 1683).cast::<c_char>();
            if out.is_null() {
                return ptr::null_mut();
            }
        } else if len < 128 {
            return ptr::null_mut();
        }
        let kx = match c.algorithm_mkey as u64 {
            x if x == t::SSL_kRSA => "RSA",
            x if x == t::SSL_kDHE => "DH",
            x if x == t::SSL_kECDHE => "ECDH",
            x if x == t::SSL_kPSK => "PSK",
            x if x == t::SSL_kRSAPSK => "RSAPSK",
            x if x == t::SSL_kECDHEPSK => "ECDHEPSK",
            x if x == t::SSL_kDHEPSK => "DHEPSK",
            x if x == t::SSL_kSRP => "SRP",
            x if x == t::SSL_kGOST => "GOST",
            x if x == t::SSL_kGOST18 => "GOST18",
            x if x == t::SSL_kANY => "any",
            _ => "unknown",
        };
        let au = match c.algorithm_auth as u64 {
            x if x == t::SSL_aRSA => "RSA",
            x if x == t::SSL_aDSS => "DSS",
            x if x == t::SSL_aNULL => "None",
            x if x == t::SSL_aECDSA => "ECDSA",
            x if x == t::SSL_aPSK => "PSK",
            x if x == t::SSL_aSRP => "SRP",
            x if x == t::SSL_aGOST01 => "GOST01",
            x if x == (t::SSL_aGOST12 | t::SSL_aGOST01) => "GOST12",
            x if x == t::SSL_aANY => "any",
            _ => "unknown",
        };
        let enc = match c.algorithm_enc as u64 {
            x if x == t::SSL_DES => "DES(56)",
            x if x == t::SSL_3DES => "3DES(168)",
            x if x == t::SSL_RC4 => "RC4(128)",
            x if x == t::SSL_RC2 => "RC2(128)",
            x if x == t::SSL_IDEA => "IDEA(128)",
            x if x == t::SSL_eNULL => "None",
            x if x == t::SSL_AES128 => "AES(128)",
            x if x == t::SSL_AES256 => "AES(256)",
            x if x == t::SSL_AES128GCM => "AESGCM(128)",
            x if x == t::SSL_AES256GCM => "AESGCM(256)",
            x if x == t::SSL_AES128CCM => "AESCCM(128)",
            x if x == t::SSL_AES256CCM => "AESCCM(256)",
            x if x == t::SSL_AES128CCM8 => "AESCCM8(128)",
            x if x == t::SSL_AES256CCM8 => "AESCCM8(256)",
            x if x == t::SSL_CAMELLIA128 => "Camellia(128)",
            x if x == t::SSL_CAMELLIA256 => "Camellia(256)",
            x if x == t::SSL_ARIA128GCM => "ARIAGCM(128)",
            x if x == t::SSL_ARIA256GCM => "ARIAGCM(256)",
            x if x == t::SSL_SEED => "SEED(128)",
            x if x == t::SSL_eGOST2814789CNT || x == t::SSL_eGOST2814789CNT12 => "GOST89(256)",
            x if x == t::SSL_MAGMA => "MAGMA",
            x if x == t::SSL_KUZNYECHIK => "KUZNYECHIK",
            x if x == t::SSL_CHACHA20 => "CHACHA20/POLY1305(256)",
            _ => "unknown",
        };
        let mac = match c.algorithm_mac as u64 {
            x if x == t::SSL_MD5 => "MD5",
            x if x == t::SSL_SHA1 => "SHA1",
            x if x == t::SSL_SHA256 => "SHA256",
            x if x == t::SSL_SHA384 => "SHA384",
            x if x == t::SSL_AEAD => "AEAD",
            x if x == t::SSL_GOST89MAC || x == t::SSL_GOST89MAC12 => "GOST89",
            x if x == t::SSL_GOST94 => "GOST94",
            x if x == t::SSL_GOST12_256 || x == t::SSL_GOST12_512 => "GOST2012",
            _ => "unknown",
        };
        // SAFETY: `row_str(c.name)` is a NUL-terminated static string.
        let name = unsafe { core::ffi::CStr::from_ptr(row_str(c.name)) }.to_string_lossy();
        let ver = if c.min_tls == t::TLS1_VERSION as c_int {
            "TLSv1.0".to_string()
        } else {
            // SAFETY: `ssl_protocol_to_string` returns a static string.
            unsafe { core::ffi::CStr::from_ptr(ssl_protocol_to_string(c.min_tls)) }
                .to_string_lossy()
                .into_owned()
        };
        let text = format!(
            "{:<30} {:<7} Kx={:<8} Au={:<5} Enc={:<22} Mac={:<4}\n",
            name, ver, kx, au, enc, mac
        );
        let bytes = text.as_bytes();
        let cap = (out_len as usize).saturating_sub(1);
        let ncopy = bytes.len().min(cap);
        // SAFETY: `out` is writable for `out_len` bytes per the caller's contract.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), ncopy);
            *out.add(ncopy) = 0;
        }
        out
    })
}

/// `const char *SSL_CIPHER_get_version(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:1881-1893`.
///
/// # Safety
/// `c` NULL or a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_version(c: *const SslCipher) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if c.is_null() {
            return c"(NONE)".as_ptr();
        }
        // SAFETY: `c` is live.
        let min_tls = unsafe { (*c).min_tls };
        if min_tls == t::TLS1_VERSION as c_int {
            return c"TLSv1.0".as_ptr();
        }
        ssl_protocol_to_string(min_tls)
    })
}

/// `const char *SSL_CIPHER_get_name(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:1896-1901`.
///
/// # Safety
/// `c` NULL or a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_name(c: *const SslCipher) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if c.is_null() {
            return c"(NONE)".as_ptr();
        }
        // SAFETY: `c` is live.
        row_str(unsafe { (*c).name })
    })
}

/// `const char *SSL_CIPHER_standard_name(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:1904-1909`.
///
/// # Safety
/// `c` NULL or a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_standard_name(c: *const SslCipher) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if c.is_null() {
            return c"(NONE)".as_ptr();
        }
        // SAFETY: `c` is live.
        row_str(unsafe { (*c).stdname })
    })
}

/// `const char *OPENSSL_cipher_name(const char *stdname)` — `ssl/ssl_ciph.c:1912-1920`.
///
/// # Safety
/// `stdname` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_cipher_name(stdname: *const c_char) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if stdname.is_null() {
            return c"(NONE)".as_ptr();
        }
        // SAFETY: `stdname` is NUL-terminated.
        let c = unsafe { ssl3_get_cipher_by_std_name(stdname) };
        // SAFETY: the getter takes NULL or a live cipher.
        unsafe { SSL_CIPHER_get_name(c) }
    })
}

/// `int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits)` — `ssl/ssl_ciph.c:1923-1933`.
///
/// # Safety
/// `c` NULL or live; `alg_bits` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_bits(c: *const SslCipher, alg_bits: *mut c_int) -> c_int {
    guard_ffi(0, || {
        let mut ret = 0;
        if !c.is_null() {
            // SAFETY: `c` is live.
            let c = unsafe { &*c };
            if !alg_bits.is_null() {
                // SAFETY: writable per the caller's contract.
                unsafe { *alg_bits = c.alg_bits as c_int };
            }
            ret = c.strength_bits;
        }
        ret
    })
}

/// `uint32_t SSL_CIPHER_get_id(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:1935-1938`.
///
/// # Safety
/// `c` must point to a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_id(c: *const SslCipher) -> u32 {
    guard_ffi(0, || {
        // SAFETY: `c` is live per the caller's contract.
        unsafe { (*c).id }
    })
}

/// `uint16_t SSL_CIPHER_get_protocol_id(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:1940-1943`.
///
/// # Safety
/// `c` must point to a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_protocol_id(c: *const SslCipher) -> u16 {
    guard_ffi(0, || {
        // SAFETY: `c` is live per the caller's contract.
        (unsafe { (*c).id } & 0xFFFF) as u16
    })
}

/// `const SSL_CIPHER *SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr)` —
/// `ssl/ssl_ciph.c:2095-2098`.
///
/// # Safety
/// `ssl` NULL or live; `ptr` points at two readable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_find(ssl: *mut Ssl, ptr_: *const u8) -> *const SslCipher {
    guard_ffi(ptr::null(), || {
        if ssl.is_null() || ptr_.is_null() {
            return ptr::null();
        }
        // `ssl->method->get_cipher_by_char` is `ssl3_get_cipher_by_char` for every method here.
        // SAFETY: `ptr_` points at two readable bytes per the caller's contract.
        unsafe { ssl3_get_cipher_by_char(ptr_) }
    })
}

/// `int SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:2100-2109`.
///
/// # Safety
/// `c` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_cipher_nid(c: *const SslCipher) -> c_int {
    guard_ffi(NID_undef, || {
        if c.is_null() {
            return NID_undef;
        }
        // SAFETY: `c` is live.
        let mask = unsafe { (*c).algorithm_enc };
        lookup_nid(&t::SSL_CIPHER_TABLE_CIPHER, mask)
    })
}

/// `int SSL_CIPHER_get_digest_nid(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:2111-2118`.
///
/// # Safety
/// `c` must point to a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_digest_nid(c: *const SslCipher) -> c_int {
    guard_ffi(NID_undef, || {
        // SAFETY: `c` is live per the caller's contract.
        let mask = unsafe { (*c).algorithm_mac };
        lookup_nid(&t::SSL_CIPHER_TABLE_MAC, mask)
    })
}

/// `int SSL_CIPHER_get_kx_nid(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:2120-2127`.
///
/// # Safety
/// `c` must point to a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_kx_nid(c: *const SslCipher) -> c_int {
    guard_ffi(NID_undef, || {
        // SAFETY: `c` is live per the caller's contract.
        let mask = unsafe { (*c).algorithm_mkey };
        lookup_nid(&t::SSL_CIPHER_TABLE_KX, mask)
    })
}

/// `int SSL_CIPHER_get_auth_nid(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:2129-2136`.
///
/// # Safety
/// `c` must point to a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_auth_nid(c: *const SslCipher) -> c_int {
    guard_ffi(NID_undef, || {
        // SAFETY: `c` is live per the caller's contract.
        let mask = unsafe { (*c).algorithm_auth };
        lookup_nid(&t::SSL_CIPHER_TABLE_AUTH, mask)
    })
}

fn lookup_nid(table: &[(u32, c_int)], mask: u32) -> c_int {
    for (m, nid) in table {
        if *m == mask {
            return *nid;
        }
    }
    NID_undef
}

/// `const EVP_MD *SSL_CIPHER_get_handshake_digest(const SSL_CIPHER *c)` —
/// `ssl/ssl_ciph.c:2149-2156`.
///
/// # Safety
/// `c` must point to a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_handshake_digest(c: *const SslCipher) -> *const EvpMd {
    guard_ffi(ptr::null(), || {
        // SAFETY: `c` is live per the caller's contract.
        let idx = (unsafe { (*c).algorithm2 } & t::SSL_HANDSHAKE_MAC_MASK as u32) as usize;
        if idx >= t::SSL_CIPHER_TABLE_MAC.len() {
            return ptr::null();
        }
        let nid = t::SSL_CIPHER_TABLE_MAC[idx].1;
        // SAFETY: `OBJ_nid2sn` takes any NID.
        let sn = OBJ_nid2sn(nid);
        if sn.is_null() {
            return ptr::null();
        }
        // SAFETY: `sn` is a NUL-terminated static string.
        unsafe { EVP_get_digestbyname(sn) }
    })
}

/// `int SSL_CIPHER_is_aead(const SSL_CIPHER *c)` — `ssl/ssl_ciph.c:2158-2161`.
///
/// # Safety
/// `c` must point to a live cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_is_aead(c: *const SslCipher) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `c` is live per the caller's contract.
        if (unsafe { (*c).algorithm_mac } & t::SSL_AEAD as u32) != 0 {
            1
        } else {
            0
        }
    })
}

/// `const char *OSSL_default_cipher_list(void)` — `ssl/ssl_ciph.c:2239-2242`.
///
/// # Safety
/// The returned pointer is a static string.
#[no_mangle]
pub unsafe extern "C" fn OSSL_default_cipher_list() -> *const c_char {
    c"ALL:!COMPLEMENTOFDEFAULT:!eNULL".as_ptr()
}

/// `const char *OSSL_default_ciphersuites(void)` — `ssl/ssl_ciph.c:2249-2254`.
///
/// # Safety
/// The returned pointer is a static string.
#[no_mangle]
pub unsafe extern "C" fn OSSL_default_ciphersuites() -> *const c_char {
    c"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256".as_ptr()
}

// ---------------------------------------------------------------------------------------------
// SSL_CTX_set_ciphersuites / SSL_set_ciphersuites (`ssl_ciph.c:1389-1421`)
// ---------------------------------------------------------------------------------------------

/// `int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str)` — `ssl/ssl_ciph.c:1389-1398`.
///
/// # Safety
/// `ctx` must be NULL or live; `str` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_ciphersuites(ctx: *mut SslCtx, str_: *const c_char) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live.
        let ret = unsafe { set_ciphersuites(&mut (*ctx).tls13_ciphersuites, str_) };
        // SAFETY: `ctx` is live; its cipher-list field is a plain pointer read.
        let has_list = !unsafe { (*ctx).cipher_list }.is_null();
        if ret && has_list {
            // SAFETY: `ctx` is live; the stack slots are its own fields.
            let ok = unsafe {
                update_cipher_list(
                    ctx,
                    &mut (*ctx).cipher_list,
                    &mut (*ctx).cipher_list_by_id,
                    (*ctx).tls13_ciphersuites,
                )
            };
            return c_int::from(ok);
        }
        c_int::from(ret)
    })
}

/// `int SSL_set_ciphersuites(SSL *s, const char *str)` — `ssl/ssl_ciph.c:1400-1421`.
///
/// # Safety
/// `s` must be NULL or live; `str` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_ciphersuites(s: *mut Ssl, str_: *const c_char) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        let ret = unsafe { set_ciphersuites(&mut (*s).tls13_ciphersuites, str_) };
        // SAFETY: `s` is live.
        unsafe {
            if (*s).cipher_list.is_null() {
                let cl = SSL_get_ciphers(s);
                if !cl.is_null() {
                    (*s).cipher_list = OPENSSL_sk_dup(cl);
                }
            }
        }
        // SAFETY: `s` is live, and `s->ctx` is a live fallback context.
        unsafe {
            if ret && !(*s).cipher_list.is_null() {
                return c_int::from(update_cipher_list(
                    (*s).ctx,
                    &mut (*s).cipher_list,
                    &mut (*s).cipher_list_by_id,
                    (*s).tls13_ciphersuites,
                ));
            }
        }
        c_int::from(ret)
    })
}

// ---------------------------------------------------------------------------------------------
// The compression-method surface (`ssl_ciph.c:1945-2082`)
// ---------------------------------------------------------------------------------------------

/// `struct ssl_comp_st` — `include/internal/comp.h:18-22`.
#[repr(C)]
pub struct SslComp {
    /// `int id`.
    pub id: c_int,
    /// `const char *name`.
    pub name: *const c_char,
    /// `COMP_METHOD *method`.
    pub method: *mut CompMethod,
}

/// `STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void)` — `ssl/ssl_ciph.c:1981-1991`.
///
/// # Safety
/// No precondition; the process-wide compression-method slot is read.
#[no_mangle]
pub unsafe extern "C" fn SSL_COMP_get_compression_methods() -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the NULL context selects the default library context.
        let rv = unsafe { OSSL_LIB_CTX_get_data(ptr::null_mut(), OSSL_LIB_CTX_COMP_METHODS) };
        if rv.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `rv` is the address of the slot's stack pointer.
        unsafe { *(rv as *mut *mut OpenSslStack) }
    })
}

/// `STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP) *meths)` —
/// `ssl/ssl_ciph.c:1993-2009`.
///
/// # Safety
/// `meths` NULL or a live stack whose ownership is transferred.
#[no_mangle]
pub unsafe extern "C" fn SSL_COMP_set0_compression_methods(
    meths: *mut OpenSslStack,
) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the NULL context selects the default library context.
        let comp_methods =
            unsafe { OSSL_LIB_CTX_get_data(ptr::null_mut(), OSSL_LIB_CTX_COMP_METHODS) };
        if comp_methods.is_null() {
            meths
        } else {
            // SAFETY: `comp_methods` is the address of the slot's stack pointer.
            unsafe {
                let slot = comp_methods as *mut *mut OpenSslStack;
                let old = *slot;
                *slot = meths;
                old
            }
        }
    })
}

/// `int SSL_COMP_add_compression_method(int id, COMP_METHOD *cm)` — `ssl/ssl_ciph.c:2011-2054`.
///
/// # Safety
/// `cm` NULL or a live `COMP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn SSL_COMP_add_compression_method(id: c_int, cm: *mut CompMethod) -> c_int {
    guard_ffi(1, || {
        // SAFETY: no precondition.
        let comp_methods = unsafe { SSL_COMP_get_compression_methods() };
        if comp_methods.is_null() {
            return 1;
        }
        if cm.is_null() {
            return 1;
        }
        // SAFETY: `cm` is live per the caller's contract.
        if COMP_get_type(cm) == NID_undef {
            return 1;
        }
        if !(193..=255).contains(&id) {
            return 1; // SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE
        }
        // SAFETY: a fresh zeroed block.
        let comp = crate::runtime::mem::CRYPTO_zalloc(core::mem::size_of::<SslComp>(), FILE, 2037)
            .cast::<SslComp>();
        if comp.is_null() {
            return 1;
        }
        // The authority sets only `comp->id` here (`ssl_ciph.c:2041`); `name`/`method` are left
        // as `OPENSSL_malloc` produced them. This is a zeroed block, so they read NULL.
        // SAFETY: `comp` is a fresh allocation; `id` is in range; `comp_methods` is a live stack.
        unsafe {
            (*comp).id = id;
            let _ = OPENSSL_sk_push(comp_methods, comp.cast::<c_void>());
        }
        0
    })
}

/// `const char *SSL_COMP_get_name(const COMP_METHOD *comp)` — `ssl/ssl_ciph.c:2057-2064`.
///
/// # Safety
/// `comp` NULL or a live `COMP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn SSL_COMP_get_name(comp: *const CompMethod) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if comp.is_null() {
            return ptr::null();
        }
        // SAFETY: `comp` is live per the caller's contract.
        COMP_get_name(comp)
    })
}

/// `const char *SSL_COMP_get0_name(const SSL_COMP *comp)` — `ssl/ssl_ciph.c:2066-2073`.
///
/// # Safety
/// `comp` must point to a live `SSL_COMP`.
#[no_mangle]
pub unsafe extern "C" fn SSL_COMP_get0_name(comp: *const SslComp) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `comp` is live per the caller's contract.
        unsafe { (*comp).name }
    })
}

/// `int SSL_COMP_get_id(const SSL_COMP *comp)` — `ssl/ssl_ciph.c:2075-2082`.
///
/// # Safety
/// `comp` must point to a live `SSL_COMP`.
#[no_mangle]
pub unsafe extern "C" fn SSL_COMP_get_id(comp: *const SslComp) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `comp` is live per the caller's contract.
        unsafe { (*comp).id }
    })
}

/// The file name the authority's `OPENSSL_malloc`/`OPENSSL_free` sites carry.
const FILE: *const c_char = c"ssl_ciph.c".as_ptr();
