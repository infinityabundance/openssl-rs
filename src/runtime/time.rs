//! Phase 3 — the civil-time arithmetic: `crypto/o_time.c`.
//!
//! Three symbols, all in `crypto.h` and all in the ownership atlas's Phase 3
//! set: `OPENSSL_gmtime`, `OPENSSL_gmtime_adj` and `OPENSSL_gmtime_diff`. They
//! are the authority's own calendar, written because "this avoids any OS issues
//! with restricted date types and overflows which cause the year 2038 problem" —
//! so the arithmetic here is *not* a call into the platform. Only
//! `OPENSSL_gmtime` itself delegates, and it delegates to `gmtime_r`, which is
//! what the authority's `#elif defined(OPENSSL_THREADS) && !WIN32 && !MACOSX`
//! arm resolves to on the admitted profile.
//!
//! ## Why the arithmetic is transcribed rather than improved
//!
//! The three helpers are Fliegel & Van Flandern's Julian-day conversion, and
//! every one of their intermediate values is observable through a deliberate
//! input: `OPENSSL_gmtime_diff(pday, psec, NULL, tm)` is a documented call that
//! answers day and second counts, and `OPENSSL_gmtime_adj` is what
//! `ASN1_UTCTIME_adj` and `ASN1_GENERALIZEDTIME_adj` are built on. So the
//! truncation of `offset_sec / SECS_PER_DAY` toward zero, the `int`-typed
//! intermediate in `date_to_julian` that can wrap for an extreme year, and the
//! `long`-to-`int` narrowing `julian_to_date` does on its three outputs are all
//! part of the contract rather than incidental.
//!
//! ## Overflow is defined here and is not upstream
//!
//! The crate builds with `overflow-checks = true` (see `Cargo.toml`), and a
//! caller can hand `OPENSSL_gmtime_adj` an `offset_sec` of `LONG_MIN` or
//! `LONG_MAX`, which the authority's `long` arithmetic then overflows — undefined
//! behaviour upstream, and a panic here without the `wrapping_*` operations
//! below. Every arithmetic operation in this module wraps. The result for a
//! value upstream leaves undefined is therefore *a* result rather than a crash;
//! no probe compares that region, and `docs/SECURITY_DIVERGENCE_POLICY.md`
//! records the disposition.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long};

/// `time_t` on the admitted profile — `long`, 64-bit on x86-64.
pub type TimeT = c_long;

/// `struct tm` from `<time.h>`, as glibc lays it out on the admitted platform.
///
/// This is a C library structure, not an OpenSSL one: it is declared here
/// because four exported functions take a `struct tm *` and the crate has to
/// agree with `<time.h>` about its layout. The probe
/// `courts/phase5/rt_asn1_time_probe.c` measures the candidate's layout against
/// the authority's own `sizeof` and `offsetof` so the agreement is checked rather
/// than asserted.
///
/// The trailing two members are the glibc extension. The authority's
/// `ossl_asn1_time_to_tm` zeroes its local copy with `memset` and then copies the
/// whole structure out, so `tm_isdst`, `tm_gmtoff` and `tm_zone` are observable
/// in the caller's structure and are part of what is compared.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tm {
    /// `tm_sec` — seconds after the minute, 0 to 60.
    pub tm_sec: c_int,
    /// `tm_min` — minutes after the hour, 0 to 59.
    pub tm_min: c_int,
    /// `tm_hour` — hours since midnight, 0 to 23.
    pub tm_hour: c_int,
    /// `tm_mday` — day of the month, 1 to 31.
    pub tm_mday: c_int,
    /// `tm_mon` — months since January, 0 to 11.
    pub tm_mon: c_int,
    /// `tm_year` — years since 1900. The authority's `is_utc` tests this field,
    /// not the civil year, which is why its range is `50 <= y <= 149`.
    pub tm_year: c_int,
    /// `tm_wday` — days since Sunday, 0 to 6.
    pub tm_wday: c_int,
    /// `tm_yday` — days since January 1, 0 to 365.
    pub tm_yday: c_int,
    /// `tm_isdst` — daylight-saving flag, negative when unknown.
    pub tm_isdst: c_int,
    /// `tm_gmtoff` — seconds east of UTC (glibc extension).
    pub tm_gmtoff: c_long,
    /// `tm_zone` — the timezone abbreviation (glibc extension).
    pub tm_zone: *const c_char,
}

/// `SECS_PER_DAY` — the authority's `(24 * 60 * 60)`.
const SECS_PER_DAY: c_long = 24 * 60 * 60;

extern "C" {
    /// `struct tm *gmtime_r(const time_t *, struct tm *)` — the reentrant UTC
    /// conversion the authority's Linux arm calls.
    fn gmtime_r(timer: *const TimeT, result: *mut Tm) -> *mut Tm;
}

/// `struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result)`
///
/// Answers `result` on success and null when the platform's conversion refused
/// the value — which on glibc happens for a `time_t` outside the representable
/// range. The authority's threaded non-VMS, non-Windows, non-macOS arm is a bare
/// `gmtime_r` whose result becomes `ts`, and `result` is returned rather than the
/// pointer `gmtime_r` answered, which are the same address.
///
/// # Safety
///
/// `timer` must be a readable `time_t` and `result` a writable `struct tm`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_gmtime(timer: *const TimeT, result: *mut Tm) -> *mut Tm {
    // SAFETY: the caller's contract is this function's own, and `gmtime_r` is
    // the authority's arm — it writes `*result` and reads `*timer`.
    if unsafe { gmtime_r(timer, result) }.is_null() {
        return core::ptr::null_mut();
    }
    result
}

/// `static long date_to_julian(int y, int m, int d)`
///
/// Fliegel & Van Flandern. Every intermediate is an `int` upstream, so the
/// wrapping operations below are what the emitted code does; see the module
/// documentation.
fn date_to_julian(y: c_int, m: c_int, d: c_int) -> c_long {
    let md = (m.wrapping_sub(14)).wrapping_div(12);
    let a = 1461_i32.wrapping_mul(y.wrapping_add(4800).wrapping_add(md)) / 4;
    let b = 367_i32.wrapping_mul(m.wrapping_sub(2).wrapping_sub(12_i32.wrapping_mul(md))) / 12;
    let c = 3_i32.wrapping_mul(y.wrapping_add(4900).wrapping_add(md).wrapping_div(100)) / 4;
    a.wrapping_add(b)
        .wrapping_sub(c)
        .wrapping_add(d)
        .wrapping_sub(32075) as c_long
}

/// `static void julian_to_date(long jd, int *y, int *m, int *d)`
///
/// The three answers are narrowed to `int` exactly where the authority narrows
/// them, and the order of the assignments matters: the day is computed from the
/// second value of `L`, and the month from the third.
fn julian_to_date(jd: c_long) -> (c_int, c_int, c_int) {
    let mut l = jd.wrapping_add(68569);
    let n = 4_i64.wrapping_mul(l).wrapping_div(146097);
    l = l.wrapping_sub(146097_i64.wrapping_mul(n).wrapping_add(3).wrapping_div(4));
    let i = 4000_i64
        .wrapping_mul(l.wrapping_add(1))
        .wrapping_div(1461001);
    l = l
        .wrapping_sub(1461_i64.wrapping_mul(i).wrapping_div(4))
        .wrapping_add(31);
    let j = 80_i64.wrapping_mul(l).wrapping_div(2447);
    let d = l.wrapping_sub(2447_i64.wrapping_mul(j).wrapping_div(80));
    l = j.wrapping_div(11);
    let m = j.wrapping_add(2).wrapping_sub(12_i64.wrapping_mul(l));
    let y = 100_i64
        .wrapping_mul(n.wrapping_sub(49))
        .wrapping_add(i)
        .wrapping_add(l);
    (y as c_int, m as c_int, d as c_int)
}

/// `static int julian_adj(const struct tm *tm, int off_day, long offset_sec,
/// long *pday, int *psec)`
///
/// Splits the second offset into whole days and day-seconds, folds the time of
/// day in, borrows or carries across the day boundary once, and adds the whole
/// days to the Julian day number. The single borrow/carry — rather than a
/// division of the combined value — is observable: `offset_hms` is an `int` and
/// the fold can overflow it for an extreme `tm_hour`.
///
/// Answers the Julian day and the second-of-day, or nothing when the resulting
/// day number is negative.
fn julian_adj(tm: &Tm, off_day: c_int, offset_sec: c_long) -> Option<(c_long, c_int)> {
    let mut offset_day: c_long = offset_sec.wrapping_div(SECS_PER_DAY);
    let mut offset_hms: c_int =
        offset_sec.wrapping_sub(offset_day.wrapping_mul(SECS_PER_DAY)) as c_int;
    offset_day = offset_day.wrapping_add(c_long::from(off_day));
    offset_hms = offset_hms.wrapping_add(
        tm.tm_hour
            .wrapping_mul(3600)
            .wrapping_add(tm.tm_min.wrapping_mul(60))
            .wrapping_add(tm.tm_sec),
    );
    if offset_hms >= SECS_PER_DAY as c_int {
        offset_day = offset_day.wrapping_add(1);
        offset_hms = offset_hms.wrapping_sub(SECS_PER_DAY as c_int);
    } else if offset_hms < 0 {
        offset_day = offset_day.wrapping_sub(1);
        offset_hms = offset_hms.wrapping_add(SECS_PER_DAY as c_int);
    }

    let time_year = tm.tm_year.wrapping_add(1900);
    let time_month = tm.tm_mon.wrapping_add(1);
    let time_day = tm.tm_mday;
    let time_jd = date_to_julian(time_year, time_month, time_day).wrapping_add(offset_day);
    if time_jd < 0 {
        return None;
    }
    Some((time_jd, offset_hms))
}

/// `int OPENSSL_gmtime_adj(struct tm *tm, int off_day, long offset_sec)`
///
/// Adds a day and second offset in place, updating only the six fields a caller
/// reads back — `tm_wday`, `tm_yday`, `tm_isdst`, `tm_gmtoff` and `tm_zone` are
/// left as they were, which is observable.
///
/// The year range test answers failure *after* the Julian conversion, so an
/// offset that lands outside `[1900, 9999]` is a failure rather than a clamp.
///
/// A null `tm` faults upstream. Here it answers failure; see
/// `docs/SECURITY_DIVERGENCE_POLICY.md`.
///
/// # Safety
///
/// `tm` must be null or a live, writable `struct tm`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_gmtime_adj(
    tm: *mut Tm,
    off_day: c_int,
    offset_sec: c_long,
) -> c_int {
    // SAFETY: the caller's contract is this function's own.
    let Some(t) = (unsafe { tm.as_ref() }) else {
        return 0;
    };
    let Some((time_jd, time_sec)) = julian_adj(t, off_day, offset_sec) else {
        return 0;
    };
    let (time_year, time_month, time_day) = julian_to_date(time_jd);
    if !(1900..=9999).contains(&time_year) {
        return 0;
    }
    // SAFETY: `tm` was live above and no other reference to it exists.
    let t = unsafe { &mut *tm };
    t.tm_year = time_year.wrapping_sub(1900);
    t.tm_mon = time_month.wrapping_sub(1);
    t.tm_mday = time_day;
    t.tm_hour = time_sec.wrapping_div(3600);
    t.tm_min = time_sec.wrapping_div(60).wrapping_rem(60);
    t.tm_sec = time_sec.wrapping_rem(60);
    1
}

/// `int OPENSSL_gmtime_diff(int *pday, int *psec, const struct tm *from,
/// const struct tm *to)`
///
/// The signed difference, normalised so that the day and second parts carry the
/// same sign. Both outputs are optional — `ASN1_TIME_diff` always passes both,
/// but the authority's null tests are contractual and a caller may pass one.
///
/// # Safety
///
/// `from` and `to` must be readable `struct tm`s. `pday` and `psec` must be null
/// or writable `int`s.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_gmtime_diff(
    pday: *mut c_int,
    psec: *mut c_int,
    from: *const Tm,
    to: *const Tm,
) -> c_int {
    // SAFETY: the caller's contract is this function's own; a null `from` or
    // `to` faults upstream, and answering failure here is recorded in
    // `docs/SECURITY_DIVERGENCE_POLICY.md`.
    let (Some(f), Some(t)) = (unsafe { from.as_ref() }, unsafe { to.as_ref() }) else {
        return 0;
    };
    let Some((from_jd, from_sec)) = julian_adj(f, 0, 0) else {
        return 0;
    };
    let Some((to_jd, to_sec)) = julian_adj(t, 0, 0) else {
        return 0;
    };
    let mut diff_day = to_jd.wrapping_sub(from_jd);
    let mut diff_sec = to_sec.wrapping_sub(from_sec);
    if diff_day > 0 && diff_sec < 0 {
        diff_day = diff_day.wrapping_sub(1);
        diff_sec = diff_sec.wrapping_add(SECS_PER_DAY as c_int);
    }
    if diff_day < 0 && diff_sec > 0 {
        diff_day = diff_day.wrapping_add(1);
        diff_sec = diff_sec.wrapping_sub(SECS_PER_DAY as c_int);
    }
    if !pday.is_null() {
        // SAFETY: the caller's contract is this function's own.
        unsafe { *pday = diff_day as c_int };
    }
    if !psec.is_null() {
        // SAFETY: the caller's contract is this function's own.
        unsafe { *psec = diff_sec };
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All-zero, the way the authority's `memset` produces it.
    fn zeroed() -> Tm {
        // SAFETY: `Tm` is integers and one pointer; all-zero is a valid value.
        unsafe { core::mem::zeroed() }
    }

    /// The Julian-day conversion is exact at the two epochs every implementation
    /// has to agree on, and at a leap-day boundary.
    #[test]
    fn julian_day_round_trips_the_epoch() {
        let jd = date_to_julian(1970, 1, 1);
        assert_eq!(julian_to_date(jd), (1970, 1, 1));
        let jd = date_to_julian(2000, 2, 29);
        assert_eq!(julian_to_date(jd), (2000, 2, 29));
    }

    /// `OPENSSL_gmtime_adj` moves the day, the calendar and the clock together,
    /// and rolls the date when the clock crosses midnight.
    #[test]
    fn adjust_carries_across_midnight() {
        let mut tm = zeroed();
        tm.tm_year = 100; // 2000
        tm.tm_mday = 1;
        tm.tm_hour = 23;
        // SAFETY: `tm` is a live local.
        let ok = unsafe { OPENSSL_gmtime_adj(&mut tm, 0, 3600) };
        assert_eq!(ok, 1);
        assert_eq!(
            (tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour),
            (100, 0, 2, 0)
        );
    }

    /// The difference normalises both parts to one sign, which is the property
    /// `ASN1_TIME_compare` depends on.
    #[test]
    fn diff_has_one_sign() {
        let mut from = zeroed();
        from.tm_year = 100;
        from.tm_mday = 2;
        let mut to = zeroed();
        to.tm_year = 100;
        to.tm_mday = 1;
        to.tm_hour = 23;
        let (mut day, mut sec) = (0, 0);
        // SAFETY: both `tm`s and both outputs are live locals.
        let ok = unsafe { OPENSSL_gmtime_diff(&mut day, &mut sec, &from, &to) };
        assert_eq!(ok, 1);
        // `from` is one hour *after* `to`, and the day part is borrowed from so
        // that both parts carry the same sign rather than `(-1, +82800)`.
        assert_eq!((day, sec), (0, -3600));
    }

    /// A year the calendar cannot express is a failure, not a clamp.
    #[test]
    fn year_10000_is_rejected() {
        let mut tm = zeroed();
        tm.tm_year = 9999 - 1900;
        tm.tm_mday = 31;
        tm.tm_mon = 11;
        // SAFETY: `tm` is a live local.
        let ok = unsafe { OPENSSL_gmtime_adj(&mut tm, 1, 0) };
        assert_eq!(ok, 0);
    }

    /// The layout the exported signatures depend on.
    #[test]
    fn tm_layout_is_glibc() {
        assert_eq!(core::mem::size_of::<Tm>(), 56);
    }
}
