// PFP-59 audit firing control.
//
// Two functions built with the same toolchain and optimisation level as the
// carrier. `pfp59_audit_canary` branches on its argument (a value-dependent
// conditional transfer); `pfp59_audit_ct` is the branchless mask form. The
// audit's classifier must report the first and not the second, which shows the
// instrument is sensitive on the same run that clears the carrier.

#[no_mangle]
pub fn pfp59_audit_canary(x: u64) -> u64 {
    let mut s = 0u64;
    let mut i = 0u64;
    let n = x & 15;
    while i < n {
        s = s.wrapping_add(i);
        i += 1;
    }
    s
}

#[no_mangle]
pub fn pfp59_audit_ct(x: u64, y: u64) -> u64 {
    // mask = -1 when x < y, 0 otherwise; no branch.
    let lt = ((x.wrapping_sub(y)) >> 63) & 1;
    let mask = 0u64.wrapping_sub(lt);
    (x & mask) | (y & !mask)
}
