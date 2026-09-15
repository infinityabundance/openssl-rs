//! `crypto/err/err_save.c` — saving and restoring the thread's error queue.
//!
//! ## Why this is a separate file, and why it is small
//!
//! The authority splits it out for the same reason: `err_save.c` manipulates the
//! *whole* `ERR_STATE` structure at once — it moves slots between one state and
//! another, transfers ownership of the attached data buffers, and leaves the
//! source in a defined empty shape. Doing that inside `err.rs` would put
//! structure-level surgery beside the per-error operations and make it much harder
//! to see which one a caller is getting.
//!
//! Everything here is a transcription of `err_save.c` at `openssl-3.6.4` with one
//! structural difference: the authority reaches its thread-local state through
//! `ossl_err_get_state_int()`, which lazily creates it, and this crate reaches the
//! same state through `err::with_state` — the function that already implements
//! exactly that lazy creation. A state that does not exist yet is therefore the
//! `None` arm, which is the same condition the authority's NULL return
//! distinguishes.
//!
//! ## What each of the five does, and the fact that decides it
//!
//! * `OSSL_ERR_STATE_new` — `CRYPTO_zalloc(sizeof(ERR_STATE), NULL, 0)`. Deliberately
//!   **zalloc**, not `OPENSSL_malloc`: the file's own comment says so, to avoid a
//!   malloc-failure loop inside the error path. A fresh state therefore has
//!   `top == bottom == 0` and every `err_line` zero.
//! * `OSSL_ERR_STATE_free` — clears all sixteen slots **with `deall`** so the
//!   attached buffers go with it, then frees the state itself. The `deall`
//!   argument is the whole content of this function: `clear(_, false)` would keep
//!   the buffers.
//! * `OSSL_ERR_STATE_save` — clears the destination *first* (releasing anything it
//!   already held), then **copies the thread state over it whole** and **zeroes the
//!   thread state**. So after a save the caller owns the queue and the thread's is
//!   empty. The clears before the copy look redundant and are not: they are what
//!   releases the destination's previous contents, and a state reused across two
//!   saves would leak without them.
//! * `OSSL_ERR_STATE_save_to_mark` — the partial form: move only the errors pushed
//!   since the last mark, oldest-first, and leave the `bottom` bookkeeping such
//!   that a `restore` puts them back in order. The loop that counts them walks
//!   *down* from `top` while `err_marks[top]` is zero, which is why the count and
//!   the transfer are two separate loops in the original: the first decides how
//!   many, the second moves them from the oldest end.
//! * `OSSL_ERR_STATE_restore` — pushes the saved errors back onto the thread's
//!   queue, **duplicating** the attached data (`CRYPTO_malloc` + `memcpy`) rather
//!   than transferring it, because the argument is `const` and may be restored
//!   more than once. A slot whose `ERR_FLAG_CLEAR` bit is set is skipped, which is
//!   how a lazy clear is honoured across the boundary.

use core::ffi::c_void;

use crate::runtime::err::{
    with_state, ErrState, ERR_FLAG_CLEAR_FLAG, ERR_STATE_SLOTS, ERR_TXT_MALLOCED_FLAG,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The `file`/`line` the authority's `OSSL_ERR_STATE_free` passes to `CRYPTO_free`.
/// They are 0 and NULL in the authority's own source for this allocate/free pair,
/// because it uses the allocator directly rather than the `OPENSSL_free` macro.
const NO_FILE: *const core::ffi::c_char = core::ptr::null();
const NO_LINE: core::ffi::c_int = 0;

/// `ERR_STATE *OSSL_ERR_STATE_new(void)`
///
/// A zeroed state, or NULL when the allocator fails. Zeroed and not initialised:
/// `err_line` is 0 rather than the `-1` a cleared slot carries, because
/// `CRYPTO_zalloc` cannot know that. The difference is unobservable — every path
/// that reads a line number first clears the slot — but it is the authority's
/// shape and is reproduced rather than tidied.
#[no_mangle]
pub extern "C" fn OSSL_ERR_STATE_new() -> *mut ErrState {
    CRYPTO_zalloc(core::mem::size_of::<ErrState>(), NO_FILE, NO_LINE).cast::<ErrState>()
}

/// `void OSSL_ERR_STATE_free(ERR_STATE *es)`
///
/// NULL is a no-op. Otherwise every slot is cleared **with `deall`** — the
/// attached buffers are released — and then the state itself is freed.
///
/// # Safety
/// `es` must be NULL or a pointer returned by `OSSL_ERR_STATE_new` that has not
/// already been freed.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ERR_STATE_free(es: *mut ErrState) {
    if es.is_null() {
        return;
    }
    // SAFETY: `es` is a live state per the caller's contract, and this function is
    // the only place that frees it, so the reference cannot outlive the call.
    unsafe { (*es).clear_all(true) };
    // SAFETY: as above; the pointer came from `CRYPTO_zalloc`.
    unsafe { CRYPTO_free(es.cast::<c_void>(), NO_FILE, NO_LINE) };
}

/// `void OSSL_ERR_STATE_save(ERR_STATE *es)`
///
/// Moves the whole thread queue into `es` and leaves the thread's empty. See the
/// module header for why the destination is cleared first.
///
/// # Safety
/// `es` must be NULL or a live state owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ERR_STATE_save(es: *mut ErrState) {
    if es.is_null() {
        return;
    }
    // SAFETY: `es` is a live state per the caller's contract.
    let dst = unsafe { &mut *es };
    dst.clear_all(true);
    let _ = with_state(|thread_es| {
        // The authority `memcpy`s the structure. Transcribing that structurally is
        // what keeps the ownership transfer exact: the data pointers move with the
        // slots rather than being duplicated, so exactly one state owns each.
        *dst = ErrState::copy_of(thread_es);
        // "Taking over the pointers, just clear the thread state." The authority's
        // comment says "clear" and its code is `memset(thread_es, 0, sizeof(*thread_es))`
        // -- which is *not* the same thing. `clear_all(false)` keeps an owned buffer
        // and truncates it, so the destination and the thread would both own it.
        *thread_es = ErrState::zeroed();
    });
}

/// `void OSSL_ERR_STATE_save_to_mark(ERR_STATE *es)`
///
/// Moves only the errors pushed since the thread queue's last mark, oldest first,
/// and zeroes those slots in the thread state. With no marked error the whole
/// queue moves; with no queue at all the destination is left empty.
///
/// # Safety
/// `es` must be NULL or a live state owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ERR_STATE_save_to_mark(es: *mut ErrState) {
    if es.is_null() {
        return;
    }
    // SAFETY: `es` is a live state per the caller's contract.
    let dst = unsafe { &mut *es };
    let result = with_state(|thread_es| {
        let n = ERR_STATE_SLOTS as i32;
        // Count the unmarked run from `top` downwards.
        let mut count = 0usize;
        let mut top = thread_es.top;
        while thread_es.bottom != top && thread_es.err_marks[top as usize] == 0 {
            count += 1;
            top = if top > 0 { top - 1 } else { n - 1 };
        }
        // Move them, preserving order, from the oldest end.
        let mut j = top;
        for i in 0..count {
            j = (j + 1) % n;
            let (src, target) = (j as usize, i);
            dst.clear(target, true);
            dst.err_flags[target] = thread_es.err_flags[src];
            dst.err_marks[target] = 0;
            dst.err_buffer[target] = thread_es.err_buffer[src];
            dst.err_data[target] = thread_es.err_data[src];
            dst.err_data_size[target] = thread_es.err_data_size[src];
            dst.err_data_flags[target] = thread_es.err_data_flags[src];
            dst.err_file[target] = thread_es.err_file[src];
            dst.err_line[target] = thread_es.err_line[src];
            dst.err_func[target] = thread_es.err_func[src];

            thread_es.err_flags[src] = 0;
            thread_es.err_buffer[src] = 0;
            thread_es.err_data[src] = core::ptr::null_mut();
            thread_es.err_data_size[src] = 0;
            thread_es.err_data_flags[src] = 0;
            thread_es.err_file[src] = core::ptr::null_mut();
            thread_es.err_line[src] = 0;
            thread_es.err_func[src] = core::ptr::null_mut();
        }
        if count > 0 {
            thread_es.top = top;
            dst.top = count as i32 - 1;
            dst.bottom = n - 1;
        } else {
            dst.top = 0;
            dst.bottom = 0;
        }
        // "Erase extra space as a precaution."
        for i in count..ERR_STATE_SLOTS {
            dst.clear(i, true);
        }
    });
    if result.is_none() {
        // No thread state: the destination is emptied and reported as empty, which
        // is the authority's NULL-thread-state arm.
        dst.clear_all(true);
        dst.top = 0;
        dst.bottom = 0;
    }
}

/// `void OSSL_ERR_STATE_restore(const ERR_STATE *es)`
///
/// Pushes the saved errors back onto the thread's queue, **copying** the attached
/// data rather than transferring it, because the argument is `const` and may be
/// restored more than once. A slot whose `ERR_FLAG_CLEAR` bit is set is skipped.
///
/// The loop is transcribed as written, `for (i = es->bottom; i != es->top;)` with
/// the increment first: with `save`'s bookkeeping (`bottom = 15`,
/// `top = count - 1`) that walks exactly `0 .. count - 1`.
///
/// # Safety
/// `es` must be NULL or point to a live state. It is only read.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ERR_STATE_restore(es: *const ErrState) {
    if es.is_null() {
        return;
    }
    // SAFETY: `es` is a live state per the caller's contract and is only read here.
    let src = unsafe { &*es };
    if src.bottom == src.top {
        return;
    }
    let _ = with_state(|thread_es| {
        let n = ERR_STATE_SLOTS as i32;
        let mut i = src.bottom;
        while i != src.top {
            i = (i + 1) % n;
            let from = i as usize;
            if (src.err_flags[from] & ERR_FLAG_CLEAR_FLAG) != 0 {
                continue;
            }
            thread_es.get_slot();
            let top = thread_es.top as usize;
            thread_es.clear(top, false);

            thread_es.err_flags[top] = src.err_flags[from];
            thread_es.err_buffer[top] = src.err_buffer[from];
            thread_es.set_debug(
                top,
                src.err_file[from],
                src.err_line[from],
                src.err_func[from],
            );

            if !src.err_data[from].is_null() && src.err_data_size[from] != 0 {
                let size = src.err_data_size[from];
                let copy = crate::runtime::mem::CRYPTO_malloc(size, NO_FILE, NO_LINE);
                if !copy.is_null() {
                    // SAFETY: `copy` is a fresh allocation of `size` bytes and the
                    // source holds at least that many, per its own size field.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            src.err_data[from].cast::<u8>(),
                            copy.cast::<u8>(),
                            size,
                        )
                    };
                    thread_es.set_data(
                        top,
                        copy.cast(),
                        size,
                        src.err_data_flags[from] | ERR_TXT_MALLOCED_FLAG,
                    );
                }
            } else {
                thread_es.clear_data(top, false);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::err::{
        raise_with, ERR_clear_error, ERR_get_error, ERR_peek_error, ERR_pop_to_mark, ERR_set_mark,
    };

    /// Raise `n` distinguishable errors, oldest first.
    fn raise_n(n: usize) {
        ERR_clear_error();
        for i in 0..n {
            // SAFETY: the site is a static and the file pointer is NULL.
            unsafe { raise_with(1, (i + 1) as i32, core::ptr::null(), 0) };
        }
    }

    #[test]
    fn a_new_state_is_empty_and_free_accepts_null() {
        let es = OSSL_ERR_STATE_new();
        assert!(!es.is_null());
        // SAFETY: `es` is a fresh state.
        unsafe {
            assert_eq!((*es).top, 0);
            assert_eq!((*es).bottom, 0);
            OSSL_ERR_STATE_free(es);
            OSSL_ERR_STATE_free(core::ptr::null_mut());
        }
    }

    #[test]
    fn save_moves_the_queue_and_leaves_the_thread_empty() {
        raise_n(3);
        let es = OSSL_ERR_STATE_new();
        // SAFETY: `es` is live.
        unsafe { OSSL_ERR_STATE_save(es) };
        // The thread queue is empty afterwards, which is the whole point of save.
        assert_eq!(ERR_peek_error(), 0);
        // SAFETY: `es` still holds the three errors; the ring is read through
        // `restore`, which is the only public way back.
        unsafe {
            OSSL_ERR_STATE_restore(es);
            assert_ne!(ERR_peek_error(), 0);
            // Restoring again is legal, because restore copies: the saved state is
            // `const` and keeps its own buffers.
            ERR_clear_error();
            OSSL_ERR_STATE_restore(es);
            // The errors come back in order, oldest first. `pack(lib, reason)` is
            // `(lib << 23) | reason`, so the first of the three raised with
            // library 1 is `0x80_0001`.
            assert_eq!(ERR_peek_error(), 0x80_0001);
            assert_eq!(ERR_get_error(), 0x80_0001);
            assert_eq!(ERR_get_error(), 0x80_0002);
            assert_eq!(ERR_get_error(), 0x80_0003);
            assert_eq!(ERR_get_error(), 0);
            ERR_clear_error();
            OSSL_ERR_STATE_free(es);
        }
    }

    #[test]
    fn a_state_reused_across_a_clear_survives_a_second_save() {
        // The probe's sequence, which is what found the defect this test exists to
        // pin: `es` is filled, restored twice with an `ERR_clear_error` between,
        // and then used again. `ERR_clear_error` clears with `deall = false`, so
        // the slots keep their buffers -- which is what makes the reuse the
        // interesting case.
        raise_n(3);
        let es = OSSL_ERR_STATE_new();
        // SAFETY: `es` is live for the whole test.
        unsafe {
            OSSL_ERR_STATE_save(es);
            OSSL_ERR_STATE_restore(es);
            ERR_clear_error();
            OSSL_ERR_STATE_restore(es);
            ERR_clear_error();

            raise_with(1, 1, core::ptr::null(), 0);
            ERR_set_mark();
            raise_with(1, 2, core::ptr::null(), 0);
            raise_with(1, 3, core::ptr::null(), 0);
            OSSL_ERR_STATE_save_to_mark(es);
            assert_eq!(ERR_peek_error(), 0x80_0001);
            ERR_pop_to_mark();
            OSSL_ERR_STATE_restore(es);
            assert_eq!(ERR_get_error(), 0x80_0001);
            ERR_clear_error();
            OSSL_ERR_STATE_free(es);
        }
    }

    #[test]
    fn save_to_mark_moves_only_what_is_above_the_mark() {
        raise_n(2);
        assert_eq!(ERR_set_mark(), 1);
        // Two more on top of the mark.
        // SAFETY: the site is a static and the file pointer is NULL.
        unsafe {
            raise_with(1, 10, core::ptr::null(), 0);
            raise_with(1, 11, core::ptr::null(), 0);
        }
        let es = OSSL_ERR_STATE_new();
        // SAFETY: `es` is live.
        unsafe { OSSL_ERR_STATE_save_to_mark(es) };
        // The two marked errors are still on the thread's queue and the two above
        // them moved, so the thread's oldest is still reason 1.
        assert_eq!(ERR_peek_error(), 0x80_0001);
        // `ERR_pop_to_mark` stops *at* the marked slot -- which is the top one, not
        // the oldest -- and unmarks it, so both marked errors stay in the queue and
        // the oldest is still reason 1.
        ERR_pop_to_mark();
        assert_eq!(ERR_peek_error(), 0x80_0001);

        // SAFETY: `es` holds the two errors that were above the mark. `restore`
        // **pushes** them onto the thread's queue, so the thread's older errors are
        // still in front of them; they are reached by draining.
        unsafe {
            OSSL_ERR_STATE_restore(es);
            assert_eq!(ERR_get_error(), 0x80_0001);
            assert_eq!(ERR_get_error(), 0x80_0002);
            assert_eq!(ERR_get_error(), 0x80_000a);
            assert_eq!(ERR_get_error(), 0x80_000b);
            assert_eq!(ERR_get_error(), 0);
            ERR_clear_error();
            OSSL_ERR_STATE_free(es);
        }
    }
}
