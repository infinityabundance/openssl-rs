/*
 * openssl-rs — B33 probe: borrowed error data must never reach CRYPTO_realloc.
 *
 * The vulnerable external sequence is:
 *
 *     ERR_new();
 *     ERR_set_error_data(borrowed, 0);      // flags 0: the queue does NOT own it
 *     ERR_set_error(lib, reason, fmt, ...); // variadic adapter reuses the slot
 *
 * Before the repair, the adapter detached that slot pointer and passed it to
 * `CRYPTO_realloc` unconditionally (the grow-to-ERR_MAX_DATA_SIZE step), so the
 * caller's borrowed storage was reallocated: invalid free/realloc and UB.
 *
 * After the repair, `openssl_rs_err_take_data` copies borrowed slot data into a
 * fresh seam block, so the adapter only ever reallocs memory the crate owns.
 * The borrowed original must remain readable and unchanged.
 *
 * Modes:
 *   (default)   run the sequence and print the observable result. Exit 0.
 *   --negative  reproduce the pre-fix shape by handing the borrowed pointer to
 *               CRYPTO_realloc directly. This MUST fail (ASan report or libc
 *               abort); it is the negative control, never a supported call.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

/* Deliberately static storage: the error queue does not own it. */
static const char borrowed[] = "borrowed diagnostic text";

int main(int argc, char **argv)
{
    unsigned long e;
    const char *data = NULL;
    int flags = 0;

    if (argc > 1 && strcmp(argv[1], "--negative") == 0) {
        /* The pre-fix adapter shape. No Rust ownership check is performed: the
         * pointer is passed to the allocator as if it were a seam block. */
        void *p = CRYPTO_realloc((void *)borrowed, ERR_MAX_DATA_SIZE, NULL, 0);
        /* A sanitizer or libc must have stopped us before this line. */
        printf("NEGATIVE_CONTROL_DID_NOT_FIRE p=%p\n", p);
        return 3;
    }

    ERR_clear_error();
    ERR_new();
    ERR_set_debug("rt_err_borrowed_data_probe.c", 42, "main");
    ERR_set_error_data((char *)borrowed, 0);
    ERR_set_error(ERR_LIB_CRYPTO, 1, "raised: %s", "ok");

    e = ERR_peek_last_error_all(NULL, NULL, NULL, &data, &flags);
    printf("e=%08lx\n", e);
    printf("data=[%s]\n", data != NULL ? data : "(null)");
    printf("flags=%d\n", flags);
    printf("borrowed=[%s]\n", borrowed);
    ERR_clear_error();
    return 0;
}
