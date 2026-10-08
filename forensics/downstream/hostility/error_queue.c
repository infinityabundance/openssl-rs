/*
 * 24.10 hostility probe: **error-queue lifetime** — the mark/pop protocol, an error raised by a
 * failing fetch and read back with the 3.0 `ERR_get_error_all` form, the library/reason strings, and
 * the clear. The error queue is a thread-local contract the counted families' union does not reach.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"

int main(void)
{
    hostility_banner("error-queue");
    ERR_clear_error();

    ERR_set_mark();
    unsigned long peeked = ERR_peek_last_error();
    printf("after_mark_peek=%lu\n", peeked);
    int popped = ERR_pop_to_mark();
    printf("pop_to_mark=%d\n", popped);
    ERR_clear_error();

    EVP_MD *md = EVP_MD_fetch(NULL, "NO-SUCH-DIGEST-XYZ", NULL);
    printf("bogus_fetch_null=%d\n", md == NULL);

    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0;
    unsigned long code = ERR_get_error_all(&file, &line, &func, &data, &flags);
    printf("raised_error=%d\n", code != 0);

    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    printf("err_string_len=%d\n", (int)strlen(buf));
    const char *lib = ERR_lib_error_string(code);
    const char *reason = ERR_reason_error_string(code);
    printf("err_lib=%s\n", lib != NULL ? lib : "(null)");
    printf("err_reason=%s\n", reason != NULL ? reason : "(null)");
    printf("err_lib_known=%d\n", ERR_lib_error_string(code) != NULL);

    ERR_clear_error();
    printf("cleared_peek=%lu\n", ERR_peek_last_error());
    hostility_ok();
    return 0;
}
