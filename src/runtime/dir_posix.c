/*
 * openssl-rs — the directory and file-status syscalls, kept on the C side of
 * the ABI.
 *
 * Why this file exists
 * --------------------
 * `crypto/LPdir_unix.c` reads a directory entry through `struct dirent`, and
 * `crypto/conf/conf_def.c` asks whether an include target is a directory through
 * `struct stat`. Both layouts are the platform's business: `d_name`'s offset
 * inside `struct dirent` and `st_mode`'s offset inside `struct stat` are not
 * something a compatibility implementation may assume, and an assumed offset
 * that happens to be right on one libc is exactly the kind of silent divergence
 * this project exists to avoid.
 *
 * So the two structs are read here, by the same headers the authority compiled
 * against, and only the answers cross into Rust: a directory stream handle, a
 * NUL-terminated entry name, and a three-state file-status result.
 *
 * Nothing behavioural lives here. `OPENSSL_DIR_read`, `OPENSSL_DIR_end` and the
 * `stat` decision that `process_include` makes are decided in Rust; this file
 * only performs the syscall and reports what the kernel and the libc said,
 * including `errno`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>

/*
 * `opendir` returns a `DIR *`, which is opaque to this project; it crosses the
 * boundary as `void *` and comes back unchanged.
 */
void *openssl_rs_dir_open(const char *path)
{
    return (void *)opendir(path);
}

/*
 * One `readdir` step. Returns the entry name (valid until the next call on the
 * same stream, exactly as `readdir` specifies) or NULL at end of directory or on
 * error, in which case `errno` is whatever `readdir` left in it. `*err` carries
 * it across the ABI so the Rust side does not have to re-read the thread's
 * `errno` through a second call that could clobber it.
 */
const char *openssl_rs_dir_next(void *dir, int *err)
{
    struct dirent *entry = readdir((DIR *)dir);

    if (entry == NULL) {
        *err = errno;
        return NULL;
    }
    return entry->d_name;
}

int openssl_rs_dir_close(void *dir)
{
    return closedir((DIR *)dir);
}

/*
 * The three-state status `process_include` needs.
 *
 *   -1  `stat` failed; `*err` holds `errno`
 *    0  `stat` succeeded and the path is not a directory
 *    1  `stat` succeeded and the path is a directory
 *
 * `S_ISDIR` is used rather than a mode comparison because the macro is what the
 * authority uses and the encoding is not uniform across platforms.
 */
int openssl_rs_stat_is_dir(const char *path, int *err)
{
    struct stat st;

    if (stat(path, &st) < 0) {
        *err = errno;
        return -1;
    }
    *err = 0;
    return S_ISDIR(st.st_mode) ? 1 : 0;
}
