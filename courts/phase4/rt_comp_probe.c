/*
 * openssl-rs — RT-COMP: the eighteen Phase 4 exports that 6.0's ownership
 * reconciliation found unaccounted for, and which 6.3 implemented.
 *
 * Three families, and each has a different reachability story, which is why the
 * probe is explicit about what it does *not* call.
 *
 *   * `COMP_*` — the public compression-object API. The pinned profile is
 *     configured `no-zlib no-zstd no-brotli`, so all six factories answer NULL and
 *     every context-taking function is unreachable through the public ABI: the only
 *     other public source of a `COMP_METHOD` is libssl's
 *     `SSL_COMP_get_compression_methods`, whose entries all hold a NULL method
 *     because TLS compression was removed in 3.0. So this probe compares the
 *     NULL-tolerant surface and nothing else, and the seal records which four
 *     exports no consumer in this profile can reach.
 *   * `OPENSSL_config` — the deprecated automatic loader. Its whole body is a
 *     settings object and a call into `OPENSSL_init_crypto`, so what is observable
 *     is that it returns and what it leaves on the error queue.
 *   * `conf_ssl_*` — the `ssl_conf` module's accessors. Only
 *     `conf_ssl_name_find` is reachable before that module has been initialised;
 *     the other two index into a store that is empty until it runs. The module's
 *     registration is Phase 6.9's, because it needs `CONF_module_add`.
 *
 * NOT CALLED, because the authority faults and the divergence is recorded rather
 * than reproduced (docs/SECURITY_DIVERGENCE_POLICY.md):
 *
 *   COMP_CTX_get_type(NULL)     -- dereferences comp->meth without checking comp
 *   COMP_CTX_get_method(NULL)   -- dereferences ctx
 *   COMP_compress_block(NULL,..) -- dereferences ctx
 *   COMP_expand_block(NULL,..)   -- dereferences ctx
 *   conf_ssl_get(...)            -- indexes a NULL store
 *   conf_ssl_get_cmd(...)        -- indexes whatever it is given
 *
 * `conf_ssl_name_find` IS called, with an empty store, because it is the one that
 * is both reachable and NULL-tolerant.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/comp.h>
#include <openssl/err.h>

#include <openssl/objects.h>

/*
 * `crypto/conf/conf_local.h` is not installed, so these three have no declaration
 * in the public surface. The prototypes are the authority's own, transcribed from
 * that header; `conf_ssl.c` declares the structures it hands out but nothing
 * outside lcrypto ever dereferences them.
 */
struct ssl_conf_cmd_st;
const struct ssl_conf_cmd_st *conf_ssl_get(size_t idx, const char **name,
                                          size_t *cnt);
int conf_ssl_name_find(const char *name, size_t *idx);
void conf_ssl_get_cmd(const struct ssl_conf_cmd_st *cmd, size_t idx,
                      char **cmdstr, char **arg);

static void comp_factories(void)
{
    COMP_METHOD *z = COMP_zlib();
    COMP_METHOD *zo = COMP_zlib_oneshot();
    COMP_METHOD *s = COMP_zstd();
    COMP_METHOD *so = COMP_zstd_oneshot();
    COMP_METHOD *b = COMP_brotli();
    COMP_METHOD *bo = COMP_brotli_oneshot();

    printf("COMP_zlib=%s\n", z == NULL ? "<NULL>" : "<METHOD>");
    printf("COMP_zlib_oneshot=%s\n", zo == NULL ? "<NULL>" : "<METHOD>");
    printf("COMP_zstd=%s\n", s == NULL ? "<NULL>" : "<METHOD>");
    printf("COMP_zstd_oneshot=%s\n", so == NULL ? "<NULL>" : "<METHOD>");
    printf("COMP_brotli=%s\n", b == NULL ? "<NULL>" : "<METHOD>");
    printf("COMP_brotli_oneshot=%s\n", bo == NULL ? "<NULL>" : "<METHOD>");
}

static void comp_null_contracts(void)
{
    printf("COMP_get_type(NULL)=%d\n", COMP_get_type(NULL));
    printf("COMP_get_type(NULL)_is_nid_undef=%d\n",
           COMP_get_type(NULL) == NID_undef);
    printf("COMP_get_name(NULL)=%s\n",
           COMP_get_name(NULL) == NULL ? "<NULL>" : COMP_get_name(NULL));
    printf("COMP_CTX_new(NULL)=%s\n",
           COMP_CTX_new(NULL) == NULL ? "<NULL>" : "<CTX>");
    /* Defined and harmless, which is not true of every NULL in this API. */
    COMP_CTX_free(NULL);
    printf("COMP_CTX_free(NULL)=returned\n");
}

static void conf_ssl_plane(void)
{
    size_t idx = (size_t)-1;
    int r;

    r = conf_ssl_name_find(NULL, &idx);
    printf("name_find(NULL)=%d\n", r);
    printf("name_find(NULL)_idx_untouched=%d\n", idx == (size_t)-1);

    idx = (size_t)-1;
    r = conf_ssl_name_find("SECLEVEL", &idx);
    printf("name_find_empty_store=%d\n", r);
    printf("name_find_empty_store_idx_untouched=%d\n", idx == (size_t)-1);

    idx = (size_t)-1;
    r = conf_ssl_name_find("", &idx);
    printf("name_find_empty_name=%d\n", r);
}

static void openssl_config_plane(void)
{
    ERR_clear_error();
    OPENSSL_config(NULL);
    printf("OPENSSL_config(NULL)=returned\n");
    printf("OPENSSL_config(NULL)_errors=%lu\n", ERR_peek_error());

    ERR_clear_error();
    OPENSSL_config("openssl-rs-rt-comp");
    printf("OPENSSL_config(appname)=returned\n");
    printf("OPENSSL_config(appname)_errors=%lu\n", ERR_peek_error());

    /*
     * The build-independent half of `OPENSSL_info`, which `crypto/info.c` answers
     * from compile-time platform facts and which both sides must therefore agree
     * on exactly.
     */
    printf("info_dso_extension=%s\n", OPENSSL_info(OPENSSL_INFO_DSO_EXTENSION));
    printf("info_dir_separator=%s\n",
           OPENSSL_info(OPENSSL_INFO_DIR_FILENAME_SEPARATOR));
    printf("info_list_separator=%s\n",
           OPENSSL_info(OPENSSL_INFO_LIST_SEPARATOR));

    /*
     * The build-dependent half, which is NOT printed, and which this probe found.
     *
     * `OPENSSL_info(OPENSSL_INFO_CONFIG_DIR)` answers the authority's own
     * `--openssldir`, a forensic-build path this candidate deliberately does not
     * claim -- the same divergence `RT-CONF` records for
     * `CONF_get1_default_config_file` under `OBL-CONF-DEFAULT-CONFIG-FILE`
     * (Phase 16), reached here by a second route. Both sides print the label
     * instead, which is the idiom `RT-CONF` and `RT-LHASH` already use for a
     * boundary they cannot compare. The finding worth noting is that
     * `src/runtime/init.rs`'s `OPENSSL_info` answers NULL for this code where the
     * authority answers a path, so the *non-nullness* is not comparable either --
     * a decision recorded in `docs/DECISIONS.md` D100 rather than left in a probe
     * comment.
     */
    printf("info_config_dir=RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE\n");
    printf("info_engines_dir=RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE\n");
    printf("info_modules_dir=RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE\n");
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    comp_factories();
    comp_null_contracts();
    conf_ssl_plane();
    openssl_config_plane();
    printf("done=1\n");
    return 0;
}
