/*
 * 24.10 hostility probe: the **legacy ENGINE** surface — the built-in ENGINE registry, the dynamic
 * ENGINE binding, and an ENGINE control command. The candidate's reduced distribution disables the
 * legacy engine modules, so this is the surface most likely to diverge; the probe records it rather
 * than assuming it, and the court records the disposition honestly.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/engine.h>

int main(void)
{
    hostility_banner("engine-legacy");
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    int count = 0;
    ENGINE *e;
    for (e = ENGINE_get_first(); e != NULL; e = ENGINE_get_next(e)) {
        const char *id = ENGINE_get_id(e);
        if (id != NULL && count < 8)
            printf("engine[%d]=%s\n", count, id);
        count++;
    }
    printf("engine_count=%d\n", count);

    ENGINE *dyn = ENGINE_by_id("dynamic");
    if (dyn != NULL) {
        printf("dynamic_ctrl_so_path=%d\n",
               ENGINE_ctrl_cmd_string(dyn, "SO_PATH", "/nonexistent-hostility.so", 0));
        ENGINE_free(dyn);
    } else {
        printf("dynamic_ctrl_so_path=-1\n");
    }
    hostility_ok();
    return 0;
}
