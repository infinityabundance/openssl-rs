/*
 * l7_prosody.c — the admitted L7 workload program for the prosody family.
 *
 * Prosody is a Lua program; its OpenSSL consumer is LuaSec, a Lua C module loaded by the running
 * server.  This harness embeds the pinned Lua 5.4 interpreter, exposes the conventional `arg`
 * table, and runs prosody's own `prosody` / `prosodyctl` entry script unchanged.  Linking this
 * program against the subject libssl/libcrypto (and LuaSec, built by the recipe against the same
 * prefix) makes the load proof resolve the subject libraries, while the server and its TLS
 * listener are prosody's own code path — no protocol is re-implemented here.
 *
 * `--version` reports the harness identity so the runtime atlas can prove the program started.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <openssl/ssl.h>

int main(int argc, char **argv) {
    /* The harness itself is a consumer of the subject OpenSSL: it binds the subject libssl and
     * libcrypto explicitly so the load proof resolves them (LuaSec's module is loaded later by
     * prosody).  The call has no other effect. */
    if (TLS_method() == NULL) {
        fputs("no TLS method from the subject libssl\n", stderr);
        return 2;
    }
    (void)OpenSSL_version_num();

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        puts("prosody-l7-harness 0.12.4");
        return 0;
    }

    const char *root = getenv("PROSODY_SRCDIR");
    const char *entry = getenv("PROSODY_ENTRY");
    if (!entry || !*entry)
        entry = "prosody";
    if (!root || !*root) {
        fputs("PROSODY_SRCDIR is not set\n", stderr);
        return 2;
    }

    char script[4096];
    int n = snprintf(script, sizeof script, "%s/%s", root, entry);
    if (n < 0 || (size_t)n >= sizeof script) {
        fputs("prosody entry path is too long\n", stderr);
        return 2;
    }

    lua_State *L = luaL_newstate();
    if (!L) {
        fputs("luaL_newstate failed\n", stderr);
        return 2;
    }
    luaL_openlibs(L);

    lua_createtable(L, argc, 1);
    lua_pushstring(L, entry);
    lua_rawseti(L, -2, 0);
    for (int i = 1; i < argc; i++) {
        lua_pushstring(L, argv[i]);
        lua_rawseti(L, -2, i);
    }
    lua_setglobal(L, "arg");

    if (luaL_loadfile(L, script) != LUA_OK || lua_pcall(L, 0, 0, 0) != LUA_OK) {
        fprintf(stderr, "%s\n", lua_tostring(L, -1));
        lua_close(L);
        return 1;
    }

    lua_close(L);
    return 0;
}
