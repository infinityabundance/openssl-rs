/*
 * A tiny Lua 5.4 runner for the two Lua module families (lua-luaossl, lua-sec).
 *
 * The admitted workload is the Lua script named by L7_SCRIPT_PATH. The runner is linked against
 * the module under test with -Wl,--no-as-needed, so the process's own dynamic closure contains the
 * module and the subject libssl/libcrypto. It exports `arg` in the normal Lua convention.
 */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef L7_NAME
#define L7_NAME "lua-l7-harness"
#endif
#ifndef L7_SCRIPT_PATH
#error "L7_SCRIPT_PATH must name the Lua workload"
#endif
#ifndef L7_LUA_PATH
#define L7_LUA_PATH ""
#endif
#ifndef L7_LUA_CPATH
#define L7_LUA_CPATH ""
#endif

static void set_package_field(lua_State *L, const char *field, const char *value)
{
    lua_getglobal(L, "package");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    lua_getfield(L, -1, field);
    const char *current = lua_tostring(L, -1);
    lua_pop(L, 1);
    char joined[8192];
    snprintf(joined, sizeof(joined), "%s;%s", value, current ? current : "");
    lua_pushstring(L, joined);
    lua_setfield(L, -2, field);
    lua_pop(L, 1);
}

int main(int argc, char **argv)
{
    lua_State *L;
    int rc;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("%s\n", L7_NAME);
        return 0;
    }

    L = luaL_newstate();
    if (L == NULL) {
        fprintf(stderr, "lua state creation failed\n");
        return 2;
    }
    luaL_openlibs(L);
    set_package_field(L, "path", L7_LUA_PATH);
    set_package_field(L, "cpath", L7_LUA_CPATH);

    lua_createtable(L, argc, 1);
    for (int i = 0; i < argc; i++) {
        lua_pushstring(L, argv[i]);
        lua_rawseti(L, -2, i);
    }
    lua_setglobal(L, "arg");

    rc = luaL_dofile(L, L7_SCRIPT_PATH);
    if (rc != LUA_OK) {
        fprintf(stderr, "lua workload failed: %s\n", lua_tostring(L, -1));
        lua_close(L);
        return 2;
    }
    lua_close(L);
    return 0;
}
