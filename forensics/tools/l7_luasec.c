/*
 * lua-sec L7 workload: a loopback TLS server (subject libssl) plus the LuaSec client script.
 *
 * The server is started first and its ephemeral port is handed to the script. The script uses
 * LuaSec to complete a TLS1.3 handshake with peer verification against --ca, sends a payload and
 * reads the echoed line. With an unrelated CA the handshake fails and the script prints
 * `negative=rejected`.
 */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "l7_local_tls.h"

#ifndef L7_SCRIPT_PATH
#error "L7_SCRIPT_PATH must name the Lua workload"
#endif
#ifndef L7_LUA_PATH
#define L7_LUA_PATH ""
#endif
#ifndef L7_LUA_CPATH
#define L7_LUA_CPATH ""
#endif

static int echo_handler(SSL *ssl, void *arg)
{
    char line[256];
    size_t used = 0;
    (void)arg;
    while (used + 1 < sizeof(line)) {
        char c;
        if (!l7_read_full(ssl, &c, 1))
            return -1;
        line[used++] = c;
        if (c == '\n')
            break;
    }
    line[used] = '\0';
    if (strcmp(line, "phase25-l7-luasec-ping\n") != 0)
        return -1;
    return l7_write_all(ssl, "phase25-l7-luasec-pong\n", 24) ? 0 : -1;
}

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
    const char *cert = NULL, *key = NULL, *ca = NULL;
    l7_tls_server server;
    lua_State *L;
    int rc;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("luasec-l7-harness\n");
            return 0;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca = argv[++i];
        }
    }
    if (cert == NULL || key == NULL || ca == NULL) {
        fprintf(stderr, "usage: %s --cert CRT --key KEY --ca CA\n", argv[0]);
        return 2;
    }
    if (l7_tls_server_start(&server, cert, key, echo_handler, NULL, 1) != 0) {
        fprintf(stderr, "the local TLS listener did not start\n");
        return 2;
    }

    L = luaL_newstate();
    if (L == NULL) {
        l7_tls_server_stop(&server);
        return 2;
    }
    luaL_openlibs(L);
    set_package_field(L, "path", L7_LUA_PATH);
    set_package_field(L, "cpath", L7_LUA_CPATH);
    lua_createtable(L, 2, 1);
    lua_pushstring(L, ca);
    lua_rawseti(L, -2, 1);
    lua_pushinteger(L, server.port);
    lua_rawseti(L, -2, 2);
    lua_setglobal(L, "arg");

    rc = luaL_dofile(L, L7_SCRIPT_PATH);
    if (rc != LUA_OK) {
        fprintf(stderr, "lua workload failed: %s\n", lua_tostring(L, -1));
        lua_close(L);
        l7_tls_server_stop(&server);
        return 2;
    }
    lua_close(L);
    l7_tls_server_stop(&server);
    return 0;
}
