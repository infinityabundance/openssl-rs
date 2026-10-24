/*
 * Phase-25 L7 workload runner for the Python binding families.
 *
 * The binding (py-scrypt, M2Crypto) is a loadable extension, not an executable.
 * This runner embeds CPython, exposes the caller's arguments as sys.argv and
 * evaluates the admitted workload script. The binary links the subject
 * libssl/libcrypto directly, so the L5 load proof resolves them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef L7_SCRIPT_PATH
#define L7_SCRIPT_PATH ""
#endif

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("py-l7-harness");
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: %s ROOT [args...]\n", argv[0]);
        return 2;
    }
    wchar_t *prog = Py_DecodeLocale(argv[0], NULL);
    if (prog)
        Py_SetProgramName(prog);
    Py_Initialize();

    char **pyargv = calloc((size_t) argc + 1, sizeof(char *));
    if (!pyargv)
        return 3;
    pyargv[0] = (char *) L7_SCRIPT_PATH;
    for (int i = 1; i < argc; i++)
        pyargv[i] = argv[i];
    PySys_SetArgv(argc, pyargv);

    FILE *fp = fopen(L7_SCRIPT_PATH, "r");
    if (!fp) {
        fprintf(stderr, "cannot open %s\n", L7_SCRIPT_PATH);
        Py_Finalize();
        return 3;
    }
    int rc = PyRun_SimpleFile(fp, L7_SCRIPT_PATH);
    fclose(fp);
    Py_Finalize();
    return rc == 0 ? 0 : 1;
}
