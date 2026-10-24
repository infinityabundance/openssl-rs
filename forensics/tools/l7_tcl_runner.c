/*
 * Phase-25 L7 workload runner for the TclTLS family.
 *
 * TclTLS ships a loadable Tcl module, not an executable. This runner embeds the
 * Tcl interpreter that the family's own configure discovered, exposes the
 * arguments as `argv`/`argc`, and evaluates the admitted workload script.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <tcl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef L7_SCRIPT_PATH
#define L7_SCRIPT_PATH ""
#endif
#ifndef L7_TCL_LIBRARY
#define L7_TCL_LIBRARY ""
#endif
#ifndef L7_TCL_TMLIB
#define L7_TCL_TMLIB ""
#endif

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("tcltls-l7-harness");
        return 0;
    }
    if (argc < 5) {
        fprintf(stderr, "usage: %s ROOT PORT CA OTHER_CA\n", argv[0]);
        return 2;
    }
    if (L7_TCL_LIBRARY[0])
        setenv("TCL_LIBRARY", L7_TCL_LIBRARY, 1);
    if (L7_TCL_TMLIB[0])
        setenv("TCLLIBPATH", L7_TCL_TMLIB, 1);

    Tcl_FindExecutable(argv[0]);
    Tcl_Interp *interp = Tcl_CreateInterp();
    if (Tcl_Init(interp) != TCL_OK) {
        fprintf(stderr, "tcl init failed: %s\n", Tcl_GetStringResult(interp));
        return 3;
    }
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    for (int i = 1; i < argc; i++)
        Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(argv[i], -1));
    Tcl_SetVar2Ex(interp, "argv", NULL, list, TCL_GLOBAL_ONLY);
    Tcl_SetVar2Ex(interp, "argc", NULL, Tcl_NewIntObj(argc - 1), TCL_GLOBAL_ONLY);

    int rc = Tcl_EvalFile(interp, L7_SCRIPT_PATH);
    if (rc != TCL_OK)
        fprintf(stderr, "tcl workload failed: %s\n", Tcl_GetStringResult(interp));
    Tcl_Finalize();
    return rc == TCL_OK ? 0 : 1;
}
