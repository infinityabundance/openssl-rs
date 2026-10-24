/*
 * tcl-tls L7 workload: embed Tcl 8.6 and run the admitted TclTLS client script.
 *
 * The interpreter is linked against the pinned Tcl 8.6 runtime; the script's first job is
 * `load <rebuilt tcltls.so> Tls`, so the process's dynamic closure contains the TclTLS
 * module and, transitively, the subject libssl/libcrypto.  Fixture paths are passed as
 * ordinary global variables; the workload logic lives in l7_tcl.tcl.
 */
#include <tcl.h>

#include <stdio.h>
#include <string.h>

#ifndef L7_SCRIPT_PATH
#error "L7_SCRIPT_PATH must name the Tcl workload"
#endif

int main(int argc, char **argv)
{
    Tcl_Interp *interp;
    int rc;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("tcltls-l7-harness\n");
        return 0;
    }
    if (argc < 5) {
        fprintf(stderr, "usage: %s TCLTLS.SO CA OTHER PORT\n", argv[0]);
        return 2;
    }

    Tcl_FindExecutable(argv[0]);
    interp = Tcl_CreateInterp();
    if (interp == NULL) {
        fprintf(stderr, "tcl interpreter allocation failed\n");
        return 2;
    }
    if (Tcl_Init(interp) != TCL_OK) {
        fprintf(stderr, "tcl init: %s\n", Tcl_GetStringResult(interp));
        Tcl_DeleteInterp(interp);
        return 2;
    }

    Tcl_SetVar(interp, "tcltls_so", argv[1], TCL_GLOBAL_ONLY);
    Tcl_SetVar(interp, "tcltls_ca", argv[2], TCL_GLOBAL_ONLY);
    Tcl_SetVar(interp, "tcltls_other", argv[3], TCL_GLOBAL_ONLY);
    Tcl_SetVar(interp, "tcltls_port", argv[4], TCL_GLOBAL_ONLY);

    rc = Tcl_EvalFile(interp, L7_SCRIPT_PATH);
    if (rc != TCL_OK) {
        fprintf(stderr, "tcl workload failed: %s\n", Tcl_GetStringResult(interp));
        Tcl_DeleteInterp(interp);
        Tcl_Finalize();
        return 2;
    }
    Tcl_DeleteInterp(interp);
    Tcl_Finalize();
    return 0;
}
