/*
 * S33: an embedded-Perl runner for the Perl XS consumer families.
 *
 * The family's XS module is linked with -Wl,--no-as-needed, so the process's own
 * dynamic closure contains the module and (transitively) the subject libssl/libcrypto.
 * The admitted workload is the Perl script named by L7_SCRIPT_PATH; every fixture path
 * is passed through as a normal @ARGV element.  This is the Perl analogue of
 * l7_lua_runner.c.
 */
#include <EXTERN.h>
#include <perl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef L7_NAME
#define L7_NAME "perl-l7-harness"
#endif
#ifndef L7_SCRIPT_PATH
#error "L7_SCRIPT_PATH must name the Perl workload"
#endif

EXTERN_C void boot_DynaLoader(pTHX_ CV *cv);

EXTERN_C void xs_init(pTHX)
{
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);
}

int main(int argc, char **argv, char **env)
{
    PerlInterpreter *my_perl;
    int rc;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("%s\n", L7_NAME);
        return 0;
    }

    PERL_SYS_INIT3(&argc, &argv, &env);
    my_perl = perl_alloc();
    if (my_perl == NULL) {
        fprintf(stderr, "perl allocation failed\n");
        return 2;
    }
    perl_construct(my_perl);

    {
        char **args = (char **)calloc((size_t)argc + 1, sizeof(char *));
        if (args == NULL) {
            perl_destruct(my_perl);
            perl_free(my_perl);
            return 2;
        }
        args[0] = (char *)"perl";
        for (int i = 1; i < argc; i++)
            args[i] = argv[i];
        rc = perl_parse(my_perl, xs_init, argc, args, NULL);
        if (rc == 0)
            rc = perl_run(my_perl);
        free(args);
    }

    PL_perl_destruct_level = 1;
    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SYS_TERM();
    return rc == 0 ? 0 : 2;
}
