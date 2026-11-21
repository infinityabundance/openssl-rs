/*
 * map_probe.c — O5: report the libcrypto a process actually mapped.
 *
 * OpenSSH's sshd and ssh-agent mark themselves non-dumpable, so another process
 * cannot read /proc/<pid>/maps for them (observed: EACCES on this host). The
 * process itself can, so this constructor writes its own matches to the file
 * named by MAP_PROBE_OUT before main() runs. The binary, the loader, the
 * LD_LIBRARY_PATH and the mapped object are therefore all the real ones; only
 * the observation moved inside.
 *
 * Exit status of the probed binary is irrelevant to the probe and is not used:
 * a usage message still maps the library.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((constructor)) static void map_probe(void)
{
    const char *out = getenv("MAP_PROBE_OUT");
    if (out == NULL || *out == '\0')
        return;

    FILE *maps = fopen("/proc/self/maps", "r");
    FILE *rec = fopen(out, "a");
    if (maps == NULL || rec == NULL) {
        if (maps != NULL)
            fclose(maps);
        if (rec != NULL)
            fclose(rec);
        return;
    }
    char line[8192];
    while (fgets(line, sizeof line, maps) != NULL) {
        if (strstr(line, "libcrypto") != NULL)
            fputs(line, rec);
    }
    fclose(maps);
    fclose(rec);
}
