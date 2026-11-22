/*
 * subreaper.c — reap orphans so a container's PID 1 cannot stall the harness.
 *
 * In the court container PID 1 does not reap orphaned descendants. OpenSSH's
 * `agent-subprocess` test backgrounds an `ssh-agent`, kills it, and then polls
 * `kill -0`; a dead-but-unreaped agent answers `kill -0` successfully, so the
 * test keeps "agent still running" until it times out and fails. The 96-script
 * matrix run used an untracked helper for exactly this; it is tracked here so
 * the reproduction does not depend on a file in someone's work directory.
 *
 * Behaviour: become a child subreaper, fork the command, and reap *every*
 * child until the command itself exits, returning its status. No signal
 * handling is installed, so the command's own signal disposition is untouched.
 *
 * Usage: subreaper <command> [args...]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 2;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        perror("subreaper: prctl(PR_SET_CHILD_SUBREAPER)");
        return 2;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("subreaper: fork");
        return 2;
    }
    if (child == 0) {
        execvp(argv[1], &argv[1]);
        perror("subreaper: execvp");
        _exit(127);
    }

    for (;;) {
        int status;
        pid_t reaped = wait(&status);
        if (reaped == child)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        if (reaped < 0)
            return 0;
        /* any other child is an orphan we have just reaped; keep waiting */
    }
}
