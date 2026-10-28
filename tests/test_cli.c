/*
 ============================================================================
 Name        : test_cli.c
 Description : Smoke tests for the portmux CLI UX: --help / --help-all /
               --version / completion and exit codes. Execs bin/portmux.
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

/* run `bin/portmux ARGS`, capture stdout, return exit code; stdout -> out. */
static int
run (const char *args, char *out, size_t outcap)
{
    char cmd[512];
    snprintf (cmd, sizeof cmd, "bin/portmux %s 2>/dev/null", args);
    FILE *p = popen (cmd, "r");
    if (!p) return -1;
    size_t n = 0;
    if (out && outcap) {
        n = fread (out, 1, outcap - 1, p);
        out[n] = '\0';
    } else {
        char buf[256];
        while (fread (buf, 1, sizeof buf, p) > 0) { }
    }
    int rc = pclose (p);
    return (rc == -1) ? -1 : (rc >> 8); /* WEXITSTATUS */
}

#define CK(cond, msg) do { if (!(cond)) { printf ("  FAIL: %s\n", msg); failures++; } } while (0)

int
main (void)
{
    char out[8192];

    CK (run ("--version", out, sizeof out) == 0 && strstr (out, "portmux ") == out,
        "--version prints 'portmux <ver>' and exits 0");
    CK (run ("-V", out, sizeof out) == 0 && strstr (out, "portmux "),
        "-V prints version");
    CK (run ("--help", out, sizeof out) == 0 && strstr (out, "usage:") != NULL,
        "--help prints usage to stdout, exit 0");
    CK (run ("-h", out, sizeof out) == 0, "-h exit 0");
    CK (run ("--help-all", out, sizeof out) == 0
        && strstr (out, "full reference") && strstr (out, "ENVIRONMENT VARIABLES")
        && strstr (out, "PM_JUMPS") && strstr (out, "CIPHERS"),
        "--help-all includes env vars + ciphers");
    CK (run ("completion bash", out, sizeof out) == 0 && strstr (out, "complete") != NULL,
        "completion bash emits a script");
    CK (run ("completion zsh", out, sizeof out) == 0 && strstr (out, "#compdef portmux"),
        "completion zsh emits a compdef");
    CK (run ("completion fish", out, sizeof out) == 0 && strstr (out, "complete -c portmux"),
        "completion fish emits completions");
    CK (run ("completion powershell", NULL, 0) == 1, "completion bad-shell exits 1");
    CK (run ("", NULL, 0) == 1, "no args exits 1");
    CK (run ("not-a-route", NULL, 0) == 1, "bad route exits 1");

    if (failures) { printf ("CLI FAIL: %d\n", failures); printf ("RESULT: %d failure(s)\n", failures); return 1; }
    printf ("CLI OK: help/help-all/version/completion + exit codes\n");
    printf ("RESULT: all passed\n");
    return 0;
}
