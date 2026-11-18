/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Minimal argparse-style option scanner shared by rblob, bsm and
 * holo-reverse: `-x VALUE`, `-xVALUE`, `--long VALUE`, `--long=VALUE`,
 * flags, `--` and positionals. Usage errors exit with status 2. C23. */
#ifndef PW_CLI_H
#define PW_CLI_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *shrt;   /* "-o" or nullptr */
    const char *lng;    /* "--output" or nullptr */
    bool takes_value;
    const char **value; /* receives the value (or "1" for flags) */
} pw_opt;

[[noreturn]] static inline void pw_cli_error(const char *usage, const char *prog, const char *msg) {
    fprintf(stderr, "%s\n%s: error: %s\n", usage, prog, msg);
    exit(2);
}

/* Returns the number of positionals stored in pos (up to maxpos; extra ones
 * are reported as unrecognized). `help` is printed for -h / --help. */
static inline int pw_cli_scan(int argc, char **argv, int first, pw_opt *opts, int nopts,
                              const char **pos, int maxpos, bool pos_many,
                              const char *usage, const char *prog, const char *help) {
    int np = 0;
    bool only_pos = false;
    for (int i = first; i < argc; i++) {
        const char *a = argv[i];
        if (!only_pos && strcmp(a, "--") == 0) { only_pos = true; continue; }
        if (!only_pos && (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0)) {
            fputs(help, stdout);
            exit(0);
        }
        if (!only_pos && a[0] == '-' && a[1] != 0) {
            bool matched = false;
            for (int k = 0; k < nopts && !matched; k++) {
                const pw_opt *o = &opts[k];
                const char *val = nullptr;
                if (o->lng && strncmp(a, o->lng, strlen(o->lng)) == 0 &&
                    (a[strlen(o->lng)] == 0 || (a[strlen(o->lng)] == '=' && o->takes_value))) {
                    matched = true;
                    if (a[strlen(o->lng)] == '=') val = a + strlen(o->lng) + 1;
                } else if (o->shrt && strncmp(a, o->shrt, 2) == 0 && a[1] != '-' &&
                           (a[2] == 0 || o->takes_value)) {
                    matched = true;
                    if (a[2]) val = a + 2;
                }
                if (!matched) continue;
                if (!o->takes_value) { *o->value = "1"; break; }
                if (val == nullptr) {
                    if (i + 1 >= argc || (argv[i + 1][0] == '-' && argv[i + 1][1] != 0)) {
                        char msg[256];
                        snprintf(msg, sizeof msg, "argument %s%s%s: expected one argument",
                                 o->shrt ? o->shrt : "", (o->shrt && o->lng) ? "/" : "", o->lng ? o->lng : "");
                        pw_cli_error(usage, prog, msg);
                    }
                    val = argv[++i];
                }
                *o->value = val;
            }
            if (!matched) {
                char msg[512];
                snprintf(msg, sizeof msg, "unrecognized arguments: %s", a);
                pw_cli_error(usage, prog, msg);
            }
            continue;
        }
        if (np < maxpos) pos[np++] = a;
        else if (pos_many) pos[maxpos - 1] = a;  /* caller handles lists itself */
        else {
            char msg[512];
            snprintf(msg, sizeof msg, "unrecognized arguments: %s", a);
            pw_cli_error(usage, prog, msg);
        }
    }
    return np;
}

#endif /* PW_CLI_H */
