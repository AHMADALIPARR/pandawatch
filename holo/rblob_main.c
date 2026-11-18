/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* rblob: Rust crate -> Binary Blob (.rblob) -> Functor Disassembler. C23.
 *   rblob ingest CRATE_PATH -o OUTPUT
 *   rblob verify BLOB_FILE
 *   rblob disassemble BLOB_FILE */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_cli.h"
#include "pw_json.h"
#include "pw_rblob.h"
#include "pw_text.h"

static const char USAGE[] = "usage: rblob [-h] {ingest,verify,disassemble} ...";
static const char HELP[] =
    "usage: rblob [-h] {ingest,verify,disassemble} ...\n"
    "\n"
    "Rust Crate -> Binary Blob (.rblob) -> Functor Disassembler\n"
    "\n"
    "positional arguments:\n"
    "  {ingest,verify,disassemble}\n"
    "    ingest              Ingest a Rust crate or .rs file into a verified .rblob\n"
    "    verify              Verify a .rblob file's SHA-256 and structure\n"
    "    disassemble         Verify and disassemble a .rblob into Functors\n"
    "\n"
    "options:\n"
    "  -h, --help            show this help message and exit\n";
static const char USAGE_INGEST[] = "usage: rblob ingest [-h] -o OUTPUT crate_path";
static const char HELP_INGEST[] =
    "usage: rblob ingest [-h] -o OUTPUT crate_path\n"
    "\n"
    "positional arguments:\n"
    "  crate_path\n"
    "\n"
    "options:\n"
    "  -h, --help           show this help message and exit\n"
    "  -o, --output OUTPUT\n";
static const char USAGE_VERIFY[] = "usage: rblob verify [-h] blob_file";
static const char HELP_VERIFY[] =
    "usage: rblob verify [-h] blob_file\n"
    "\n"
    "positional arguments:\n"
    "  blob_file\n"
    "\n"
    "options:\n"
    "  -h, --help  show this help message and exit\n";
static const char USAGE_DIS[] = "usage: rblob disassemble [-h] blob_file";
static const char HELP_DIS[] =
    "usage: rblob disassemble [-h] blob_file\n"
    "\n"
    "positional arguments:\n"
    "  blob_file\n"
    "\n"
    "options:\n"
    "  -h, --help  show this help message and exit\n";

static void print_json(const pj *v) {
    size_t n;
    char *s = pj_dump(v, 2, false, &n);
    fwrite(s, 1, n, stdout);
    fputc('\n', stdout);
    free(s);
}

static uint8_t *read_or_die(const char *path, size_t *len) {
    uint8_t *d = pw_slurp(path, len);
    if (d == nullptr) pw_die("FileNotFoundError: [Errno %d] %s: '%s'", errno, strerror(errno), path);
    return d;
}

int main(int argc, char **argv) {
    if (argc < 2) pw_cli_error(USAGE, "rblob", "the following arguments are required: cmd");
    const char *cmd = argv[1];
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) { fputs(HELP, stdout); return 0; }
    if (strcmp(cmd, "ingest") == 0) {
        const char *out = nullptr, *pos[1] = {nullptr};
        pw_opt opts[] = { { "-o", "--output", true, &out } };
        const int np = pw_cli_scan(argc, argv, 2, opts, 1, pos, 1, false, USAGE_INGEST, "rblob ingest", HELP_INGEST);
        if (np < 1 && out == nullptr)
            pw_cli_error(USAGE_INGEST, "rblob ingest", "the following arguments are required: crate_path, -o/--output");
        if (np < 1) pw_cli_error(USAGE_INGEST, "rblob ingest", "the following arguments are required: crate_path");
        if (out == nullptr) pw_cli_error(USAGE_INGEST, "rblob ingest", "the following arguments are required: -o/--output");
        pj *ir = pw_rblob_parse_crate(pos[0]);
        size_t len;
        char hex[65];
        uint8_t *blob = pw_rblob_build(ir, &len, hex);
        char *parent = pw_path_parent(out);
        if (pw_mkdirs(parent) != 0) pw_die("OSError: [Errno %d] %s: '%s'", errno, strerror(errno), parent);
        if (pw_spit(out, blob, len) != 0) pw_die("OSError: [Errno %d] %s: '%s'", errno, strerror(errno), out);
        char *outn = pw_path_norm(out);
        pj *r = pj_obj();
        pj_set(r, "output", pj_str(outn));
        pj_set(r, "bytes", pj_int((int64_t)len));
        pj_set(r, "sha256", pj_str(hex));
        print_json(r);
        pj_free(r);
        pj_free(ir);
        free(outn);
        free(parent);
        free(blob);
        return 0;
    }
    const bool is_verify = strcmp(cmd, "verify") == 0;
    if (is_verify || strcmp(cmd, "disassemble") == 0) {
        const char *pos[1] = {nullptr};
        const char *usage = is_verify ? USAGE_VERIFY : USAGE_DIS;
        const char *prog = is_verify ? "rblob verify" : "rblob disassemble";
        const int np = pw_cli_scan(argc, argv, 2, nullptr, 0, pos, 1, false, usage, prog,
                                   is_verify ? HELP_VERIFY : HELP_DIS);
        if (np < 1) pw_cli_error(usage, prog, "the following arguments are required: blob_file");
        size_t len;
        uint8_t *blob = read_or_die(pos[0], &len);
        char err[512];
        if (is_verify) {
            pj *v = pw_rblob_verify(blob, len, err, sizeof err);
            if (v == nullptr) pw_die("%s", err);
            pj *r = pj_obj();
            pj_set(r, "verified", pj_copy(pj_get(v, "verified")));
            pj_set(r, "sha256", pj_copy(pj_get(v, "sha256")));
            pj_set(r, "blob_bytes", pj_copy(pj_get(v, "blob_bytes")));
            print_json(r);
            pj_free(r);
            pj_free(v);
        } else {
            pj *d = pw_rblob_disassemble(blob, len, err, sizeof err);
            if (d == nullptr) pw_die("%s", err);
            print_json(d);
            pj_free(d);
        }
        free(blob);
        return 0;
    }
    char msg[512];
    snprintf(msg, sizeof msg, "argument cmd: invalid choice: '%s' (choose from ingest, verify, disassemble)", cmd);
    pw_cli_error(USAGE, "rblob", msg);
}
