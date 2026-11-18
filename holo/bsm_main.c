/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* bsm: Binary Semantics Machine -> Wasm Holo Packer. C23.
 *   bsm pack INPUT... -o OUTPUT [--abi lp64|wasm32]
 *   bsm inspect WASM_FILE [--json] */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_bsm.h"
#include "pw_cli.h"
#include "pw_json.h"
#include "pw_text.h"

static const char USAGE[] = "usage: bsm [-h] {pack,inspect} ...";
static const char HELP[] =
    "usage: bsm [-h] {pack,inspect} ...\n"
    "\n"
    "Binary Semantics Machine -> Wasm Holo Packer\n"
    "\n"
    "positional arguments:\n"
    "  {pack,inspect}\n"
    "    pack          Analyze legacy inputs and wrap into a .holo.wasm module\n"
    "    inspect       Validate and inspect a .holo.wasm module\n"
    "\n"
    "options:\n"
    "  -h, --help      show this help message and exit\n";
static const char USAGE_PACK[] = "usage: bsm pack [-h] -o OUTPUT [--abi {lp64,wasm32}] inputs [inputs ...]";
static const char HELP_PACK[] =
    "usage: bsm pack [-h] -o OUTPUT [--abi {lp64,wasm32}] inputs [inputs ...]\n"
    "\n"
    "positional arguments:\n"
    "  inputs               C, COBOL, ASM, SQLite, or ELF files\n"
    "\n"
    "options:\n"
    "  -h, --help           show this help message and exit\n"
    "  -o, --output OUTPUT  Output .holo.wasm path\n"
    "  --abi {lp64,wasm32}  Target C ABI\n";
static const char USAGE_INSPECT[] = "usage: bsm inspect [-h] [--json] wasm_file";
static const char HELP_INSPECT[] =
    "usage: bsm inspect [-h] [--json] wasm_file\n"
    "\n"
    "positional arguments:\n"
    "  wasm_file   Path to .holo.wasm module\n"
    "\n"
    "options:\n"
    "  -h, --help  show this help message and exit\n"
    "  --json      Print full JSON semantic dump\n";

static void print_json(const pj *v) {
    size_t n;
    char *s = pj_dump(v, 2, false, &n);
    fwrite(s, 1, n, stdout);
    fputc('\n', stdout);
    free(s);
}

static int cmd_pack(int argc, char **argv) {
    const char *out = nullptr, *abi = "lp64";
    const char **pos = calloc((size_t)argc + 1, sizeof *pos);
    if (pos == nullptr) abort();
    pw_opt opts[] = { { "-o", "--output", true, &out }, { nullptr, "--abi", true, &abi } };
    const int np = pw_cli_scan(argc, argv, 2, opts, 2, pos, argc, false, USAGE_PACK, "bsm pack", HELP_PACK);
    if (np < 1 && out == nullptr) pw_cli_error(USAGE_PACK, "bsm pack", "the following arguments are required: inputs, -o/--output");
    if (np < 1) pw_cli_error(USAGE_PACK, "bsm pack", "the following arguments are required: inputs");
    if (out == nullptr) pw_cli_error(USAGE_PACK, "bsm pack", "the following arguments are required: -o/--output");
    if (strcmp(abi, "lp64") != 0 && strcmp(abi, "wasm32") != 0) {
        char msg[512];
        snprintf(msg, sizeof msg, "argument --abi: invalid choice: '%s' (choose from lp64, wasm32)", abi);
        pw_cli_error(USAGE_PACK, "bsm pack", msg);
    }
    pw_holo_ir ir;
    pw_holo_ir_init(&ir);
    pw_bsm_ingest(&ir, pos, (size_t)np, abi);
    size_t len;
    pj *manifest;
    uint8_t *wasm = pw_bsm_pack(&ir, &len, &manifest);
    char *parent = pw_path_parent(out);
    if (pw_mkdirs(parent) != 0) pw_die("OSError: [Errno %d] %s: '%s'", errno, strerror(errno), parent);
    if (pw_spit(out, wasm, len) != 0) pw_die("OSError: [Errno %d] %s: '%s'", errno, strerror(errno), out);
    pj *r = pj_obj();
    pj_set(r, "output", pj_strown(pw_path_norm(out)));
    pj_set(r, "wasm_bytes", pj_int((int64_t)len));
    pj_set(r, "manifest", manifest);
    print_json(r);
    pj_free(r);
    free(parent);
    free(wasm);
    free(pos);
    pw_holo_ir_free(&ir);
    return 0;
}

static int cmd_inspect(int argc, char **argv) {
    const char *json = nullptr, *pos[1] = {nullptr};
    pw_opt opts[] = { { nullptr, "--json", false, &json } };
    const int np = pw_cli_scan(argc, argv, 2, opts, 1, pos, 1, false, USAGE_INSPECT, "bsm inspect", HELP_INSPECT);
    if (np < 1) pw_cli_error(USAGE_INSPECT, "bsm inspect", "the following arguments are required: wasm_file");
    size_t len;
    uint8_t *w = pw_slurp(pos[0], &len);
    if (w == nullptr) pw_die("FileNotFoundError: [Errno %d] %s: '%s'", errno, strerror(errno), pos[0]);
    char err[512];
    pj *rep = pw_bsm_inspect(w, len, err, sizeof err);
    free(w);
    if (rep == nullptr) pw_die("%s", err);
    if (json) {
        print_json(rep);
    } else {
        const pj *m = pj_get(rep, "manifest");
        char *shown = pw_path_norm(pos[0]);
        printf("Wasm Holo Module: %s (%lld bytes)\n", shown, (long long)pj_as_int(pj_get(rep, "total_bytes")));
        printf("Integrity Verified: %s\n", pj_truthy(pj_get(rep, "integrity_verified")) ? "True" : "False");
        const pj *root = pj_get(m, "root_sha256");
        char *rs = root && root->t == PJ_STR ? pw_dup(root->s) : pj_pyrepr(root);
        printf("Root SHA-256: %s\n", rs);
        char *st = pj_pyrepr(pj_get(m, "stats"));
        printf("Stats: %s\n", st);
        pj *names = pj_arr();
        const pj *ly = pj_get(m, "layers");
        for (size_t i = 0; ly && ly->t == PJ_OBJ && i < ly->n; i++) pj_push(names, pj_str(ly->k[i]));
        char *ln = pj_pyrepr(names);
        printf("Layers: %s\n", ln);
        free(shown);
        free(rs);
        free(st);
        free(ln);
        pj_free(names);
    }
    pj_free(rep);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) pw_cli_error(USAGE, "bsm", "the following arguments are required: cmd");
    const char *cmd = argv[1];
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) { fputs(HELP, stdout); return 0; }
    if (strcmp(cmd, "pack") == 0) return cmd_pack(argc, argv);
    if (strcmp(cmd, "inspect") == 0) return cmd_inspect(argc, argv);
    char msg[512];
    snprintf(msg, sizeof msg, "argument cmd: invalid choice: '%s' (choose from pack, inspect)", cmd);
    pw_cli_error(USAGE, "bsm", msg);
}
