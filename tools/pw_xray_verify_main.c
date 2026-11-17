/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* pw-xray-verify: standalone offline verifier for .pwxray bundles.
 *   pw-xray-verify BUNDLE [--binary FILE]
 * Exit status: 0 = verified, 1 = verification failed, 2 = usage/IO error. */
#include "pw_io.h"
#include "pw_sha256.h"
#include "pw_xray_bundle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void) {
    fprintf(stderr, "usage: pw-xray-verify BUNDLE [--binary FILE]\n");
}

int main(int argc, char **argv) {
    const char *bundle_path = NULL, *binary_path = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--binary") == 0 && i + 1 < argc) binary_path = argv[++i];
        else if (argv[i][0] == '-') { usage(); return 2; }
        else if (!bundle_path) bundle_path = argv[i];
        else { usage(); return 2; }
    }
    if (!bundle_path) { usage(); return 2; }

    uint8_t *bundle = NULL, *binary = NULL;
    size_t blen = 0, binlen = 0;
    if (pw_read_file(bundle_path, &bundle, &blen) != 0) {
        fprintf(stderr, "pw-xray-verify: cannot read %s\n", bundle_path);
        return 2;
    }
    if (binary_path && pw_read_file(binary_path, &binary, &binlen) != 0) {
        fprintf(stderr, "pw-xray-verify: cannot read %s\n", binary_path);
        free(bundle);
        return 2;
    }

    pw_verify_report_t rep;
    pw_status_t st = pw_bundle_verify(bundle, blen, binary, binlen, &rep);
    if (st != PW_OK) {
        printf("FAIL %s (byte offset %zu)\n", pw_status_str(st), rep.fail_offset);
        free(bundle);
        free(binary);
        return 1;
    }
    char hx[65];
    pw_hex32(rep.manifest.manifest_sha256, hx);
    printf("OK manifest_sha256 %s\n", hx);
    pw_hex32(rep.manifest.binary_sha256, hx);
    printf("   binary_sha256      %s (%s)\n", hx, binary ? "recomputed" : "sealed only, no --binary");
    pw_hex32(rep.manifest.ir_corpus_sha256, hx);
    printf("   ir_corpus_sha256   %s (%u functions)\n", hx, rep.func_count);
    pw_hex32(rep.manifest.alloy_model_sha256, hx);
    printf("   alloy_model_sha256 %s (%zu bytes)\n", hx, blen - rep.alloy_off);
    pw_hex32(rep.manifest.records_sha256, hx);
    printf("   records_sha256     %s (%u records)\n", hx, rep.manifest.record_count);
    free(bundle);
    free(binary);
    return 0;
}
