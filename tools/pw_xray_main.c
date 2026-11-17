/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* pw-xray: small CLI around the engine.
 *   pw-xray sha256 FILE...                          print SHA-256 like sha256sum
 *   pw-xray demo --binary FILE --alloy FILE -o OUT  write the synthetic demo bundle
 *   pw-xray inspect BUNDLE                          print manifest and records
 * The demo bundle comes from a hand-written fixture (pw_xray_demo.c); this
 * tool does not disassemble or lift binaries. */
#include "pw_io.h"
#include "pw_sha256.h"
#include "pw_xray_bundle.h"
#include "pw_xray_demo.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void) {
    fprintf(stderr,
            "usage: pw-xray sha256 FILE...\n"
            "       pw-xray demo --binary FILE --alloy FILE -o OUT\n"
            "       pw-xray inspect BUNDLE\n");
    return 2;
}

static int cmd_sha256(int argc, char **argv) {
    int rc = 0;
    for (int i = 0; i < argc; ++i) {
        uint8_t *d = NULL, dg[32];
        size_t n = 0;
        char hx[65];
        if (pw_read_file(argv[i], &d, &n) != 0) {
            fprintf(stderr, "pw-xray: cannot read %s\n", argv[i]);
            rc = 2;
            continue;
        }
        pw_sha256(d, n, dg);
        pw_hex32(dg, hx);
        printf("%s  %s\n", hx, argv[i]);
        free(d);
    }
    return rc;
}

static int cmd_demo(int argc, char **argv) {
    const char *bin = NULL, *als = NULL, *out = NULL;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--binary") == 0 && i + 1 < argc) bin = argv[++i];
        else if (strcmp(argv[i], "--alloy") == 0 && i + 1 < argc) als = argv[++i];
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) out = argv[++i];
        else return usage();
    }
    if (!bin || !als || !out) return usage();
    uint8_t *b = NULL, *a = NULL, *bundle = NULL;
    size_t bl = 0, al = 0, bundle_len = 0;
    int rc = 2;
    if (pw_read_file(bin, &b, &bl) != 0 || pw_read_file(als, &a, &al) != 0) {
        fprintf(stderr, "pw-xray: cannot read inputs\n");
        goto done;
    }
    pw_demo_t demo;
    pw_status_t st = pw_demo_build(&demo, b, bl, a, al);
    if (st == PW_OK) st = pw_bundle_write(&demo.input, &bundle, &bundle_len);
    if (st != PW_OK) {
        fprintf(stderr, "pw-xray: %s\n", pw_status_str(st));
        rc = 1;
        goto done;
    }
    if (pw_write_file(out, bundle, bundle_len) != 0) {
        fprintf(stderr, "pw-xray: cannot write %s\n", out);
        goto done;
    }
    char hx[65];
    pw_hex32(bundle + PW_MANIFEST_SEALED_BYTES, hx);
    printf("wrote %s (%zu bytes) manifest_sha256 %s\n", out, bundle_len, hx);
    rc = 0;
done:
    free(b);
    free(a);
    free(bundle);
    return rc;
}

static const char *verdict_name(uint8_t v) {
    switch (v) {
    case PW_VERDICT_PROVEN_COMPLIANT: return "PROVEN_COMPLIANT";
    case PW_VERDICT_PROVEN_VULNERABLE: return "PROVEN_VULNERABLE";
    case PW_VERDICT_UNKNOWN: return "UNKNOWN";
    default: return "INVALID";
    }
}

static int cmd_inspect(int argc, char **argv) {
    if (argc != 1) return usage();
    uint8_t *b = NULL;
    size_t n = 0;
    if (pw_read_file(argv[0], &b, &n) != 0) {
        fprintf(stderr, "pw-xray: cannot read %s\n", argv[0]);
        return 2;
    }
    pw_verify_report_t rep;
    pw_status_t st = pw_bundle_verify(b, n, NULL, 0, &rep);
    if (st != PW_OK) {
        printf("bundle does not verify: %s (byte offset %zu)\n", pw_status_str(st), rep.fail_offset);
        free(b);
        return 1;
    }
    const pw_evidence_manifest_t *m = &rep.manifest;
    char hx[65];
    printf("format %u arch %u overall_verdict %s records %u functions %u\n",
           m->container_format, m->arch, verdict_name(m->overall_verdict),
           m->record_count, rep.func_count);
    printf("binary_size_bytes %" PRIu64 "\n", m->binary_size_bytes);
    printf("layout manifest [0,192) records [%zu,%zu) ir [%zu,%zu) alloy [%zu,%zu)\n",
           rep.records_off, rep.records_end, rep.ir_off, rep.ir_end, rep.alloy_off, n);
    for (uint32_t i = 0; i < m->record_count; ++i) {
        pw_evidence_record_t r;
        pw_parse_evidence_record(b + rep.records_off + (size_t)i * PW_RECORD_BYTES, &r);
        pw_hex32(r.func_ir_sha256, hx);
        printf("record id=%u site_va=0x%" PRIx64 " rule=0x%04x verdict=%s unknown_reason=%u "
               "detected=%u required=%u func_ir=%.16s\n",
               r.record_id, r.site_va, r.rule_id, verdict_name(r.verdict), r.unknown_reason,
               r.detected_bytes, r.required_bytes, hx);
    }
    free(b);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    if (strcmp(argv[1], "sha256") == 0) return argc > 2 ? cmd_sha256(argc - 2, argv + 2) : usage();
    if (strcmp(argv[1], "demo") == 0) return cmd_demo(argc - 2, argv + 2);
    if (strcmp(argv[1], "inspect") == 0) return cmd_inspect(argc - 2, argv + 2);
    return usage();
}
