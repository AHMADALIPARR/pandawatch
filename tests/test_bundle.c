/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Bundle round trip, golden digests, exhaustive single-bit mutation and
 * truncation detection.
 *   test_bundle BINARY ALLOY GOLDEN
 * GOLDEN holds "bundle_sha256 <hex>", "manifest_sha256 <hex>",
 * "bundle_bytes <n>" lines ('#' lines are comments). */
#include "pw_io.h"
#include "pw_sha256.h"
#include "pw_xray_bundle.h"
#include "pw_xray_demo.h"
#include "pw_test.h"

#include <stdlib.h>
#include <string.h>

static int read_golden(const char *path, char bundle_hex[65], char manifest_hex[65], size_t *bytes) {
    uint8_t *g = NULL;
    size_t n = 0;
    if (pw_read_file(path, &g, &n) != 0) return -1;
    char *s = (char *)realloc(g, n + 1);
    if (!s) { free(g); return -1; }
    s[n] = '\0';
    int found = 0;
    for (char *line = strtok(s, "\n"); line; line = strtok(NULL, "\n")) {
        unsigned long long v;
        if (line[0] == '#') continue;
        if (sscanf(line, "bundle_sha256 %64s", bundle_hex) == 1) found |= 1;
        else if (sscanf(line, "manifest_sha256 %64s", manifest_hex) == 1) found |= 2;
        else if (sscanf(line, "bundle_bytes %llu", &v) == 1) { *bytes = (size_t)v; found |= 4; }
    }
    free(s);
    return found == 7 ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: test_bundle BINARY ALLOY GOLDEN\n");
        return 2;
    }
    uint8_t *bin = NULL, *als = NULL;
    size_t bl = 0, al = 0;
    if (pw_read_file(argv[1], &bin, &bl) != 0 || pw_read_file(argv[2], &als, &al) != 0) {
        fprintf(stderr, "cannot read inputs\n");
        return 2;
    }
    pw_demo_t demo;
    CHECK(pw_demo_build(&demo, bin, bl, als, al) == PW_OK);
    uint8_t *b = NULL;
    size_t n = 0;
    CHECK(pw_bundle_write(&demo.input, &b, &n) == PW_OK);
    if (!b) return TEST_DONE("test_bundle");

    /* Round trip. */
    pw_verify_report_t rep;
    CHECK(pw_bundle_verify(b, n, bin, bl, &rep) == PW_OK);
    CHECK(pw_bundle_verify(b, n, NULL, 0, &rep) == PW_OK);
    CHECK(rep.manifest.record_count == PW_DEMO_RECORDS);
    CHECK(rep.func_count == PW_DEMO_FUNCS);
    CHECK(rep.manifest.overall_verdict == PW_VERDICT_UNKNOWN);
    CHECK(n - rep.alloy_off == al && memcmp(b + rep.alloy_off, als, al) == 0);

    /* Golden digests (measured once, committed in tests/fixtures). */
    char gb[65] = "", gm[65] = "", hx[65];
    size_t gbytes = 0;
    uint8_t d[32];
    CHECK(read_golden(argv[3], gb, gm, &gbytes) == 0);
    pw_sha256(b, n, d);
    pw_hex32(d, hx);
    printf("bundle_bytes %zu\nbundle_sha256 %s\n", n, hx);
    CHECK(strcmp(hx, gb) == 0);
    pw_hex32(b + PW_MANIFEST_SEALED_BYTES, hx);
    printf("manifest_sha256 %s\n", hx);
    CHECK(strcmp(hx, gm) == 0);
    CHECK(n == gbytes);

    /* Every single-bit flip anywhere in the bundle must be rejected. */
    size_t bits = n * 8, detected = 0;
    size_t per_status[PW_E_COUNT];
    memset(per_status, 0, sizeof per_status);
    for (size_t bit = 0; bit < bits; ++bit) {
        b[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        pw_status_t st = pw_bundle_verify(b, n, NULL, 0, NULL);
        b[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        if (st != PW_OK) ++detected;
        if ((unsigned)st < PW_E_COUNT) ++per_status[st];
    }
    printf("single-bit mutations detected: %zu/%zu\n", detected, bits);
    for (int s = 1; s < PW_E_COUNT; ++s)
        if (per_status[s]) printf("  %-55s %zu\n", pw_status_str((pw_status_t)s), per_status[s]);
    CHECK(detected == bits);
    CHECK(pw_bundle_verify(b, n, NULL, 0, NULL) == PW_OK);

    /* Every truncation must be rejected; appending a byte must be rejected. */
    size_t trunc_detected = 0;
    for (size_t len = 0; len < n; ++len)
        if (pw_bundle_verify(b, len, NULL, 0, NULL) != PW_OK) ++trunc_detected;
    printf("truncations detected: %zu/%zu\n", trunc_detected, n);
    CHECK(trunc_detected == n);
    {
        uint8_t *ext = (uint8_t *)malloc(n + 1);
        memcpy(ext, b, n);
        ext[n] = '\n';
        CHECK(pw_bundle_verify(ext, n + 1, NULL, 0, NULL) == PW_E_ALLOY_DIGEST);
        free(ext);
    }

    /* Every single-bit flip in the binary must be caught with --binary. */
    size_t bin_detected = 0;
    for (size_t bit = 0; bit < bl * 8; ++bit) {
        bin[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        if (pw_bundle_verify(b, n, bin, bl, NULL) == PW_E_BINARY_DIGEST) ++bin_detected;
        bin[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    }
    printf("binary single-bit mutations detected: %zu/%zu\n", bin_detected, bl * 8);
    CHECK(bin_detected == bl * 8);
    CHECK(bl == 0 || pw_bundle_verify(b, n, bin, bl - 1, NULL) == PW_E_BINARY_SIZE);

    /* Writer rejects inconsistent records. */
    {
        pw_demo_t bad;
        uint8_t *o = NULL;
        size_t ol = 0;
        CHECK(pw_demo_build(&bad, bin, bl, als, al) == PW_OK);
        bad.records[0].unknown_reason = PW_UNK_NONE;          /* UNKNOWN without reason */
        CHECK(pw_bundle_write(&bad.input, &o, &ol) == PW_E_UNKNOWN_REASON);
        CHECK(pw_demo_build(&bad, bin, bl, als, al) == PW_OK);
        bad.records[2].func_ir_sha256[0] ^= 1u;               /* dangling Gate 3 link */
        CHECK(pw_bundle_write(&bad.input, &o, &ol) == PW_E_DANGLING_FUNC_REF);
        CHECK(pw_demo_build(&bad, bin, bl, als, al) == PW_OK);
        bad.records[2].verdict = PW_VERDICT_PROVEN_VULNERABLE;
        bad.records[2].rule_id = PW_RULE_CLASSICAL_ASYMMETRIC;
        CHECK(pw_bundle_write(&bad.input, &o, &ol) == PW_OK);
        if (o) {
            pw_verify_report_t r2;
            CHECK(pw_bundle_verify(o, ol, NULL, 0, &r2) == PW_OK);
            CHECK(r2.manifest.overall_verdict == PW_VERDICT_PROVEN_VULNERABLE);
        }
        free(o);
    }

    free(b);
    free(bin);
    free(als);
    return TEST_DONE("test_bundle");
}
