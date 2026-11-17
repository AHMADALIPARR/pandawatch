/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
#include "pw_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pw_read_file(const char *path, uint8_t **data, size_t *len) {
    *data = NULL;
    *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t cap = 4096, n = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { fclose(f); return -1; }
    for (;;) {
        if (n == cap) {
            uint8_t *nb = (uint8_t *)realloc(buf, cap * 2);
            if (!nb) { free(buf); fclose(f); return -1; }
            buf = nb;
            cap *= 2;
        }
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (got == 0) break;
    }
    int err = ferror(f);
    fclose(f);
    if (err) { free(buf); return -1; }
    *data = buf;
    *len = n;
    return 0;
}

int pw_write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = len ? fwrite(data, 1, len, f) : 0;
    int rc = (put == len) ? 0 : -1;
    if (fclose(f) != 0) rc = -1;
    return rc;
}
