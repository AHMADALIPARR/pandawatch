/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Whole-file read/write helpers shared by the CLI tools and tests. */
#ifndef PW_IO_H
#define PW_IO_H

#include <stddef.h>
#include <stdint.h>

/* Returns 0 on success; *data is malloc'd (non-NULL even for empty files). */
int pw_read_file(const char *path, uint8_t **data, size_t *len);
int pw_write_file(const char *path, const uint8_t *data, size_t len);

#endif /* PW_IO_H */
