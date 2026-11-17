/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
#ifndef PW_TEST_H
#define PW_TEST_H

#include <stdio.h>

static int pw_test_failures = 0;
static int pw_test_checks = 0;

#define CHECK(cond) do { ++pw_test_checks; if (!(cond)) { ++pw_test_failures; \
    fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); } } while (0)

#define TEST_DONE(name) (printf("%s: %d checks, %d failures\n", (name), pw_test_checks, \
    pw_test_failures), pw_test_failures ? 1 : 0)

#endif /* PW_TEST_H */
