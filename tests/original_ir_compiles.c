/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* The original pw_xray_ir.h compiles unchanged, including its own
 * _Static_assert lines. */
#include "pw_xray_ir.h"

int main(void) { return sizeof(pw_ir_inst_t) == 64 ? 0 : 1; }
