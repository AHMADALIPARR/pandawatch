/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Synthetic, hand-written Gate 3 / Gate 9 fixture used by the tests and the
 * `pw-xray demo` command. It is NOT the output of analysing any real binary:
 * there is no disassembler or lifter in this repository. Its inputs are
 * deliberately given in non-canonical order (functions, blocks, successors,
 * commutative operands and records) so the writer's canonicalization is
 * exercised. */
#ifndef PW_XRAY_DEMO_H
#define PW_XRAY_DEMO_H

#include "pw_xray_bundle.h"

#define PW_DEMO_FUNCS   2u
#define PW_DEMO_RECORDS 3u
#define PW_DEMO_MAX_BLOCKS 3u
#define PW_DEMO_MAX_INSTS  5u

typedef struct {
    pw_ir_block_t        blocks[PW_DEMO_FUNCS][PW_DEMO_MAX_BLOCKS];
    pw_ir_inst_t         insts[PW_DEMO_FUNCS][PW_DEMO_MAX_INSTS];
    pw_func_input_t      funcs[PW_DEMO_FUNCS];
    pw_evidence_record_t records[PW_DEMO_RECORDS];
    pw_bundle_input_t    input;
} pw_demo_t;

/* Fills *demo; binary/alloy are borrowed, not copied. Returns PW_OK. */
pw_status_t pw_demo_build(pw_demo_t *demo,
                          const uint8_t *binary, size_t binary_len,
                          const uint8_t *alloy, size_t alloy_len);

#endif /* PW_XRAY_DEMO_H */
