/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Compile-time layout checks for pw_xray_ir.h (original, byte-for-byte) and
 * pw_xray_evidence_checked.h. If this file compiles, every assertion holds. */
#include "pw_xray_ir.h"
#include "pw_xray_evidence_checked.h"
#include "pw_test.h"

#include <stddef.h>

_Static_assert(sizeof(pw_operand_t) == 16, "operand");
_Static_assert(offsetof(pw_operand_t, ref_id) == 4, "operand.ref_id");
_Static_assert(offsetof(pw_operand_t, imm_val) == 8, "operand.imm_val");

_Static_assert(sizeof(pw_ir_inst_t) == 64, "inst");
_Static_assert(offsetof(pw_ir_inst_t, opcode) == 4, "inst.opcode");
_Static_assert(offsetof(pw_ir_inst_t, source_va) == 8, "inst.source_va");
_Static_assert(offsetof(pw_ir_inst_t, src) == 16, "inst.src");

_Static_assert(sizeof(pw_ir_block_t) == 32, "block");
_Static_assert(offsetof(pw_ir_block_t, succ_blocks) == 16, "block.succ");
_Static_assert(offsetof(pw_ir_block_t, start_va) == 24, "block.start_va");

_Static_assert(sizeof(pw_ir_func_hdr_t) == 64, "func");
_Static_assert(offsetof(pw_ir_func_hdr_t, entry_va) == 16, "func.entry_va");
_Static_assert(offsetof(pw_ir_func_hdr_t, ir_sha256) == 24, "func.ir_sha256");
_Static_assert(offsetof(pw_ir_func_hdr_t, _reserved) == 56, "func._reserved");

_Static_assert(sizeof(pw_evidence_record_t) == 64, "record");
_Static_assert(offsetof(pw_evidence_record_t, rule_id) == 6, "record.rule_id");
_Static_assert(offsetof(pw_evidence_record_t, required_bytes) == 12, "record.required");
_Static_assert(offsetof(pw_evidence_record_t, site_va) == 16, "record.site_va");
_Static_assert(offsetof(pw_evidence_record_t, func_ir_sha256) == 24, "record.func_ir");
_Static_assert(offsetof(pw_evidence_record_t, _reserved) == 56, "record._reserved");

_Static_assert(sizeof(pw_evidence_manifest_t) == 192, "manifest");
_Static_assert(offsetof(pw_evidence_manifest_t, record_count) == 12, "manifest.record_count");
_Static_assert(offsetof(pw_evidence_manifest_t, binary_sha256) == 24, "manifest.binary");
_Static_assert(offsetof(pw_evidence_manifest_t, ir_corpus_sha256) == 56, "manifest.ir");
_Static_assert(offsetof(pw_evidence_manifest_t, alloy_model_sha256) == 88, "manifest.alloy");
_Static_assert(offsetof(pw_evidence_manifest_t, records_sha256) == 120, "manifest.records");
_Static_assert(offsetof(pw_evidence_manifest_t, _reserved1) == 152, "manifest._reserved1");
_Static_assert(offsetof(pw_evidence_manifest_t, manifest_sha256) == 160, "manifest.seal at 160");

int main(void) {
    CHECK(sizeof(pw_evidence_manifest_t) == 192);
    CHECK(offsetof(pw_evidence_manifest_t, manifest_sha256) == 160);
    return TEST_DONE("test_layout");
}
