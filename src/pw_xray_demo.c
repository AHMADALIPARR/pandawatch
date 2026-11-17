/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Synthetic fixture; see pw_xray_demo.h. Addresses and findings are made up
 * for testing the container format and carry no claim about any program. */
#include "pw_xray_demo.h"

#include <string.h>

static pw_operand_t ssa(uint32_t id) {
    pw_operand_t o;
    memset(&o, 0, sizeof o);
    o.kind = PW_OPERAND_SSA; o.type = PW_TY_I64; o.ref_id = id;
    return o;
}
static pw_operand_t imm(uint64_t v) {
    pw_operand_t o;
    memset(&o, 0, sizeof o);
    o.kind = PW_OPERAND_IMM; o.type = PW_TY_I64; o.imm_val = v;
    return o;
}
static pw_operand_t blk(uint32_t id) {
    pw_operand_t o;
    memset(&o, 0, sizeof o);
    o.kind = PW_OPERAND_BLOCK; o.ref_id = id;
    return o;
}
static pw_ir_inst_t inst(uint32_t id, uint16_t op, uint8_t ty, uint64_t va,
                         pw_operand_t a, pw_operand_t b, pw_operand_t c) {
    pw_ir_inst_t i;
    memset(&i, 0, sizeof i);
    i.ssa_id = id; i.opcode = op; i.out_type = ty; i.source_va = va;
    i.src[0] = a; i.src[1] = b; i.src[2] = c;
    return i;
}
static pw_ir_block_t block(uint32_t id, uint32_t first, uint32_t n, uint32_t ns,
                           uint32_t s0, uint32_t s1, uint64_t va) {
    pw_ir_block_t b;
    memset(&b, 0, sizeof b);
    b.block_id = id; b.first_inst = first; b.inst_count = n; b.succ_count = ns;
    b.succ_blocks[0] = s0; b.succ_blocks[1] = s1; b.start_va = va;
    return b;
}

pw_status_t pw_demo_build(pw_demo_t *d, const uint8_t *binary, size_t binary_len,
                          const uint8_t *alloy, size_t alloy_len) {
    pw_operand_t none;
    memset(&none, 0, sizeof none);
    memset(d, 0, sizeof *d);

    /* Function "A" (func_id 1, entry 0x401200): listed first although its
     * entry_va is higher. Blocks listed out of order; block 0 lists its two
     * successors descending; block 1 carries a stale unused successor. */
    d->blocks[0][0] = block(2, 4, 1, 0, 0, 0, 0x401218u);
    d->blocks[0][1] = block(0, 0, 3, 2, 2, 1, 0x401200u);
    d->blocks[0][2] = block(1, 3, 1, 1, 2, 7, 0x401210u);
    d->insts[0][0] = inst(0, PW_OP_CONST, PW_TY_I64, 0x401200u, imm(0x2a), none, none);
    d->insts[0][1] = inst(1, PW_OP_ADD, PW_TY_I64, 0x401204u, imm(5), ssa(0), none); /* IMM before SSA */
    d->insts[0][2] = inst(2, PW_OP_BR_COND, PW_TY_VOID, 0x401208u, ssa(1), blk(1), blk(2));
    d->insts[0][3] = inst(3, PW_OP_BR, PW_TY_VOID, 0x401210u, blk(2), none, none);
    d->insts[0][4] = inst(4, PW_OP_RET, PW_TY_VOID, 0x401218u, ssa(1), none, none);
    d->funcs[0].hdr.func_id = 1;
    d->funcs[0].hdr.entry_va = 0x401200u;
    d->funcs[0].hdr.stack_frame_bytes = 32;
    d->funcs[0].blocks = d->blocks[0];
    d->funcs[0].block_count = 3;
    d->funcs[0].insts = d->insts[0];
    d->funcs[0].inst_count = 5;

    /* Function "B" (func_id 0, entry 0x401000): an indirect call through a
     * register, a commutative XOR given with operands descending, a return. */
    d->blocks[1][0] = block(0, 0, 3, 0, 0, 0, 0x401000u);
    d->insts[1][0] = inst(0, PW_OP_CALL_IND, PW_TY_I64, 0x401000u, ssa(9), none, none);
    d->insts[1][0].flags = 0x02u; /* is_abi_boundary */
    d->insts[1][1] = inst(1, PW_OP_XOR, PW_TY_I64, 0x401004u, ssa(7), ssa(0), none);
    d->insts[1][2] = inst(2, PW_OP_RET, PW_TY_VOID, 0x401008u, ssa(1), none, none);
    d->funcs[1].hdr.func_id = 0;
    d->funcs[1].hdr.entry_va = 0x401000u;
    d->funcs[1].blocks = d->blocks[1];
    d->funcs[1].block_count = 1;
    d->funcs[1].insts = d->insts[1];
    d->funcs[1].inst_count = 3;

    uint8_t digest_a[32], digest_b[32];
    pw_status_t st = (pw_status_t)pw_func_ir_digest(&d->funcs[0], digest_a);
    if (st != PW_OK) return st;
    st = (pw_status_t)pw_func_ir_digest(&d->funcs[1], digest_b);
    if (st != PW_OK) return st;

    /* Records, listed out of canonical order. */
    d->records[0].record_id = 0;
    d->records[0].verdict = PW_VERDICT_UNKNOWN;
    d->records[0].rule_id = PW_RULE_TRUST_BOUNDARY_CROSS;
    d->records[0].unknown_reason = PW_UNK_STRIPPED_STRIP_LIMIT;
    d->records[0].site_va = 0x401218u; /* no function link: all-zero digest */

    d->records[1].record_id = 1;
    d->records[1].verdict = PW_VERDICT_UNKNOWN;
    d->records[1].rule_id = PW_RULE_TRUST_BOUNDARY_CROSS;
    d->records[1].unknown_reason = PW_UNK_INDIRECT_CALL_TARGET;
    d->records[1].site_va = 0x401000u;
    memcpy(d->records[1].func_ir_sha256, digest_b, 32);

    d->records[2].record_id = 2;
    d->records[2].verdict = PW_VERDICT_PROVEN_COMPLIANT;
    d->records[2].rule_id = PW_RULE_HYBRID_PQC_VERIFIED;
    d->records[2].site_va = 0x401210u;
    memcpy(d->records[2].func_ir_sha256, digest_a, 32);

    d->input.container_format = 1; /* ELF64 */
    d->input.arch = PW_ARCH_X86_64;
    d->input.binary = binary;
    d->input.binary_len = binary_len;
    d->input.alloy_model = alloy;
    d->input.alloy_len = alloy_len;
    d->input.funcs = d->funcs;
    d->input.func_count = PW_DEMO_FUNCS;
    d->input.records = d->records;
    d->input.record_count = PW_DEMO_RECORDS;
    return PW_OK;
}
