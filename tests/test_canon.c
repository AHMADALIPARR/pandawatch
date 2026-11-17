/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Canonical serialization: commutative operand ordering, zero padding,
 * explicit little-endian packing, parse/serialize round trips. */
#include "pw_xray_bundle.h"
#include "pw_xray_canon.h"
#include "pw_test.h"

#include <string.h>

static pw_operand_t op(uint8_t kind, uint8_t type, uint32_t ref, uint64_t imm) {
    pw_operand_t o;
    memset(&o, 0, sizeof o);
    o.kind = kind; o.type = type; o.ref_id = ref; o.imm_val = imm;
    return o;
}

static pw_ir_inst_t mk(uint16_t opc, pw_operand_t a, pw_operand_t b) {
    pw_ir_inst_t i;
    memset(&i, 0, sizeof i);
    i.ssa_id = 3; i.opcode = opc; i.out_type = PW_TY_I32; i.source_va = 0x1000;
    i.src[0] = a; i.src[1] = b;
    return i;
}

int main(void) {
    const uint16_t comm[] = { PW_OP_ADD, PW_OP_MUL, PW_OP_XOR, PW_OP_AND, PW_OP_OR };
    const uint16_t noncomm[] = { PW_OP_SUB, PW_OP_SHL, PW_OP_SHR, PW_OP_ROTL, PW_OP_ROTR,
                                 PW_OP_CMP_LT, PW_OP_STORE };
    /* Ordered pairs that differ in each key position: kind, type, ref_id, imm_val. */
    const pw_operand_t lo[] = { op(1, 5, 9, 9), op(1, 4, 9, 9), op(1, 4, 2, 9), op(2, 4, 0, 1) };
    const pw_operand_t hi[] = { op(2, 0, 0, 0), op(1, 5, 0, 0), op(1, 4, 3, 0), op(2, 4, 0, 2) };
    uint8_t x[64], y[64];

    for (size_t k = 0; k < sizeof comm / sizeof comm[0]; ++k) {
        for (size_t p = 0; p < sizeof lo / sizeof lo[0]; ++p) {
            pw_ir_inst_t a = mk(comm[k], lo[p], hi[p]);
            pw_ir_inst_t b = mk(comm[k], hi[p], lo[p]);
            pw_serialize_ir_inst(&a, x);
            pw_serialize_ir_inst(&b, y);
            CHECK(memcmp(x, y, 64) == 0);          /* operand order does not matter */
            pw_ir_inst_t back;
            pw_parse_ir_inst(x, &back);
            CHECK(memcmp(&back.src[0], &lo[p], sizeof lo[p]) == 0); /* smaller first */
        }
    }
    for (size_t k = 0; k < sizeof noncomm / sizeof noncomm[0]; ++k) {
        pw_ir_inst_t a = mk(noncomm[k], lo[0], hi[0]);
        pw_ir_inst_t b = mk(noncomm[k], hi[0], lo[0]);
        pw_serialize_ir_inst(&a, x);
        pw_serialize_ir_inst(&b, y);
        CHECK(memcmp(x, y, 64) != 0);              /* order preserved */
    }

    /* Exact little-endian layout of one instruction; garbage in _pad0 is zeroed. */
    {
        pw_ir_inst_t i = mk(PW_OP_SUB, op(1, 4, 0x11223344u, 0), op(2, 4, 0, 0x0102030405060708ull));
        i.ssa_id = 0xA1B2C3D4u;
        i.source_va = 0x1122334455667788ull;
        i.flags = 0x03;
        i.src[0]._pad0 = 0xFFFF;
        pw_serialize_ir_inst(&i, x);
        const uint8_t want_head[16] = { 0xD4, 0xC3, 0xB2, 0xA1, 0x03, 0x00, 0x04, 0x03,
                                        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
        CHECK(memcmp(x, want_head, 16) == 0);
        const uint8_t want_src0[8] = { 0x01, 0x04, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11 };
        CHECK(memcmp(x + 16, want_src0, 8) == 0);
        const uint8_t want_imm1[8] = { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
        CHECK(memcmp(x + 40, want_imm1, 8) == 0);
    }

    /* Evidence record: padding and reserved forced to zero; LE fields. */
    {
        pw_evidence_record_t r;
        memset(&r, 0xAB, sizeof r);
        r.record_id = 7; r.verdict = PW_VERDICT_UNKNOWN; r.rule_id = PW_RULE_FIXED_WIRE_BUFFER;
        r.unknown_reason = PW_UNK_DYNAMIC_DLOPEN_SYM; r.detected_bytes = 64; r.required_bytes = 3309;
        r.site_va = 0x401000;
        pw_serialize_evidence_record(&r, x);
        CHECK(x[5] == 0);
        for (int i = 56; i < 64; ++i) CHECK(x[i] == 0);
        CHECK(x[6] == 0x02 && x[7] == 0x01);           /* rule 0x0102 */
        CHECK(x[12] == 0xED && x[13] == 0x0C);         /* 3309 = 0x0CED */
        pw_evidence_record_t back;
        pw_parse_evidence_record(x, &back);
        pw_serialize_evidence_record(&back, y);
        CHECK(memcmp(x, y, 64) == 0);
    }

    /* Block and function header round trips. */
    {
        pw_ir_block_t b = { 5, 6, 7, 2, { 8, 9 }, 0xDEADBEEFCAFEull }, b2;
        pw_serialize_ir_block(&b, x);
        pw_parse_ir_block(x, &b2);
        CHECK(memcmp(&b, &b2, sizeof b) == 0);
        pw_ir_func_hdr_t f, f2;
        memset(&f, 0, sizeof f);
        f.func_id = 1; f.block_count = 2; f.inst_count = 3; f.stack_frame_bytes = 4;
        f.entry_va = 0x55; memset(f.ir_sha256, 0x5A, 32); f._reserved = 0x77;
        pw_serialize_func_hdr(&f, x);
        pw_parse_func_hdr(x, &f2);
        CHECK(f2._reserved == 0);
        f._reserved = 0;
        CHECK(memcmp(&f, &f2, sizeof f) == 0);
    }
    return TEST_DONE("test_canon");
}
