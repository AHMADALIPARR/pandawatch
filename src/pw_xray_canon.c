#include "pw_xray_ir.h"
#include "pw_xray_evidence.h"
#include <string.h>

static inline void put_u8(uint8_t *dst, size_t *off, uint8_t v) {
    dst[(*off)++] = v;
}

static inline void put_u16_le(uint8_t *dst, size_t *off, uint16_t v) {
    dst[(*off)++] = (uint8_t)(v & 0xFFU);
    dst[(*off)++] = (uint8_t)((v >> 8) & 0xFFU);
}

static inline void put_u32_le(uint8_t *dst, size_t *off, uint32_t v) {
    dst[(*off)++] = (uint8_t)(v & 0xFFU);
    dst[(*off)++] = (uint8_t)((v >> 8) & 0xFFU);
    dst[(*off)++] = (uint8_t)((v >> 16) & 0xFFU);
    dst[(*off)++] = (uint8_t)((v >> 24) & 0xFFU);
}

static inline void put_u64_le(uint8_t *dst, size_t *off, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        dst[(*off)++] = (uint8_t)((v >> (i * 8)) & 0xFFULL);
    }
}

static int operand_cmp(const pw_operand_t *a, const pw_operand_t *b) {
    if (a->kind != b->kind) return (a->kind < b->kind) ? -1 : 1;
    if (a->type != b->type) return (a->type < b->type) ? -1 : 1;
    if (a->ref_id != b->ref_id) return (a->ref_id < b->ref_id) ? -1 : 1;
    if (a->imm_val != b->imm_val) return (a->imm_val < b->imm_val) ? -1 : 1;
    return 0;
}

static int is_commutative_op(uint16_t op) {
    return (op == PW_OP_ADD || op == PW_OP_MUL ||
            op == PW_OP_XOR || op == PW_OP_AND || op == PW_OP_OR);
}

/* Serializes one pw_ir_inst_t into exactly 64 canonical bytes */
void pw_serialize_ir_inst(const pw_ir_inst_t *in, uint8_t out[64]) {
    pw_ir_inst_t norm = *in;
    if (is_commutative_op(norm.opcode) && operand_cmp(&norm.src[0], &norm.src[1]) > 0) {
        pw_operand_t tmp = norm.src[0];
        norm.src[0] = norm.src[1];
        norm.src[1] = tmp;
    }

    size_t off = 0;
    put_u32_le(out, &off, norm.ssa_id);
    put_u16_le(out, &off, norm.opcode);
    put_u8(out, &off, norm.out_type);
    put_u8(out, &off, norm.flags);
    put_u64_le(out, &off, norm.source_va);

    for (int i = 0; i < 3; ++i) {
        put_u8(out, &off, norm.src[i].kind);
        put_u8(out, &off, norm.src[i].type);
        put_u16_le(out, &off, 0); /* Enforce zero padding */
        put_u32_le(out, &off, norm.src[i].ref_id);
        put_u64_le(out, &off, norm.src[i].imm_val);
    }
}

/* Serializes one pw_evidence_record_t into exactly 64 canonical bytes */
void pw_serialize_evidence_record(const pw_evidence_record_t *rec, uint8_t out[64]) {
    size_t off = 0;
    put_u32_le(out, &off, rec->record_id);
    put_u8(out, &off, rec->verdict);
    put_u8(out, &off, 0); /* Enforce zero padding */
    put_u16_le(out, &off, rec->rule_id);
    put_u16_le(out, &off, rec->unknown_reason);
    put_u16_le(out, &off, rec->detected_bytes);
    put_u32_le(out, &off, rec->required_bytes);
    put_u64_le(out, &off, rec->site_va);
    memcpy(out + off, rec->func_ir_sha256, 32);
    off += 32;
    put_u64_le(out, &off, 0); /* Reserved zero */
}

