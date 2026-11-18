/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Lifts a raw x86-64 code blob (decoded by asm/pw_x86_decode.S) into one
 * pw_ir function and writes a .pwxray bundle through pw_bundle_write. C23. */
#include "pw_x86.h"

#include <stdlib.h>
#include <string.h>

static pw_operand_t op_reg(uint8_t reg, bool wide) {
    return (pw_operand_t){ .kind = PW_OPERAND_SSA, .type = wide ? PW_TY_I64 : PW_TY_I32,
                           .ref_id = reg };
}
static pw_operand_t op_imm(int64_t v, uint8_t type) {
    return (pw_operand_t){ .kind = PW_OPERAND_IMM, .type = type, .imm_val = (uint64_t)v };
}
static pw_operand_t op_block(uint32_t id) {
    return (pw_operand_t){ .kind = PW_OPERAND_BLOCK, .ref_id = id };
}

typedef struct {
    pw_x86_insn_t d;
    uint64_t      va;
    uint64_t      target;     /* direct branch/call target */
    bool          has_target;
    bool          ends_block;
    bool          falls_through;
} site_t;

static bool is_branch(pw_x86_mnem_t m) {
    return m == PW_X86_JMP || m == PW_X86_JCC || m == PW_X86_RET;
}

/* Index of the site starting at va, or -1. Sites are sorted by va. */
static long find_site(const site_t *s, size_t n, uint64_t va) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (s[mid].va < va) lo = mid + 1;
        else hi = mid;
    }
    return (lo < n && s[lo].va == va) ? (long)lo : -1;
}

/* Memory or register r/m operand as (base-or-reg, displacement). */
static void rm_operands(const pw_x86_insn_t *in, bool wide, pw_operand_t *a, pw_operand_t *disp) {
    if (in->mod == 3) {
        *a = op_reg(in->rm, wide);
        *disp = (pw_operand_t){ 0 };
        return;
    }
    if (in->base == PW_X86_NO_REG) *a = op_imm(in->disp, PW_TY_PTR);
    else *a = (pw_operand_t){ .kind = PW_OPERAND_SSA, .type = PW_TY_PTR, .ref_id = in->base };
    *disp = op_imm(in->disp, PW_TY_I64);
}

pw_status_t pw_x86_lift_bundle(const uint8_t *blob, size_t len, uint64_t base,
                               const uint8_t *alloy, size_t alloy_len,
                               uint8_t **bundle, size_t *bundle_len,
                               uint32_t *inst_count, uint32_t *block_count) {
    if ((len && blob == nullptr) || bundle == nullptr || bundle_len == nullptr) return PW_E_ARG;
    pw_status_t st = PW_OK;
    site_t *sites = calloc(len ? len : 1, sizeof *sites);
    pw_ir_inst_t *insts = nullptr;
    pw_ir_block_t *blocks = nullptr;
    uint32_t *block_of = nullptr;
    pw_evidence_record_t *recs = nullptr;
    if (sites == nullptr) return PW_E_NOMEM;

    /* 1. Linear sweep. */
    size_t n = 0;
    for (size_t off = 0; off < len;) {
        site_t *s = &sites[n];
        const size_t l = pw_x86_decode(blob + off, len - off, &s->d);
        if (l == 0 || pw_x86_mnemonic(&s->d) == PW_X86_INVALID) { st = PW_E_ARG; goto done; }
        s->va = base + off;
        const pw_x86_mnem_t m = pw_x86_mnemonic(&s->d);
        if ((m == PW_X86_JMP || m == PW_X86_JCC || m == PW_X86_CALL) && !s->d.has_modrm) {
            s->has_target = true;
            s->target = s->va + l + (uint64_t)s->d.imm;
        }
        s->ends_block = is_branch(m);
        s->falls_through = !(m == PW_X86_JMP || m == PW_X86_RET);
        off += l;
        n++;
    }

    /* 2. Leaders: entry, in-blob branch targets, and instructions after a branch. */
    bool *leader = calloc(n ? n : 1, sizeof *leader);
    if (leader == nullptr) { st = PW_E_NOMEM; goto done; }
    if (n) leader[0] = true;
    for (size_t i = 0; i < n; i++) {
        const pw_x86_mnem_t m = pw_x86_mnemonic(&sites[i].d);
        if (sites[i].has_target && m != PW_X86_CALL) {
            const long t = find_site(sites, n, sites[i].target);
            if (t >= 0) leader[t] = true;
        }
        if (sites[i].ends_block && i + 1 < n) leader[i + 1] = true;
    }
    uint32_t nb = 0;
    block_of = calloc(n ? n : 1, sizeof *block_of);
    blocks = calloc(n ? n : 1, sizeof *blocks);
    insts = calloc(n ? n : 1, sizeof *insts);
    if (block_of == nullptr || blocks == nullptr || insts == nullptr) {
        free(leader);
        st = PW_E_NOMEM;
        goto done;
    }
    for (size_t i = 0; i < n; i++) {
        if (leader[i]) {
            blocks[nb] = (pw_ir_block_t){ .block_id = nb, .first_inst = (uint32_t)i,
                                          .start_va = sites[i].va };
            nb++;
        }
        block_of[i] = nb - 1;
        blocks[nb - 1].inst_count++;
    }
    free(leader);

    /* 3. Successor edges from each block's last instruction. */
    for (uint32_t b = 0; b < nb; b++) {
        const size_t last = blocks[b].first_inst + blocks[b].inst_count - 1;
        const site_t *s = &sites[last];
        const pw_x86_mnem_t m = pw_x86_mnemonic(&s->d);
        uint32_t succ[2];
        uint32_t ns = 0;
        if (s->has_target && m != PW_X86_CALL) {
            const long t = find_site(sites, n, s->target);
            if (t >= 0) succ[ns++] = block_of[t];
        }
        if (s->falls_through && last + 1 < n) {
            const uint32_t f = block_of[last + 1];
            if (ns == 0 || succ[0] != f) succ[ns++] = f;
        }
        if (ns == 2 && succ[0] > succ[1]) { const uint32_t t = succ[0]; succ[0] = succ[1]; succ[1] = t; }
        blocks[b].succ_count = ns;
        for (uint32_t k = 0; k < ns; k++) blocks[b].succ_blocks[k] = succ[k];
    }

    /* 4. Instructions. */
    uint32_t nrec = 0;
    recs = calloc(n ? n : 1, sizeof *recs);
    if (recs == nullptr) { st = PW_E_NOMEM; goto done; }
    for (size_t i = 0; i < n; i++) {
        const pw_x86_insn_t *d = &sites[i].d;
        const pw_x86_mnem_t m = pw_x86_mnemonic(d);
        const bool w = (d->rex & 8) != 0;
        pw_ir_inst_t *ir = &insts[i];
        ir->ssa_id = (uint32_t)i;
        ir->opcode = pw_x86_to_pw_op(d);
        ir->source_va = sites[i].va;
        ir->out_type = w ? PW_TY_I64 : PW_TY_I32;
        pw_operand_t a = { 0 }, disp = { 0 };
        switch (m) {
        case PW_X86_NOP: case PW_X86_INT3: case PW_X86_RET:
            ir->out_type = PW_TY_VOID;
            if (m == PW_X86_RET) ir->flags = 0x02u;
            break;
        case PW_X86_PUSH: case PW_X86_POP:
            ir->out_type = PW_TY_I64;
            ir->src[0] = op_reg(4, true);          /* rsp */
            ir->src[1] = op_reg(d->reg, true);
            break;
        case PW_X86_MOVABS:
            ir->out_type = PW_TY_I64;
            ir->src[0] = op_imm(d->imm, PW_TY_I64);
            break;
        case PW_X86_JMP: case PW_X86_JCC: case PW_X86_CALL: {
            ir->out_type = m == PW_X86_CALL ? PW_TY_I64 : PW_TY_VOID;
            if (m == PW_X86_CALL) ir->flags = 0x02u;
            if (sites[i].has_target) {
                const long t = m == PW_X86_CALL ? -1 : find_site(sites, n, sites[i].target);
                ir->src[0] = t >= 0 ? op_block(block_of[t]) : op_imm((int64_t)sites[i].target, PW_TY_PTR);
                if (m == PW_X86_JCC) {
                    ir->src[1] = op_imm(d->opcode & 0x0F, PW_TY_I8);  /* condition code */
                    if (i + 1 < n) ir->src[2] = op_block(block_of[i + 1]);
                }
            } else {
                rm_operands(d, true, &ir->src[0], &ir->src[1]);
                recs[nrec] = (pw_evidence_record_t){
                    .record_id = nrec,
                    .verdict = PW_VERDICT_UNKNOWN,
                    .rule_id = PW_RULE_TRUST_BOUNDARY_CROSS,
                    .unknown_reason = m == PW_X86_CALL ? PW_UNK_INDIRECT_CALL_TARGET
                                                       : PW_UNK_STRIPPED_JUMP_TABLE,
                    .site_va = sites[i].va,
                };
                nrec++;
            }
            break;
        }
        default:
            if (!d->has_modrm) {                       /* B8+r mov r32, imm32 */
                ir->src[0] = op_imm((int64_t)(uint32_t)d->imm, PW_TY_I32);
                break;
            }
            rm_operands(d, w, &a, &disp);
            if (d->opcode == 0x8D) {                   /* lea: base + disp */
                ir->out_type = PW_TY_PTR;
                ir->src[0] = a;
                ir->src[1] = disp;
                if (d->index != PW_X86_NO_REG)
                    ir->src[2] = (pw_operand_t){ .kind = PW_OPERAND_SSA, .type = PW_TY_I64,
                                                 .ref_id = d->index, .imm_val = 0 };
            } else if (d->opcode == 0x81 || d->opcode == 0x83 || d->opcode == 0xC7) {
                ir->src[0] = a;
                ir->src[1] = op_imm(d->imm, w ? PW_TY_I64 : PW_TY_I32);
                ir->src[2] = disp;
            } else if (m == PW_X86_MOV && d->mod == 3) {
                ir->src[0] = a;                        /* copy: rm + 0 */
                ir->src[1] = op_imm(0, w ? PW_TY_I64 : PW_TY_I32);
            } else {
                ir->src[0] = a;
                ir->src[1] = op_reg(d->reg, w);
                ir->src[2] = disp;
            }
            break;
        }
    }

    pw_func_input_t fn = {
        .hdr = { .func_id = 0, .entry_va = base },
        .blocks = blocks, .block_count = nb,
        .insts = insts, .inst_count = (uint32_t)n,
    };
    uint8_t digest[32];
    st = (pw_status_t)pw_func_ir_digest(&fn, digest);
    if (st != PW_OK) goto done;
    for (uint32_t r = 0; r < nrec; r++) memcpy(recs[r].func_ir_sha256, digest, 32);

    const pw_bundle_input_t bi = {
        .container_format = 1,
        .arch = PW_ARCH_X86_64,
        .binary = blob, .binary_len = len,
        .alloy_model = alloy, .alloy_len = alloy_len,
        .funcs = &fn, .func_count = 1,
        .records = recs, .record_count = nrec,
    };
    st = pw_bundle_write(&bi, bundle, bundle_len);
    if (st == PW_OK) {
        if (inst_count) *inst_count = (uint32_t)n;
        if (block_count) *block_count = nb;
    }

done:
    free(sites);
    free(insts);
    free(blocks);
    free(block_of);
    free(recs);
    return st;
}
