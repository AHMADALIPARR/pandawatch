/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Mnemonics, Intel-syntax formatting and PW_OP mapping for decoded x86-64
 * instructions. C23. */
#include "pw_x86.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char *const reg64[16] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
};
static const char *const reg32[16] = {
    "eax",  "ecx",  "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
    "r8d",  "r9d",  "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
};
static const char *const jcc_names[16] = {
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
};
static const char *const names[] = {
    [PW_X86_NOP] = "nop",   [PW_X86_RET] = "ret",     [PW_X86_INT3] = "int3",
    [PW_X86_PUSH] = "push", [PW_X86_POP] = "pop",     [PW_X86_MOV] = "mov",
    [PW_X86_MOVABS] = "movabs", [PW_X86_LEA] = "lea", [PW_X86_ADD] = "add",
    [PW_X86_OR] = "or",     [PW_X86_AND] = "and",     [PW_X86_SUB] = "sub",
    [PW_X86_XOR] = "xor",   [PW_X86_CMP] = "cmp",     [PW_X86_TEST] = "test",
    [PW_X86_CALL] = "call", [PW_X86_JMP] = "jmp",     [PW_X86_JCC] = "jcc",
    [PW_X86_INVALID] = "(bad)"
};

/* Group 1 (0x81/0x83) by ModRM.reg; 2 and 3 (adc/sbb) are not decoded. */
static const pw_x86_mnem_t grp1[8] = {
    PW_X86_ADD, PW_X86_OR, PW_X86_INVALID, PW_X86_INVALID,
    PW_X86_AND, PW_X86_SUB, PW_X86_XOR, PW_X86_CMP
};

pw_x86_mnem_t pw_x86_mnemonic(const pw_x86_insn_t *in) {
    if (in->escape) return PW_X86_JCC;
    const uint8_t op = in->opcode;
    switch (op) {
    case 0x90: return PW_X86_NOP;
    case 0xC3: return PW_X86_RET;
    case 0xCC: return PW_X86_INT3;
    case 0x01: case 0x03: return PW_X86_ADD;
    case 0x09: case 0x0B: return PW_X86_OR;
    case 0x21: case 0x23: return PW_X86_AND;
    case 0x29: case 0x2B: return PW_X86_SUB;
    case 0x31: case 0x33: return PW_X86_XOR;
    case 0x39: case 0x3B: return PW_X86_CMP;
    case 0x85: return PW_X86_TEST;
    case 0x89: case 0x8B: case 0xC7: return PW_X86_MOV;
    case 0x8D: return PW_X86_LEA;
    case 0x81: case 0x83: return grp1[(in->modrm >> 3) & 7];
    case 0xE8: return PW_X86_CALL;
    case 0xE9: case 0xEB: return PW_X86_JMP;
    case 0xFF: return ((in->modrm >> 3) & 7) == 2 ? PW_X86_CALL : PW_X86_JMP;
    default: break;
    }
    if (op >= 0x50 && op <= 0x57) return PW_X86_PUSH;
    if (op >= 0x58 && op <= 0x5F) return PW_X86_POP;
    if (op >= 0x70 && op <= 0x7F) return PW_X86_JCC;
    if (op >= 0xB8 && op <= 0xBF) return (in->rex & 8) ? PW_X86_MOVABS : PW_X86_MOV;
    return PW_X86_INVALID;
}

const char *pw_x86_mnemonic_name(const pw_x86_insn_t *in) {
    const pw_x86_mnem_t m = pw_x86_mnemonic(in);
    if (m == PW_X86_JCC) return jcc_names[in->opcode & 0x0F];
    return names[m];
}

static bool is_wide(const pw_x86_insn_t *in) { return (in->rex & 8) != 0; }

typedef struct {
    char  *p;
    size_t cap;
    size_t n;
} sbuf_t;

[[gnu::format(printf, 2, 3)]]
static void put(sbuf_t *s, const char *fmt, ...);

static void put(sbuf_t *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    const size_t room = s->n < s->cap ? s->cap - s->n : 0;
    const int w = vsnprintf(s->p + s->n, room, fmt, ap);
    va_end(ap);
    if (w > 0) s->n += (size_t)w;
}

static void put_hex(sbuf_t *s, int64_t v) {
    if (v < 0) put(s, "-0x%" PRIx64, (uint64_t)0 - (uint64_t)v);
    else put(s, "0x%" PRIx64, (uint64_t)v);
}

static void put_mem(sbuf_t *s, const pw_x86_insn_t *in, const char *size_kw) {
    if (size_kw) put(s, "%s ptr ", size_kw);
    put(s, "[");
    bool first = true;
    if (in->base == PW_X86_RIP) {
        put(s, "rip");
        first = false;
    } else if (in->base != PW_X86_NO_REG) {
        put(s, "%s", reg64[in->base]);
        first = false;
    }
    if (in->index != PW_X86_NO_REG) {
        put(s, "%s%s*%u", first ? "" : "+", reg64[in->index], (unsigned)in->scale);
        first = false;
    }
    const bool gpr_base = in->base != PW_X86_RIP && in->base != PW_X86_NO_REG;
    if (in->disp_size && !(gpr_base && in->disp == 0)) {
        if (first) put_hex(s, (int64_t)(uint32_t)in->disp);
        else if (in->disp < 0) put(s, "-0x%" PRIx32, (uint32_t)0 - (uint32_t)in->disp);
        else put(s, "+0x%" PRIx32, (uint32_t)in->disp);
    }
    put(s, "]");
}

static void put_rm(sbuf_t *s, const pw_x86_insn_t *in, bool wide, const char *size_kw) {
    if (in->mod == 3) put(s, "%s", wide ? reg64[in->rm] : reg32[in->rm]);
    else put_mem(s, in, size_kw);
}

int pw_x86_format(const pw_x86_insn_t *in, uint64_t addr, char *out, size_t cap) {
    sbuf_t s = { .p = out, .cap = cap, .n = 0 };
    if (cap) out[0] = '\0';
    const pw_x86_mnem_t m = pw_x86_mnemonic(in);
    if (m == PW_X86_INVALID) return -1;
    const char *name = pw_x86_mnemonic_name(in);
    const bool w = is_wide(in);
    const uint8_t op = in->opcode;
    const uint64_t next = addr + in->length;

    switch (m) {
    case PW_X86_NOP: case PW_X86_RET: case PW_X86_INT3:
        put(&s, "%s", name);
        break;
    case PW_X86_PUSH: case PW_X86_POP:
        put(&s, "%s %s", name, reg64[in->reg]);
        break;
    case PW_X86_MOVABS:
        put(&s, "movabs %s, ", reg64[in->reg]);
        put_hex(&s, in->imm);
        break;
    case PW_X86_JCC:
        put(&s, "%s %s0x%" PRIx64, name, in->imm_size == 1 ? "short " : "",
            next + (uint64_t)in->imm);
        break;
    default:
        if (!in->has_modrm) {               /* B8+r, E8, E9, EB */
            if (op >= 0xB8 && op <= 0xBF) {
                put(&s, "mov %s, ", reg32[in->reg]);
                put_hex(&s, (int64_t)(uint32_t)in->imm);
            } else {
                put(&s, "%s %s0x%" PRIx64, name, in->imm_size == 1 ? "short " : "",
                    next + (uint64_t)in->imm);
            }
            break;
        }
        if (op == 0xFF) {
            put(&s, "%s ", name);
            put_rm(&s, in, true, "qword");
        } else if (op == 0x81 || op == 0x83 || op == 0xC7) {
            put(&s, "%s ", name);
            put_rm(&s, in, w, w ? "qword" : "dword");
            put(&s, ", ");
            if (op == 0xC7 && !w) put_hex(&s, (int64_t)(uint32_t)in->imm);
            else put_hex(&s, w ? in->imm : (int64_t)(int32_t)in->imm);
        } else if (op == 0x8D || (op & 0x02)) {   /* reg, r/m forms: 03 0B 23 2B 33 3B 8B 8D */
            put(&s, "%s %s, ", name, w ? reg64[in->reg] : reg32[in->reg]);
            put_rm(&s, in, w, nullptr);
        } else {                              /* r/m, reg forms: 01 09 21 29 31 39 85 89 */
            put(&s, "%s ", name);
            put_rm(&s, in, w, nullptr);
            put(&s, ", %s", w ? reg64[in->reg] : reg32[in->reg]);
        }
        break;
    }
    return (int)s.n;
}

uint16_t pw_x86_to_pw_op(const pw_x86_insn_t *in) {
    switch (pw_x86_mnemonic(in)) {
    case PW_X86_NOP: case PW_X86_INT3: return PW_OP_NOP;
    case PW_X86_RET: return PW_OP_RET;
    case PW_X86_PUSH: return PW_OP_STORE;
    case PW_X86_POP: return PW_OP_LOAD;
    case PW_X86_MOV:
        if (!in->has_modrm || in->opcode == 0xC7) return in->mod == 3 || !in->has_modrm
                                                         ? PW_OP_CONST : PW_OP_STORE;
        if (in->mod == 3) return PW_OP_ADD;            /* reg copy: dst = src + 0 */
        return in->opcode == 0x8B ? PW_OP_LOAD : PW_OP_STORE;
    case PW_X86_MOVABS: return PW_OP_CONST;
    case PW_X86_LEA: case PW_X86_ADD: return PW_OP_ADD;
    case PW_X86_OR: return PW_OP_OR;
    case PW_X86_AND: return PW_OP_AND;
    case PW_X86_SUB: return PW_OP_SUB;
    case PW_X86_XOR: return PW_OP_XOR;
    case PW_X86_CMP: case PW_X86_TEST: return PW_OP_CMP_EQ;
    case PW_X86_CALL: return in->opcode == 0xE8 ? PW_OP_CALL_DIR : PW_OP_CALL_IND;
    case PW_X86_JMP: return PW_OP_BR;
    case PW_X86_JCC: return PW_OP_BR_COND;
    case PW_X86_INVALID: break;
    }
    return PW_OP_NOP;
}
