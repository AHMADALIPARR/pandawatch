/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Two-pass Intel-syntax assembler for the x86-64 subset that
 * asm/pw_x86_decode.S decodes. Encodings follow GNU as for the same text:
 * reg,reg uses the r/m,reg opcode; immediates and displacements take the
 * shortest form; branches are rel32 unless written `short`. C23. */
#include "pw_x86.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

constexpr size_t MAX_LABELS = 4096;
constexpr size_t MAX_NAME = 64;
constexpr size_t MAX_LINE = 512;

typedef enum : uint8_t { OP_NONE, OP_REG, OP_MEM, OP_IMM, OP_LABEL } opkind_t;

typedef struct {
    opkind_t kind;
    uint8_t  reg;        /* OP_REG: 0..15 */
    uint8_t  width;      /* OP_REG: 32 or 64; OP_MEM: ptr size or 0 */
    uint8_t  base;       /* OP_MEM: register, PW_X86_NO_REG or PW_X86_RIP */
    uint8_t  index;      /* OP_MEM: register or PW_X86_NO_REG */
    uint8_t  scale;      /* OP_MEM */
    int64_t  disp;       /* OP_MEM */
    int64_t  imm;        /* OP_IMM, and OP_LABEL after resolution */
    char     label[MAX_NAME];
} operand_t;

typedef struct {
    char     name[MAX_NAME];
    uint64_t addr;
} label_t;

typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
    bool     oom;
    label_t *labels;
    size_t   nlabels;
    bool     final_pass;
    uint64_t base;
    char    *err;
    size_t   err_cap;
    unsigned line;
} asm_t;

[[gnu::format(printf, 2, 3)]]
static int fail(asm_t *a, const char *fmt, ...) {
    if (a->err && a->err_cap) {
        int n = snprintf(a->err, a->err_cap, "line %u: ", a->line);
        if (n < 0) n = 0;
        if ((size_t)n < a->err_cap) {
            va_list ap;
            va_start(ap, fmt);
            vsnprintf(a->err + n, a->err_cap - (size_t)n, fmt, ap);
            va_end(ap);
        }
    }
    return -1;
}

static void emit(asm_t *a, uint8_t b) {
    if (a->len == a->cap) {
        const size_t ncap = a->cap ? a->cap * 2 : 256;
        uint8_t *nb = realloc(a->buf, ncap);
        if (nb == nullptr) { a->oom = true; return; }
        a->buf = nb;
        a->cap = ncap;
    }
    a->buf[a->len++] = b;
}

static void emit_le(asm_t *a, uint64_t v, unsigned n) {
    for (unsigned i = 0; i < n; i++) emit(a, (uint8_t)(v >> (8 * i)));
}

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

static bool parse_reg(const char *s, uint8_t *reg, uint8_t *width) {
    for (uint8_t i = 0; i < 16; i++) {
        if (strcmp(s, reg64[i]) == 0) { *reg = i; *width = 64; return true; }
        if (strcmp(s, reg32[i]) == 0) { *reg = i; *width = 32; return true; }
    }
    return false;
}

static bool is_ident(const char *s) {
    if (!(isalpha((unsigned char)*s) || *s == '_' || *s == '.')) return false;
    for (s++; *s; s++)
        if (!(isalnum((unsigned char)*s) || *s == '_' || *s == '.' || *s == '$')) return false;
    return true;
}

static bool parse_num(const char *s, int64_t *out) {
    bool neg = false;
    if (*s == '+' || *s == '-') { neg = (*s == '-'); s++; }
    if (!isdigit((unsigned char)*s)) return false;
    char *end = nullptr;
    const unsigned long long v = strtoull(s, &end, 0);
    if (end == s || *end != '\0') return false;
    *out = neg ? (int64_t)(0ULL - v) : (int64_t)v;
    return true;
}

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

static int parse_mem(asm_t *a, char *s, operand_t *op) {
    op->kind = OP_MEM;
    op->base = PW_X86_NO_REG;
    op->index = PW_X86_NO_REG;
    op->scale = 1;
    op->disp = 0;
    /* s is the text between the brackets; terms are joined by + or -. */
    char *p = s;
    while (*p) {
        int sign = 1;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '+') { p++; }
        else if (*p == '-') { sign = -1; p++; }
        while (isspace((unsigned char)*p)) p++;
        char term[MAX_NAME];
        size_t n = 0;
        while (*p && *p != '+' && *p != '-' && n + 1 < sizeof term) term[n++] = *p++;
        term[n] = '\0';
        char *t = trim(term);
        if (*t == '\0') return fail(a, "empty term in memory operand");
        char *star = strchr(t, '*');
        uint8_t r = 0, w = 0;
        if (star) {
            *star = '\0';
            char *rs = trim(t);
            int64_t sc = 0;
            if (!parse_reg(rs, &r, &w) || w != 64) return fail(a, "bad index register '%s'", rs);
            if (!parse_num(trim(star + 1), &sc) || (sc != 1 && sc != 2 && sc != 4 && sc != 8))
                return fail(a, "bad scale");
            if (sign < 0 || op->index != PW_X86_NO_REG) return fail(a, "bad index term");
            if (r == 4) return fail(a, "rsp cannot be an index");
            op->index = r;
            op->scale = (uint8_t)sc;
        } else if (strcmp(t, "rip") == 0) {
            if (sign < 0 || op->base != PW_X86_NO_REG) return fail(a, "bad rip term");
            op->base = PW_X86_RIP;
        } else if (parse_reg(t, &r, &w)) {
            if (w != 64 || sign < 0) return fail(a, "bad register term '%s'", t);
            if (op->base == PW_X86_NO_REG) op->base = r;
            else if (op->index == PW_X86_NO_REG && r != 4) op->index = r;
            else return fail(a, "too many registers");
        } else {
            int64_t v = 0;
            if (!parse_num(t, &v)) return fail(a, "bad displacement '%s'", t);
            op->disp += sign * v;
        }
    }
    if (op->base == PW_X86_RIP && op->index != PW_X86_NO_REG) return fail(a, "rip with index");
    const bool absolute = op->base == PW_X86_NO_REG;
    if (absolute ? (op->disp < INT32_MIN || op->disp > (int64_t)UINT32_MAX)
                 : (op->disp < INT32_MIN || op->disp > INT32_MAX))
        return fail(a, "displacement out of range");
    if (absolute && op->disp > INT32_MAX) op->disp = (int32_t)(uint32_t)op->disp;
    return 0;
}

static int parse_operand(asm_t *a, char *s, operand_t *op) {
    memset(op, 0, sizeof *op);
    s = trim(s);
    uint8_t ptr = 0;
    if (strncmp(s, "qword ptr", 9) == 0) { ptr = 64; s = trim(s + 9); }
    else if (strncmp(s, "dword ptr", 9) == 0) { ptr = 32; s = trim(s + 9); }
    if (*s == '[') {
        char *close = strrchr(s, ']');
        if (close == nullptr || trim(close + 1)[0] != '\0') return fail(a, "unterminated '['");
        *close = '\0';
        if (parse_mem(a, s + 1, op) != 0) return -1;
        op->width = ptr;
        return 0;
    }
    if (ptr) return fail(a, "'ptr' needs a memory operand");
    if (parse_reg(s, &op->reg, &op->width)) { op->kind = OP_REG; return 0; }
    if (parse_num(s, &op->imm)) { op->kind = OP_IMM; return 0; }
    if (is_ident(s) && strlen(s) < MAX_NAME) {
        op->kind = OP_LABEL;
        strcpy(op->label, s);
        return 0;
    }
    return fail(a, "bad operand '%s'", s);
}

static void emit_rex(asm_t *a, bool w, uint8_t r, uint8_t x, uint8_t b) {
    const uint8_t rex = (uint8_t)(0x40 | (w ? 8 : 0) | ((r >> 3) & 1) << 2 | ((x >> 3) & 1) << 1 |
                                  ((b >> 3) & 1));
    if (rex != 0x40) emit(a, rex);
}

/* Emits REX (with W), the opcode bytes and the ModRM/SIB/disp for `rm`. */
static void emit_modrm_insn(asm_t *a, bool w, const uint8_t *opc, size_t nopc, uint8_t regfield,
                            const operand_t *rm) {
    if (rm->kind == OP_REG) {
        emit_rex(a, w, regfield, 0, rm->reg);
        for (size_t i = 0; i < nopc; i++) emit(a, opc[i]);
        emit(a, (uint8_t)(0xC0 | (regfield & 7) << 3 | (rm->reg & 7)));
        return;
    }
    const uint8_t idx = rm->index == PW_X86_NO_REG ? 0 : rm->index;
    const uint8_t bas = (rm->base == PW_X86_NO_REG || rm->base == PW_X86_RIP) ? 0 : rm->base;
    emit_rex(a, w, regfield, idx, bas);
    for (size_t i = 0; i < nopc; i++) emit(a, opc[i]);
    const uint8_t r3 = (uint8_t)((regfield & 7) << 3);
    if (rm->base == PW_X86_RIP) {
        emit(a, (uint8_t)(0x05 | r3));
        emit_le(a, (uint64_t)rm->disp, 4);
        return;
    }
    uint8_t ss = 0;
    switch (rm->scale) { case 2: ss = 1; break; case 4: ss = 2; break; case 8: ss = 3; break; default: break; }
    const uint8_t sidx = (uint8_t)(rm->index == PW_X86_NO_REG ? 4 : (rm->index & 7));
    if (rm->base == PW_X86_NO_REG) {
        emit(a, (uint8_t)(0x04 | r3));
        emit(a, (uint8_t)(ss << 6 | sidx << 3 | 5));
        emit_le(a, (uint64_t)rm->disp, 4);
        return;
    }
    uint8_t mod;
    if (rm->disp == 0 && (rm->base & 7) != 5) mod = 0;
    else if (rm->disp >= -128 && rm->disp <= 127) mod = 1;
    else mod = 2;
    const bool need_sib = rm->index != PW_X86_NO_REG || (rm->base & 7) == 4;
    if (need_sib) {
        emit(a, (uint8_t)(mod << 6 | r3 | 4));
        emit(a, (uint8_t)(ss << 6 | sidx << 3 | (rm->base & 7)));
    } else {
        emit(a, (uint8_t)(mod << 6 | r3 | (rm->base & 7)));
    }
    if (mod == 1) emit(a, (uint8_t)rm->disp);
    else if (mod == 2) emit_le(a, (uint64_t)rm->disp, 4);
}

static int resolve(asm_t *a, operand_t *op) {
    if (op->kind != OP_LABEL) return 0;
    for (size_t i = 0; i < a->nlabels; i++) {
        if (strcmp(a->labels[i].name, op->label) == 0) {
            op->imm = (int64_t)a->labels[i].addr;
            op->kind = OP_IMM;
            return 0;
        }
    }
    if (a->final_pass) return fail(a, "undefined label '%s'", op->label);
    op->imm = (int64_t)a->base;
    op->kind = OP_IMM;
    return 0;
}

/* Relative branch: `opc` then rel of `rsz` bytes measured from the end. */
static int emit_rel(asm_t *a, const uint8_t *opc, size_t nopc, unsigned rsz, int64_t target) {
    const int64_t here = (int64_t)(a->base + a->len);
    const int64_t rel = target - (here + (int64_t)nopc + (int64_t)rsz);
    if (a->final_pass) {
        if (rsz == 1 && (rel < -128 || rel > 127)) return fail(a, "short branch out of range");
        if (rsz == 4 && (rel < INT32_MIN || rel > INT32_MAX)) return fail(a, "branch out of range");
    }
    for (size_t i = 0; i < nopc; i++) emit(a, opc[i]);
    emit_le(a, (uint64_t)rel, rsz);
    return 0;
}

static bool fits8(int64_t v) { return v >= -128 && v <= 127; }

/* 32-bit operations take immediates in [-2^31, 2^32); returns the int32 value. */
static int imm_for_width(asm_t *a, int64_t v, uint8_t width, int64_t *out) {
    if (width == 32) {
        if (v < INT32_MIN || v > (int64_t)UINT32_MAX) return fail(a, "immediate out of range");
        *out = (int32_t)(uint32_t)v;
    } else {
        if (v < INT32_MIN || v > INT32_MAX) return fail(a, "immediate out of 32-bit range");
        *out = v;
    }
    return 0;
}

static const struct { const char *name; uint8_t base; uint8_t digit; } alu[] = {
    { "add", 0x00, 0 }, { "or", 0x08, 1 }, { "and", 0x20, 4 },
    { "sub", 0x28, 5 }, { "xor", 0x30, 6 }, { "cmp", 0x38, 7 },
};

static int width_of(asm_t *a, const operand_t *x, const operand_t *y) {
    if (x->kind == OP_REG && y->kind == OP_REG && x->width != y->width)
        return fail(a, "operand size mismatch");
    if (x->kind == OP_REG) return x->width;
    if (y->kind == OP_REG) return y->width;
    if (x->kind == OP_MEM && x->width) return x->width;
    return fail(a, "operand size not specified (use qword ptr / dword ptr)");
}

static int assemble_insn(asm_t *a, const char *mn, operand_t *ops, int nops, bool is_short) {
    for (int i = 0; i < nops; i++)
        if (resolve(a, &ops[i]) != 0) return -1;
    operand_t *x = &ops[0], *y = &ops[1];

    if (nops == 0) {
        if (strcmp(mn, "nop") == 0) { emit(a, 0x90); return 0; }
        if (strcmp(mn, "ret") == 0) { emit(a, 0xC3); return 0; }
        if (strcmp(mn, "int3") == 0) { emit(a, 0xCC); return 0; }
        return fail(a, "unknown instruction '%s'", mn);
    }

    if (nops == 1 && (strcmp(mn, "push") == 0 || strcmp(mn, "pop") == 0)) {
        if (x->kind != OP_REG || x->width != 64) return fail(a, "%s takes a 64-bit register", mn);
        emit_rex(a, false, 0, 0, x->reg);
        emit(a, (uint8_t)((mn[1] == 'u' ? 0x50 : 0x58) + (x->reg & 7)));
        return 0;
    }

    if (nops == 1 && (strcmp(mn, "call") == 0 || strcmp(mn, "jmp") == 0)) {
        const bool call = mn[0] == 'c';
        if (x->kind == OP_IMM) {
            if (is_short && call) return fail(a, "call has no short form");
            const uint8_t opc = is_short ? 0xEB : (call ? 0xE8 : 0xE9);
            return emit_rel(a, &opc, 1, is_short ? 1 : 4, x->imm);
        }
        if (is_short) return fail(a, "short needs a target address");
        if ((x->kind == OP_REG && x->width != 64) || (x->kind == OP_MEM && x->width == 32))
            return fail(a, "indirect %s takes a 64-bit operand", mn);
        const uint8_t opc = 0xFF;
        emit_modrm_insn(a, false, &opc, 1, call ? 2 : 4, x);
        return 0;
    }

    if (nops == 1 && mn[0] == 'j') {
        for (uint8_t cc = 0; cc < 16; cc++) {
            if (strcmp(mn, jcc_names[cc]) != 0) continue;
            if (x->kind != OP_IMM) return fail(a, "%s needs a target", mn);
            if (is_short) {
                const uint8_t opc = (uint8_t)(0x70 + cc);
                return emit_rel(a, &opc, 1, 1, x->imm);
            }
            const uint8_t opc[2] = { 0x0F, (uint8_t)(0x80 + cc) };
            return emit_rel(a, opc, 2, 4, x->imm);
        }
    }

    if (is_short) return fail(a, "short is only valid on jmp/jcc");
    if (nops != 2) return fail(a, "unknown instruction or operand count for '%s'", mn);

    if (strcmp(mn, "movabs") == 0) {
        if (x->kind != OP_REG || x->width != 64 || y->kind != OP_IMM)
            return fail(a, "movabs takes r64, imm64");
        emit_rex(a, true, 0, 0, x->reg);
        emit(a, (uint8_t)(0xB8 + (x->reg & 7)));
        emit_le(a, (uint64_t)y->imm, 8);
        return 0;
    }

    if (strcmp(mn, "lea") == 0) {
        if (x->kind != OP_REG || y->kind != OP_MEM) return fail(a, "lea takes reg, [mem]");
        const uint8_t opc = 0x8D;
        emit_modrm_insn(a, x->width == 64, &opc, 1, x->reg, y);
        return 0;
    }

    if (strcmp(mn, "mov") == 0) {
        if (y->kind == OP_IMM) {
            if (x->kind == OP_REG && x->width == 32) {
                int64_t v = 0;
                if (imm_for_width(a, y->imm, 32, &v) != 0) return -1;
                emit_rex(a, false, 0, 0, x->reg);
                emit(a, (uint8_t)(0xB8 + (x->reg & 7)));
                emit_le(a, (uint64_t)v, 4);
                return 0;
            }
            if (x->kind == OP_REG && (y->imm < INT32_MIN || y->imm > INT32_MAX)) {
                emit_rex(a, true, 0, 0, x->reg);           /* GNU as: movabs form */
                emit(a, (uint8_t)(0xB8 + (x->reg & 7)));
                emit_le(a, (uint64_t)y->imm, 8);
                return 0;
            }
            const int w = width_of(a, x, x);
            if (w < 0) return -1;
            int64_t v = 0;
            if (imm_for_width(a, y->imm, (uint8_t)w, &v) != 0) return -1;
            const uint8_t opc = 0xC7;
            emit_modrm_insn(a, w == 64, &opc, 1, 0, x);
            emit_le(a, (uint64_t)v, 4);
            return 0;
        }
        const int w = width_of(a, x, y);
        if (w < 0) return -1;
        if (x->kind == OP_REG && y->kind == OP_MEM) {
            const uint8_t opc = 0x8B;
            emit_modrm_insn(a, w == 64, &opc, 1, x->reg, y);
            return 0;
        }
        if (y->kind == OP_REG && (x->kind == OP_REG || x->kind == OP_MEM)) {
            const uint8_t opc = 0x89;
            emit_modrm_insn(a, w == 64, &opc, 1, y->reg, x);
            return 0;
        }
        return fail(a, "unsupported mov operands");
    }

    if (strcmp(mn, "test") == 0) {
        if (x->kind == OP_MEM && y->kind == OP_REG) { /* canonical */ }
        else if (x->kind == OP_REG && y->kind == OP_MEM) { operand_t t = *x; *x = *y; *y = t; }
        else if (!(x->kind == OP_REG && y->kind == OP_REG)) return fail(a, "test takes r/m, reg");
        const int w = width_of(a, x, y);
        if (w < 0) return -1;
        const uint8_t opc = 0x85;
        emit_modrm_insn(a, w == 64, &opc, 1, y->reg, x);
        return 0;
    }

    for (size_t i = 0; i < sizeof alu / sizeof alu[0]; i++) {
        if (strcmp(mn, alu[i].name) != 0) continue;
        if (y->kind == OP_IMM) {
            const int w = width_of(a, x, x);
            if (w < 0) return -1;
            int64_t v = 0;
            if (imm_for_width(a, y->imm, (uint8_t)w, &v) != 0) return -1;
            const uint8_t opc = fits8(v) ? 0x83 : 0x81;
            emit_modrm_insn(a, w == 64, &opc, 1, alu[i].digit, x);
            emit_le(a, (uint64_t)v, opc == 0x83 ? 1 : 4);
            return 0;
        }
        const int w = width_of(a, x, y);
        if (w < 0) return -1;
        if (x->kind == OP_REG && y->kind == OP_MEM) {
            const uint8_t opc = (uint8_t)(alu[i].base + 3);
            emit_modrm_insn(a, w == 64, &opc, 1, x->reg, y);
            return 0;
        }
        if (y->kind == OP_REG && (x->kind == OP_REG || x->kind == OP_MEM)) {
            const uint8_t opc = (uint8_t)(alu[i].base + 1);
            emit_modrm_insn(a, w == 64, &opc, 1, y->reg, x);
            return 0;
        }
        return fail(a, "unsupported %s operands", mn);
    }
    return fail(a, "unknown instruction '%s'", mn);
}

static int split_operands(asm_t *a, char *s, operand_t ops[2], int *nops) {
    *nops = 0;
    s = trim(s);
    if (*s == '\0') return 0;
    int depth = 0;
    char *start = s;
    for (char *p = s;; p++) {
        if (*p == '[') depth++;
        else if (*p == ']') depth--;
        if ((*p == ',' && depth == 0) || *p == '\0') {
            const bool end = *p == '\0';
            *p = '\0';
            if (*nops == 2) return fail(a, "too many operands");
            if (parse_operand(a, start, &ops[*nops]) != 0) return -1;
            (*nops)++;
            if (end) break;
            start = p + 1;
        }
    }
    return 0;
}

static int run_pass(asm_t *a, const char *src) {
    a->len = 0;
    a->line = 0;
    const char *p = src;
    while (*p) {
        const char *nl = strchr(p, '\n');
        const size_t n = nl ? (size_t)(nl - p) : strlen(p);
        a->line++;
        if (n >= MAX_LINE) return fail(a, "line too long");
        char line[MAX_LINE];
        memcpy(line, p, n);
        line[n] = '\0';
        p += n + (nl ? 1 : 0);
        for (char *c = line; *c; c++)
            if (*c == ';' || *c == '#') { *c = '\0'; break; }
        for (char *c = line; *c; c++) *c = (char)tolower((unsigned char)*c);
        char *s = trim(line);
        /* labels */
        char *colon;
        while ((colon = strchr(s, ':')) != nullptr) {
            *colon = '\0';
            char *name = trim(s);
            if (!is_ident(name) || strlen(name) >= MAX_NAME) return fail(a, "bad label '%s'", name);
            if (!a->final_pass) {
                for (size_t i = 0; i < a->nlabels; i++)
                    if (strcmp(a->labels[i].name, name) == 0) return fail(a, "duplicate label '%s'", name);
                if (a->nlabels == MAX_LABELS) return fail(a, "too many labels");
                strcpy(a->labels[a->nlabels].name, name);
                a->labels[a->nlabels].addr = a->base + a->len;
                a->nlabels++;
            }
            s = trim(colon + 1);
        }
        if (*s == '\0') continue;
        char *mn = s;
        while (*s && !isspace((unsigned char)*s)) s++;
        if (*s) *s++ = '\0';
        s = trim(s);
        bool is_short = false;
        if (strncmp(s, "short", 5) == 0 && (s[5] == '\0' || isspace((unsigned char)s[5]))) {
            is_short = true;
            s = trim(s + 5);
        }
        operand_t ops[2];
        int nops = 0;
        if (split_operands(a, s, ops, &nops) != 0) return -1;
        if (assemble_insn(a, mn, ops, nops, is_short) != 0) return -1;
        if (a->oom) return fail(a, "out of memory");
    }
    return 0;
}

int pw_x86_assemble(const char *src, uint64_t base, uint8_t **out, size_t *out_len,
                    char *err, size_t err_cap) {
    if (src == nullptr || out == nullptr || out_len == nullptr) return -1;
    if (err && err_cap) err[0] = '\0';
    asm_t a = { .base = base, .err = err, .err_cap = err_cap };
    a.labels = calloc(MAX_LABELS, sizeof *a.labels);
    if (a.labels == nullptr) return -1;
    int rc = run_pass(&a, src);
    if (rc == 0) {
        a.final_pass = true;
        rc = run_pass(&a, src);
    }
    free(a.labels);
    if (rc != 0) {
        free(a.buf);
        return rc;
    }
    *out = a.buf;
    *out_len = a.len;
    return 0;
}
