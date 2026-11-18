/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* x86-64 subset: decoded-instruction record filled by the assembly decoder
 * (asm/pw_x86_decode.S), text formatting, the assembler, and IR lifting.
 * C23. */
#ifndef PW_X86_H
#define PW_X86_H

#include <stddef.h>
#include <stdint.h>

#include "pw_xray_bundle.h"

/* 32 bytes; field offsets match the O_* constants in pw_x86_decode.S. */
typedef struct {
    uint8_t  length;     /* 0  total instruction length, 1..15 */
    uint8_t  opcode;     /* 1  primary opcode (second byte after 0x0F) */
    uint8_t  escape;     /* 2  1 if the opcode follows 0x0F */
    uint8_t  rex;        /* 3  REX byte, 0 if none */
    uint8_t  modrm;      /* 4 */
    uint8_t  sib;        /* 5 */
    uint8_t  has_modrm;  /* 6 */
    uint8_t  has_sib;    /* 7 */
    uint8_t  reg;        /* 8  ModRM.reg + REX.R, or opcode register + REX.B */
    uint8_t  rm;         /* 9  ModRM.rm + REX.B */
    uint8_t  base;       /* 10 memory base, 0xFF none, 0x10 RIP */
    uint8_t  index;      /* 11 SIB index, 0xFF none */
    uint8_t  scale;      /* 12 1, 2, 4 or 8 when has_sib */
    uint8_t  mod;        /* 13 ModRM.mod */
    uint8_t  imm_size;   /* 14 0, 1, 4 or 8 */
    uint8_t  disp_size;  /* 15 0, 1 or 4 */
    int32_t  disp;       /* 16 sign-extended displacement */
    uint32_t _pad;       /* 20 */
    int64_t  imm;        /* 24 sign-extended immediate or relative offset */
} pw_x86_insn_t;
static_assert(sizeof(pw_x86_insn_t) == 32, "pw_x86_insn_t must be 32 bytes");
static_assert(offsetof(pw_x86_insn_t, disp) == 16, "disp at 16");
static_assert(offsetof(pw_x86_insn_t, imm) == 24, "imm at 24");

constexpr uint8_t PW_X86_NO_REG = 0xFF;
constexpr uint8_t PW_X86_RIP = 0x10;
constexpr size_t PW_X86_MAX_LEN = 15;

/* Implemented in GNU assembler. Returns the instruction length, 0 if invalid. */
size_t pw_x86_decode(const uint8_t *buf, size_t len, pw_x86_insn_t *out);

typedef enum : uint8_t {
    PW_X86_NOP, PW_X86_RET, PW_X86_INT3, PW_X86_PUSH, PW_X86_POP,
    PW_X86_MOV, PW_X86_MOVABS, PW_X86_LEA,
    PW_X86_ADD, PW_X86_OR, PW_X86_AND, PW_X86_SUB, PW_X86_XOR, PW_X86_CMP, PW_X86_TEST,
    PW_X86_CALL, PW_X86_JMP, PW_X86_JCC,
    PW_X86_INVALID
} pw_x86_mnem_t;

[[nodiscard]] pw_x86_mnem_t pw_x86_mnemonic(const pw_x86_insn_t *in);
[[nodiscard]] const char *pw_x86_mnemonic_name(const pw_x86_insn_t *in);

/* Intel-syntax text that pw_x86_assemble accepts back. `addr` is the address
 * of the instruction (branch targets are printed as absolute addresses). */
[[nodiscard]] int pw_x86_format(const pw_x86_insn_t *in, uint64_t addr, char *out, size_t cap);

/* Assembles the text in `src` (one instruction or `label:` per line, `;`
 * comments). Output is malloc'd. On error returns nonzero and writes a
 * message with the line number into err. */
[[nodiscard]] int pw_x86_assemble(const char *src, uint64_t base, uint8_t **out, size_t *out_len,
                                  char *err, size_t err_cap);

/* Maps a decoded instruction to a PW_OP_* opcode. */
[[nodiscard]] uint16_t pw_x86_to_pw_op(const pw_x86_insn_t *in);

/* Disassembles blob into one function (basic blocks split at branch targets
 * and after branches) and writes a .pwxray bundle with pw_bundle_write.
 * Indirect call/jmp sites become UNKNOWN evidence records. */
[[nodiscard]] pw_status_t pw_x86_lift_bundle(const uint8_t *blob, size_t len, uint64_t base,
                                             const uint8_t *alloy, size_t alloy_len,
                                             uint8_t **bundle, size_t *bundle_len,
                                             uint32_t *inst_count, uint32_t *block_count);

#endif /* PW_X86_H */
