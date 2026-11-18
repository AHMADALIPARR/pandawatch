/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 *
 * pw_x86_decode: x86-64 instruction decoder written in GNU assembler
 * (Intel syntax, System V AMD64 ABI, leaf function, no stack use).
 *
 *   size_t pw_x86_decode(const uint8_t *buf, size_t len, pw_x86_insn_t *out);
 *
 * Decodes one instruction at buf[0..len) into *out (32 bytes, layout in
 * xasm/pw_x86.h) and returns its length, or 0 if the bytes are truncated or
 * outside the supported subset:
 *
 *   prefix   REX 0x40-0x4F (W, R, X, B)
 *   class 1  0x90 nop, 0xC3 ret, 0xCC int3
 *   class 2  0x50+r push r64, 0x58+r pop r64
 *   class 3  0xB8+r mov r32, imm32 / REX.W mov r64, imm64
 *   class 4  0x70-0x7F jcc rel8, 0xEB jmp rel8
 *   class 5  0xE8 call rel32, 0xE9 jmp rel32, 0x0F 0x80-0x8F jcc rel32
 *   class 6  ModRM, no immediate: 01 03 09 0B 21 23 29 2B 31 33 39 3B
 *            85 89 8B 8D, FF /2 (call r/m) and FF /4 (jmp r/m)
 *   class 7  0x83 /0,1,4,5,6,7 r/m, imm8
 *   class 8  0x81 /0,1,4,5,6,7 r/m, imm32
 *   class 9  0xC7 /0 r/m, imm32
 *
 * A REX prefix is rejected on classes 1, 4 and 5 and on 0F 8x; 8D (lea)
 * requires a memory operand.
 *
 * ModRM addressing: register, [base], [base+disp8/32], SIB with
 * scale/index/base (index 4 = none, base 5 with mod 0 = disp32 only) and
 * RIP-relative [rip+disp32] (base reported as 0x10).
 */

#define O_LEN     0
#define O_OPC     1
#define O_ESC     2
#define O_REX     3
#define O_MODRM   4
#define O_SIB     5
#define O_HASMODRM 6
#define O_HASSIB  7
#define O_REG     8
#define O_RM      9
#define O_BASE    10
#define O_INDEX   11
#define O_SCALE   12
#define O_MOD     13
#define O_IMMSZ   14
#define O_DISPSZ  15
#define O_DISP    16
#define O_IMM     24

    .intel_syntax noprefix

/* Fetch the next byte into eax (zero-extended); fail if past the end. */
.macro FETCH
    cmp     rcx, rsi
    jae     .Lfail
    movzx   eax, byte ptr [rdi + rcx]
    inc     rcx
.endm

    .text
    .globl  pw_x86_decode
    .type   pw_x86_decode, @function
pw_x86_decode:
    xor     eax, eax
    mov     [rdx], rax
    mov     [rdx + 8], rax
    mov     [rdx + 16], rax
    mov     [rdx + 24], rax
    mov     byte ptr [rdx + O_BASE], 0xFF
    mov     byte ptr [rdx + O_INDEX], 0xFF
    xor     ecx, ecx                 /* rcx = position */
    xor     r8d, r8d                 /* r8  = REX byte (0 if none) */

    FETCH
    mov     r9d, eax
    and     r9d, 0xF0
    cmp     r9d, 0x40
    jne     .Lnorex
    mov     r8d, eax
    mov     [rdx + O_REX], al
    FETCH
.Lnorex:
    cmp     eax, 0x0F
    jne     .Lprimary

    /* Two-byte opcodes: only 0F 80-8F (jcc rel32). */
    mov     byte ptr [rdx + O_ESC], 1
    FETCH
    mov     [rdx + O_OPC], al
    mov     r9d, eax
    and     r9d, 0xF0
    cmp     r9d, 0x80
    jne     .Lfail
    test    r8d, r8d                 /* no REX on branches */
    jnz     .Lfail
    mov     byte ptr [rdx + O_IMMSZ], 4
    jmp     .Limm

.Lprimary:
    mov     [rdx + O_OPC], al
    lea     r9, [rip + pw_x86_opclass]
    movzx   r11d, byte ptr [r9 + rax]
    cmp     r11d, 1
    je      .Lnoops
    cmp     r11d, 2
    je      .Lopreg
    cmp     r11d, 3
    je      .Lmovimm
    cmp     r11d, 4
    je      .Lrel8
    cmp     r11d, 5
    je      .Lrel32
    cmp     r11d, 6
    je      .Lmodrm
    cmp     r11d, 7
    je      .Lmodrm_ib
    cmp     r11d, 8
    je      .Lmodrm_id
    cmp     r11d, 9
    je      .Lmodrm_id
    jmp     .Lfail

.Lnoops:                             /* nop, ret, int3: no REX allowed */
    test    r8d, r8d
    jnz     .Lfail
    jmp     .Ldone

.Lopreg:                             /* register in opcode low bits + REX.B */
    mov     r9d, eax
    and     r9d, 7
    mov     r10d, r8d
    and     r10d, 1
    shl     r10d, 3
    or      r9d, r10d
    mov     [rdx + O_REG], r9b
    jmp     .Ldone

.Lmovimm:
    mov     r9d, eax
    and     r9d, 7
    mov     r10d, r8d
    and     r10d, 1
    shl     r10d, 3
    or      r9d, r10d
    mov     [rdx + O_REG], r9b
    mov     byte ptr [rdx + O_IMMSZ], 4
    test    r8d, 8                   /* REX.W -> imm64 */
    jz      .Limm
    mov     byte ptr [rdx + O_IMMSZ], 8
    jmp     .Limm

.Lrel8:
    test    r8d, r8d
    jnz     .Lfail
    mov     byte ptr [rdx + O_IMMSZ], 1
    jmp     .Limm

.Lrel32:
    test    r8d, r8d
    jnz     .Lfail
    mov     byte ptr [rdx + O_IMMSZ], 4
    jmp     .Limm

.Lmodrm_ib:
    mov     byte ptr [rdx + O_IMMSZ], 1
    jmp     .Lmodrm

.Lmodrm_id:
    mov     byte ptr [rdx + O_IMMSZ], 4

.Lmodrm:
    FETCH
    mov     [rdx + O_MODRM], al
    mov     byte ptr [rdx + O_HASMODRM], 1
    mov     r9d, eax
    shr     r9d, 6
    mov     [rdx + O_MOD], r9b

    mov     r9d, eax                 /* r9 = ModRM.reg (opcode extension) */
    shr     r9d, 3
    and     r9d, 7
    mov     r10d, r8d
    and     r10d, 4
    shl     r10d, 1                  /* REX.R -> bit 3 */
    or      r10d, r9d
    mov     [rdx + O_REG], r10b

    cmp     r11d, 7
    je      .Lchk_grp
    cmp     r11d, 8
    je      .Lchk_grp
    cmp     r11d, 9
    jne     .Lchk_ff
    test    r9d, r9d                 /* C7 /0 only */
    jnz     .Lfail
    jmp     .Lrm
.Lchk_grp:                           /* 81/83: add or and sub xor cmp */
    cmp     r9d, 2
    je      .Lfail
    cmp     r9d, 3
    je      .Lfail
    jmp     .Lrm
.Lchk_ff:
    movzx   r10d, byte ptr [rdx + O_OPC]
    cmp     r10d, 0x8D               /* lea needs a memory operand */
    jne     .Lchk_ff2
    cmp     al, 0xC0
    jae     .Lfail
    jmp     .Lrm
.Lchk_ff2:
    cmp     r10d, 0xFF
    jne     .Lrm
    cmp     r9d, 2                   /* FF /2 call r/m */
    je      .Lrm
    cmp     r9d, 4                   /* FF /4 jmp r/m */
    je      .Lrm
    jmp     .Lfail

.Lrm:
    mov     r9d, eax                 /* r9 = ModRM.rm (low 3 bits) */
    and     r9d, 7
    mov     r10d, r8d
    and     r10d, 1
    shl     r10d, 3                  /* REX.B -> bit 3 */
    or      r10d, r9d
    mov     [rdx + O_RM], r10b
    mov     r11d, eax                /* r11 = mod */
    shr     r11d, 6
    cmp     r11d, 3
    je      .Limm                    /* register operand */
    cmp     r9d, 4
    je      .Lsib
    cmp     r9d, 5
    jne     .Lbase_rm
    test    r11d, r11d
    jnz     .Lbase_rm
    mov     byte ptr [rdx + O_BASE], 0x10   /* [rip + disp32] */
    mov     byte ptr [rdx + O_DISPSZ], 4
    jmp     .Ldisp
.Lbase_rm:
    mov     [rdx + O_BASE], r10b
    jmp     .Lmoddisp

.Lsib:
    FETCH
    mov     [rdx + O_SIB], al
    mov     byte ptr [rdx + O_HASSIB], 1
    mov     r9d, eax
    shr     r9d, 6
    xor     r10d, r10d
    bts     r10d, r9d                /* scale = 1 << ss */
    mov     [rdx + O_SCALE], r10b
    mov     r9d, eax
    shr     r9d, 3
    and     r9d, 7
    mov     r10d, r8d
    and     r10d, 2
    shl     r10d, 2                  /* REX.X -> bit 3 */
    or      r10d, r9d
    cmp     r10d, 4                  /* index 4 without REX.X = none */
    je      .Lsib_base
    mov     [rdx + O_INDEX], r10b
.Lsib_base:
    mov     r9d, eax
    and     r9d, 7
    cmp     r9d, 5
    jne     .Lsib_hasbase
    test    r11d, r11d
    jnz     .Lsib_hasbase
    mov     byte ptr [rdx + O_DISPSZ], 4    /* no base, disp32 */
    jmp     .Ldisp
.Lsib_hasbase:
    mov     r10d, r8d
    and     r10d, 1
    shl     r10d, 3
    or      r10d, r9d
    mov     [rdx + O_BASE], r10b

.Lmoddisp:
    cmp     r11d, 1
    jne     .Lmod2
    mov     byte ptr [rdx + O_DISPSZ], 1
    jmp     .Ldisp
.Lmod2:
    cmp     r11d, 2
    jne     .Limm
    mov     byte ptr [rdx + O_DISPSZ], 4

.Ldisp:
    movzx   r9d, byte ptr [rdx + O_DISPSZ]
    cmp     r9d, 1
    jne     .Ldisp32
    FETCH
    movsx   eax, al
    mov     [rdx + O_DISP], eax
    jmp     .Limm
.Ldisp32:
    lea     r10, [rcx + 4]
    cmp     r10, rsi
    ja      .Lfail
    mov     eax, [rdi + rcx]
    mov     [rdx + O_DISP], eax
    add     rcx, 4

.Limm:
    movzx   r9d, byte ptr [rdx + O_IMMSZ]
    test    r9d, r9d
    jz      .Ldone
    lea     r10, [rcx + r9]
    cmp     r10, rsi
    ja      .Lfail
    cmp     r9d, 1
    jne     .Limm4
    movsx   rax, byte ptr [rdi + rcx]
    jmp     .Lstimm
.Limm4:
    cmp     r9d, 4
    jne     .Limm8
    movsxd  rax, dword ptr [rdi + rcx]
    jmp     .Lstimm
.Limm8:
    mov     rax, [rdi + rcx]
.Lstimm:
    mov     [rdx + O_IMM], rax
    add     rcx, r9

.Ldone:
    cmp     rcx, 15
    ja      .Lfail
    mov     [rdx + O_LEN], cl
    mov     rax, rcx
    ret
.Lfail:
    xor     eax, eax
    ret
    .size   pw_x86_decode, . - pw_x86_decode

/* Opcode class table for one-byte opcodes (0 = unsupported). */
    .section .rodata
    .globl  pw_x86_opclass
    .type   pw_x86_opclass, @object
pw_x86_opclass:
    .org    pw_x86_opclass + 0x01
    .byte   6
    .org    pw_x86_opclass + 0x03
    .byte   6
    .org    pw_x86_opclass + 0x09
    .byte   6
    .org    pw_x86_opclass + 0x0B
    .byte   6
    .org    pw_x86_opclass + 0x21
    .byte   6
    .org    pw_x86_opclass + 0x23
    .byte   6
    .org    pw_x86_opclass + 0x29
    .byte   6
    .org    pw_x86_opclass + 0x2B
    .byte   6
    .org    pw_x86_opclass + 0x31
    .byte   6
    .org    pw_x86_opclass + 0x33
    .byte   6
    .org    pw_x86_opclass + 0x39
    .byte   6
    .org    pw_x86_opclass + 0x3B
    .byte   6
    .org    pw_x86_opclass + 0x50
    .rept   16
    .byte   2
    .endr
    .org    pw_x86_opclass + 0x70
    .rept   16
    .byte   4
    .endr
    .org    pw_x86_opclass + 0x81
    .byte   8
    .org    pw_x86_opclass + 0x83
    .byte   7
    .org    pw_x86_opclass + 0x85
    .byte   6
    .org    pw_x86_opclass + 0x89
    .byte   6
    .org    pw_x86_opclass + 0x8B
    .byte   6
    .org    pw_x86_opclass + 0x8D
    .byte   6
    .org    pw_x86_opclass + 0x90
    .byte   1
    .org    pw_x86_opclass + 0xB8
    .rept   8
    .byte   3
    .endr
    .org    pw_x86_opclass + 0xC3
    .byte   1
    .org    pw_x86_opclass + 0xC7
    .byte   9
    .org    pw_x86_opclass + 0xCC
    .byte   1
    .org    pw_x86_opclass + 0xE8
    .byte   5
    .byte   5
    .org    pw_x86_opclass + 0xEB
    .byte   4
    .org    pw_x86_opclass + 0xFF
    .byte   6
    .size   pw_x86_opclass, 256

    .section .note.GNU-stack, "", @progbits
