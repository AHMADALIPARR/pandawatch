/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 *
 * Static x86-64 ELF fixture for bsm. Only instructions decoded by
 * asm/pw_x86_decode.S are used, so every function has a full CFG.
 */
    .intel_syntax noprefix
    .text
    .globl _start
    .type _start, @function
_start:
    mov edi, 3
    call ledger_sum
    mov edi, eax
    mov eax, 60
    jmp exit_now
    .size _start, .-_start

    .globl ledger_sum
    .type ledger_sum, @function
ledger_sum:
    push rbp
    mov rbp, rsp
    xor eax, eax
    test edi, edi
    je 2f
1:
    add eax, edi
    sub edi, 1
    jne 1b
2:
    pop rbp
    ret
    .size ledger_sum, .-ledger_sum

    .type exit_now, @function
exit_now:
    mov eax, 60
    nop
    ret
    .size exit_now, .-exit_now

    .section .note.GNU-stack,"",@progbits
