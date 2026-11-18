# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
# Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
    .text
    .globl post_transaction
post_transaction:
    pushq %rbp
    movq %rsp, %rbp
    movq 8(%rsi), %rax
    testq %rax, %rax
    je .Lreject
    addq %rax, 8(%rdi)
    call audit_log
    movl $0, %eax
    popq %rbp
    ret
.Lreject:
    movl $-1, %eax
    popq %rbp
    ret
    .globl audit_log
audit_log:
    xorl %eax, %eax
    ret
