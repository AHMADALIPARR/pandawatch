; SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
; Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
;
; Fixed corpus for the pw-xasm round-trip and objdump cross-check tests.
; Covers every opcode form the decoder accepts.
entry:
    push rbp
    push r12
    mov rbp, rsp
    sub rsp, 0x40
    mov rax, rbx
    mov r9d, r10d
    mov eax, 0x12345678
    mov r11d, 0xffffffff
    mov rcx, -5
    mov rdx, 0x7fffffff
    movabs rax, 0x1122334455667788
    movabs r15, -1
    mov r8, qword ptr [rsp+8]
    mov rax, [rbp-0x10]
    mov [rbp-0x18], rdi
    mov eax, [r13]
    mov [r12+0x80], ecx
    mov qword ptr [rbp-8], 5
    mov dword ptr [r12], 7
    mov qword ptr [rax+rbx*2+0x1000], -1
    lea rax, [rax+rcx*4]
    lea rdx, [rip+0x10]
    lea rsi, [rsp+rdi*8-0x20]
    lea r10, [r14*2+0x400000]
    lea rax, [0x601000]
    add eax, -1
    add rax, rbx
    add rax, [rdi]
    add [rdi+0x8], rax
    add qword ptr [rsp], 0x100
    or ecx, edx
    or r8, [rsi+r9*4]
    or [rbx+rsi*8+0x7f], edx
    or rax, 1
    and rcx, [r13]
    and eax, 0xff
    and [rdx], rcx
    sub rax, 0x12345678
    sub [rax], r8d
    sub rdx, [rcx]
    xor r15d, r15d
    xor eax, [rbp+0x40]
    xor [rsp+0x10], rbx
    xor dword ptr [rcx], -0x80
    cmp rax, 1000
    cmp rax, rcx
    cmp [rsi], edi
    cmp ebx, [rdx+rax*1]
    cmp dword ptr [rip+0x200], 0
back:
    test rax, rax
    test [rbx], ecx
    test r12, [rsp+8]
    je done
    jne short back
    jne entry
    jb done
    jae done
    jbe tail
    ja done
    js done
    jns done
    jp done
    jnp done
    jl done
    jge done
    jle done
    jg done
    jo done
    jno done
    call r11
    call qword ptr [rax+0x100]
    call entry
    jmp qword ptr [rip+0x20]
    jmp rax
tail:
    int3
    nop
    jmp short tail
    jmp done
done:
    add rsp, 0x40
    pop r12
    pop rbp
    ret
