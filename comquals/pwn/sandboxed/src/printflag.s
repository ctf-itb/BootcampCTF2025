    .intel_syntax noprefix
    .section .text
    .global _start

_start:
    mov     rax, 1
    mov     rdi, 1
    mov     rsi, OFFSET message
    mov     rdx, OFFSET message_len
    syscall

    mov     rax, 60
    xor     rdi, rdi
    syscall

    .section .rodata
message:
    .incbin "flag.txt"
    message_len = . - message
