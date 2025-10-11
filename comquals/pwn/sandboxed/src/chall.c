#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

void __attribute__((naked)) clear_register()
{
    __asm__ volatile(".intel_syntax noprefix;"
                     "xor rax, rax;"
                     "xor rbx, rbx;"
                     "xor rcx, rcx;"
                     "xor rdx, rdx;"
                     "xor rdi, rdi;"
                     "xor rsi, rsi;"
                     "xor rbp, rsp;"
                     "xor rsp, rsp;"
                     "xor r8, r8;"
                     "xor r9, r9;"
                     "xor r10, r10;"
                     "xor r11, r11;"
                     "xor r12, r12;"
                     "xor r13, r13;"
                     "xor r14, r14;"
                     "xor r15, r15;"
                     "mov fs, ax;"
                     "mov gs, ax;"
                     ".globl clear_register_end;"
                     "clear_register_end:"
                     ".att_syntax noprefix;");
}

extern void clear_register_end;

int main()
{
    char *shellcode = mmap(NULL, 0x1000, PROT_WRITE | PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (shellcode == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }
    size_t prologue_length = (size_t)&clear_register_end - (size_t)clear_register;
    memcpy(shellcode, clear_register, prologue_length);
    write(1, "Enter shellcode: ", 17);
    read(0, &shellcode[prologue_length], 0x1000 - prologue_length);
    ((void (*)())shellcode)();
}
