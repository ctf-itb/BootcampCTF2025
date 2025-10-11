#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h> 
#include <string.h>

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void seccomp_r(void) {
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        perror("seccomp_init");
        exit(EXIT_FAILURE);
    }

    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0));

    if (seccomp_load(ctx) != 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(EXIT_FAILURE);
    }
    seccomp_release(ctx);
    
    __asm__(
        "jmp end_gadgets \n\t"
        "pop %rdi; ret \n\t"
        "pop %r12; ret \n\t"  
        "pop %r13; ret \n\t"
        "pop %r14; ret \n\t"
        "pop %r15; ret \n\t"
        "xorb %r14b, (%r15); incq %r15; ret \n\t"
        "mov %r12, (%r13); ret \n\t"
        "end_gadgets: \n\t"
    );
}

void open(char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    char buffer[100];
    fread(buffer, 1, sizeof(buffer) - 1, file);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("%s\n", buffer);
    fclose(file);
}

void filter_bad_chars(char* buf) {
    for (int i = 0; buf[i] != '\0'; i++) {
        if (buf[i] == '.') {
            buf[i] = '\0'; 
            break;
        }
    }
}

void get_input(char* dest_buffer) {
    char temp_buf[0x400];
    printf("> ");
    fgets(temp_buf, sizeof(temp_buf), stdin);
    filter_bad_chars(temp_buf);
    memcpy(dest_buffer, temp_buf, 0x400);
}

int main(int argc, char* argv[]) {
    setup();
    char buf[100];
    printf("Ng Damdamin ko~~\n");
    get_input(buf);
    seccomp_r();
    return 0;
}