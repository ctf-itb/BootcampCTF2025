#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <seccomp.h>

#define MAX_TRAINER_LEN 8
#define NAME_CHUNK_SIZE 0x30
#define MAX_POKEMON 16
#define SPECIES "magikarp"

static char *g_pokemon[MAX_POKEMON];

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void setup_seccomp(void) {
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

    if (seccomp_load(ctx) != 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(EXIT_FAILURE);
    }
    seccomp_release(ctx);
}

static int count_percent(const char *s) {
    int cnt = 0;
    for (; *s; s++) if (*s == '%') cnt++;
    return cnt;
}

static void get_name(char *dst_heap) {
    char tmp[NAME_CHUNK_SIZE] = {0};

    for (;;) {
        fputs("Give it a name: ", stdout);

        size_t n = read(1, tmp, 0x48);
        if (n == 0 && ferror(stdin)) {
            puts("\n(read error)");
            clearerr(stdin);
            return;
        }

        fputs("Preview: ", stdout);
        printf("%s", tmp);
        putchar('\n');

        fputs("Is this OK? (y/n) ", stdout);
        char c = 0;
        if (scanf(" %c", &c) != 1) { puts("Invalid input!"); return; }
        int ch; while ((ch = getchar()) != '\n' && ch != EOF) {}

        if (c == 'y' || c == 'Y') {
            size_t copy = n;
            if (copy > NAME_CHUNK_SIZE) copy = NAME_CHUNK_SIZE;
            if (copy && tmp[copy - 1] == '\n') copy--;
            if (copy) {
                memcpy(dst_heap, tmp, copy);
                if (copy < NAME_CHUNK_SIZE) dst_heap[copy] = '\0';
            }
            return;
        } else {
            puts("Okay, try again.");
        }
    }
}

static void catch_pokemon(void) {
    int slot = -1;
    for (int i = 0; i < MAX_POKEMON; i++) if (!g_pokemon[i]) { slot = i; break; }
    if (slot == -1) { puts("Your party is full!"); return; }

    char *name = malloc(NAME_CHUNK_SIZE);
    g_pokemon[slot] = name;

    if (!name) { puts("malloc failed"); return; }

    printf("You caught a %s! ", SPECIES);
    get_name(name);

    printf("Added %s (species: %s) to slot %d.\n", name, SPECIES, slot);
}

static void view_pokemon(void) {
    int any = 0;
    for (int i = 0; i < MAX_POKEMON; i++) {
        if (g_pokemon[i]) {
            printf("[%2d] Name: %s | Species: %s\n", i, g_pokemon[i], SPECIES);
            any = 1;
        }
    }
    if (!any) puts("You have no Pokémon yet.");
}

static void release_pokemon(void) {
    printf("Enter slot to release (0-%d): ", MAX_POKEMON - 1);
    int idx;
    if (scanf(" %d", &idx) != 1) { puts("Invalid input!"); return; }
    if (idx < 0 || idx >= MAX_POKEMON) { puts("Invalid slot!"); return; }
    if (!g_pokemon[idx]) { puts("That slot is empty."); return; }
    free(g_pokemon[idx]);
    g_pokemon[idx] = NULL;
    puts("Released Magikarp!");
}

static void cleanup(void) {
    for (int i = 0; i < MAX_POKEMON; i++) {
        free(g_pokemon[i]);
        g_pokemon[i] = NULL;
    }
}

int main(void) {
    setup();

    char trainer[MAX_TRAINER_LEN + 1] = {0};
    printf("Enter your trainer name (%d chars): ", MAX_TRAINER_LEN);
    if (scanf(" %8s", trainer) != 1) { puts("Invalid input!"); exit(0); }
    if (count_percent(trainer) > 1) {
        puts("Sus name!");
        exit(1);
    }

    puts("");
    printf("Welcome, ");
    printf(trainer);
    puts("! Your adventure begins!\n");

    setup_seccomp(); 

    while (1) {
        puts("=== MENU ===");
        puts("1) catch pokemon");
        puts("2) view pokemon");
        puts("3) release pokemon");
        puts("4) quit");
        printf("> ");

        int choice;
        if (scanf(" %d", &choice) != 1) { puts("Invalid input!"); continue; }

        switch (choice) {
            case 1: catch_pokemon(); break;
            case 2: view_pokemon();  break;
            case 3: release_pokemon(); break;
            case 4: cleanup(); puts("Goodbye!"); return 0;
            default: puts("Invalid choice!"); break;
        }
        puts("");
    }
}
