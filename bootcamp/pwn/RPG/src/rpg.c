#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char input[160];

__attribute__((constructor))
void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void strip_newline(char *s) {
    size_t i = strcspn(s, "\n");
    s[i] = '\0';
}


void flag() {
    FILE *fd = fopen("flag.txt", "r");
    char flag[64];
    if (fd) {
        fgets(flag, sizeof(flag), fd);
        printf("Congratulations, you reach the Valhalla.\n%s", flag);
        fclose(fd);
    } else {
        printf("Could not open flag file.\n");
    }
}

void dungeon() {
    printf("I prayeth f'r thy success !!\n");
    char buffer[128];
    printf(">> ");
    read(0, input, sizeof(input));
    strncpy(buffer, input, strlen(input)-1);
    printf("God hast been speaken : %s\n", buffer);
    printf(">> ");
    gets(buffer);
}
int main() {
    setup();
    printf("Welcometh adventur'r !!\nthou art chosen to expl'ring unlimit'd dungeon\n");
    printf("\n=================================================================\n\n");
    printf("sayeth \"READY\" if 't be true thou art brave to embrace this journey of teen\n");
    printf("> ");
    char buffer[16];
    if (!fgets(buffer, sizeof(buffer), stdin)) return 1;
    strip_newline(buffer);
    if (strcmp(buffer, "READY") == 0) {
        printf("thou art brave indeed !!\n");
        printf("here is thy gift : %p\n", main);
        dungeon();
    } else {
        printf("Such a disgrace, leaveth mine own dungeon anon !!!\n");
    }
    printf("I has't seen thy braveness, anon rest mine own adventur'r....\n");
    return 0;
}
